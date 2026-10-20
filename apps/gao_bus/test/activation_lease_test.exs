defmodule GaoBus.ActivationLeaseTest do
  use ExUnit.Case, async: false

  alias GaoBus.Limits
  alias GaoBus.Unix.{Native, Resources}

  setup context do
    directory =
      Path.join(System.tmp_dir!(), "gb-activation-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "socket")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)

    actor =
      Port.open({:spawn_executable, System.find_executable("python3")}, [
        :binary,
        :exit_status,
        args: [
          Path.expand("fixtures/resource_actor.py", __DIR__),
          path,
          Map.get(context, :actor_mode, "discard")
        ]
      ])

    {:ok, socket} = :socket.accept(listener, 5000)
    assert {:ok, _} = :socket.recv(socket, 1, [:peek], 5000)
    assert {:ok, "resources", [_, _, _] = originals} = Resources.recv(socket, 1024)

    limits =
      start_supervised!(
        {Limits,
         name: nil,
         limits: Map.get(context, :limits, %{}),
         xml_limits: Map.get(context, :xml_limits)}
      )

    peer = owner()
    assert :ok = Limits.acquire(peer, Native.identity(), limits)
    assert {:ok, ingress} = Limits.reserve_ingress_fds(peer, 8, 3, limits)

    identity = %{
      caller: peer,
      caller_incarnation: {make_ref(), ":1.1"},
      request_key: {make_ref(), make_ref()},
      deadline: System.monotonic_time(:millisecond) + 5000
    }

    on_exit(fn ->
      Resources.close(originals)
      :socket.close(socket)
      :socket.close(listener)
      if Port.info(actor), do: Port.close(actor)
      File.rm_rf!(directory)
    end)

    %{
      limits: limits,
      peer: peer,
      ingress: ingress,
      identity: identity,
      originals: originals,
      socket: socket,
      actor: actor
    }
  end

  test "claim hands independent descriptors to the exact coordinator once", ctx do
    assert {:ok, lease} = reserve(ctx)
    assert :ok = Resources.close(ctx.originals)
    assert :ok = Limits.release(ctx.ingress, ctx.limits)
    assert {:ok, copies} = claim(ctx, lease)
    assert_open(copies)
    intruder = owner()

    assert {:error, :activation_not_owner} =
             invoke(intruder, fn ->
               api(:release_activation, [lease, ctx.identity.request_key, ctx.limits])
             end)

    assert_open(copies)
    assert :ok = release(ctx, lease)
    assert_closed(copies)

    assert %{activation_fds: 0, activation_messages: 0, ingress_messages: 0} =
             snapshot(ctx).global

    finish_actor(ctx)
  end

  test "launch view preserves actual FD policy while terminal events omit resources", ctx do
    coordinator =
      start_supervised!({GaoBus.Activation, name: nil, router: self(), limits: ctx.limits})

    assert {:ok, epoch} = GaoBus.Activation.epoch(coordinator)
    identity = %{ctx.identity | request_key: {epoch, make_ref()}}
    ctx = %{ctx | identity: identity}
    assert {:ok, lease} = reserve(ctx, coordinator)
    definition = %{key: :fd_definition, backend: :helper, unit: nil}

    waiter = %{
      caller: ctx.peer,
      caller_incarnation: identity.caller_incarnation,
      request: identity.request_key,
      serial: {epoch, identity.caller_incarnation, 1},
      kind: :automatic,
      message_type: :method_call,
      flags: 0,
      destination: "org.example.Activated",
      generation: 1,
      definition: definition.key,
      deadline: identity.deadline,
      lease: lease
    }

    message =
      ExDBus.Message.method_call("/org/example", "org.example.Service", "Request",
        serial: 1,
        destination: waiter.destination,
        sender: ":1.1",
        signature: "hhh",
        body: [0, 1, 2],
        fds: ctx.originals
      )

    assert {:ok, attempt} = GaoBus.Activation.admit(waiter, message, definition, coordinator)
    assert :ok = Limits.release(ctx.ingress, ctx.limits)
    assert :ok = Resources.close(ctx.originals)
    assert {:ok, %{waiters: [%{message: view}]}} = GaoBus.Activation.view(attempt, coordinator)

    rules = [
      %{
        selector: :default,
        rules: [
          %{effect: :allow, attributes: %{"send_destination" => "*"}},
          %{effect: :deny, attributes: %{"send_destination" => "*", "min_fds" => 3}}
        ]
      }
    ]

    assert {:ok, policy} = GaoBus.Policy.XML.compile(rules, daemon_uid: 4)

    assert :deny =
             GaoBus.Policy.XML.authorize(policy, :send, %{
               credentials: Native.identity(),
               message: view
             })

    assert length(view.fds) == 3
    assert_open(view.fds)
    assert view.body == []
    assert view.signature == message.signature

    assert :ok =
             GaoBus.Activation.finish(attempt, waiter.request, {:terminal, :denied}, coordinator)

    assert_receive {:activation_event, ^coordinator, ^epoch,
                    {:terminal, ^attempt, _, _, terminal, :denied}}

    assert terminal.body == []
    assert terminal.fds == []
    await(ctx, &(&1.global.activation_messages == 0))
    assert_closed(view.fds)
    finish_actor(ctx)
  end

  for scope <- [:peer, :uid, :global] do
    @tag limits: %{scope => %{activation_fds: 2}}
    test "#{scope} FD denial preserves originals and all credits", ctx do
      before = snapshot(ctx)
      assert {:error, {:limit_exceeded, unquote(scope), :activation_fds}} = reserve(ctx)
      assert snapshot(ctx) == before
      assert_open(ctx.originals)
      finish_actor(ctx)
    end
  end

  test "invalid original handle rolls back without duplicating the other descriptors", ctx do
    [first | _rest] = ctx.originals
    assert :ok = Resources.close([first])
    before = snapshot(ctx)
    assert {:error, :invalid_handles} = reserve(ctx)
    assert snapshot(ctx) == before
    finish_actor(ctx)
  end

  test "caller death closes resources held elsewhere but retains queued body credit", ctx do
    assert {:ok, lease} = reserve(ctx)
    assert {:ok, copies} = claim(ctx, lease)
    assert :ok = Limits.release(ctx.ingress, ctx.limits)
    monitor = Process.monitor(ctx.peer)
    Process.exit(ctx.peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, peer, :killed} when peer == ctx.peer
    await(ctx, fn stats -> not Map.has_key?(stats.peers, ctx.peer) end)
    assert_closed(copies)

    assert %{activation_messages: 1, activation_bytes: 8, ingress_messages: 1} =
             snapshot(ctx).global

    assert :ok = release(ctx, lease)
    assert %{activation_messages: 0, ingress_messages: 0} = snapshot(ctx).global
    finish_actor(ctx)
  end

  test "coordinator death closes externally retained terms before retiring the lease", ctx do
    coordinator = owner()
    assert {:ok, lease} = reserve(ctx, coordinator)
    assert {:ok, copies} = invoke(coordinator, fn -> claim(ctx, lease) end)
    assert :ok = Limits.release(ctx.ingress, ctx.limits)
    monitor = Process.monitor(coordinator)
    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :killed}
    await(ctx, &(&1.global.activation_messages == 0))
    assert_closed(copies)
    assert %{activation_bytes: 0, activation_fds: 0, ingress_messages: 0} = snapshot(ctx).global
    assert_open(ctx.originals)
    finish_actor(ctx)
  end

  @tag actor_mode: "roundtrip", xml_limits: %{"max_incoming_bytes" => 8}
  test "delayed output owns separate copies and preserves causal ingress until write completion",
       ctx do
    recipient = owner()
    assert :ok = Limits.acquire(recipient, Native.identity(), ctx.limits)
    assert {:ok, lease} = reserve(ctx)
    assert {:ok, held} = claim(ctx, lease)
    assert :ok = Resources.close(ctx.originals)
    assert :ok = Limits.release(ctx.ingress, ctx.limits)

    assert {:error, :invalid_ingress_reservation} =
             Limits.reserve_egress(recipient, 8, 3, ctx.limits, ctx.ingress)

    assert {:ok, egress} =
             Limits.reserve_egress(
               recipient,
               8,
               3,
               ctx.limits,
               {:activation, lease, ctx.identity.request_key}
             )

    assert {:ok, delivery} = Resources.duplicate(held)
    assert :ok = Limits.bind_egress(egress, delivery, ctx.limits)
    assert :ok = release(ctx, lease)
    assert_closed(held)
    assert_open(delivery)

    assert %{activation_messages: 0, ingress_messages: 1, egress_messages: 1} =
             snapshot(ctx).global

    assert {:error, {:xml_limit_exceeded, "max_incoming_bytes"}} =
             Limits.ingress_ready(ctx.peer, ctx.limits)

    assert {:ok, 8} = Resources.send(ctx.socket, "returned", delivery)
    assert :ok = Limits.release(egress, ctx.limits)
    assert_closed(delivery)
    assert %{ingress_messages: 0, egress_messages: 0} = snapshot(ctx).global
    assert :ok = Limits.ingress_ready(ctx.peer, ctx.limits)
    finish_actor(ctx, false)
  end

  defp reserve(ctx, coordinator \\ self()),
    do:
      api(:reserve_activation, [
        ctx.ingress,
        ctx.identity,
        8,
        ctx.originals,
        coordinator,
        ctx.limits
      ])

  defp claim(ctx, lease),
    do: api(:claim_activation, [lease, ctx.identity.request_key, ctx.limits])

  defp release(ctx, lease),
    do: api(:release_activation, [lease, ctx.identity.request_key, ctx.limits])

  defp api(function, args) do
    assert function_exported?(Limits, function, length(args)),
           "missing activation lease API #{function}"

    apply(Limits, function, args)
  end

  defp snapshot(ctx) do
    assert {:ok, stats} = Limits.snapshot(ctx.limits)
    stats
  end

  defp owner, do: start_supervised!({Task, &coordinator_loop/0}, id: make_ref())

  defp coordinator_loop do
    receive do
      {:invoke, from, reference, fun} ->
        send(from, {reference, fun.()})
        coordinator_loop()

      :stop ->
        :ok
    end
  end

  defp invoke(pid, fun) do
    reference = make_ref()
    send(pid, {:invoke, self(), reference, fun})
    assert_receive {^reference, result}, 5000
    result
  end

  defp assert_open(handles),
    do: Enum.each(handles, &assert(Resources.info(&1) == {:ok, %{cloexec: true}}))

  defp assert_closed(handles),
    do: Enum.each(handles, &assert(Resources.info(&1) == {:error, :closed}))

  defp await(ctx, predicate),
    do: await(ctx, predicate, System.monotonic_time(:millisecond) + 1500)

  defp await(ctx, predicate, deadline) do
    unless predicate.(snapshot(ctx)) do
      assert System.monotonic_time(:millisecond) < deadline
      await(ctx, predicate, deadline)
    end
  end

  defp finish_actor(ctx, acknowledge \\ true) do
    if acknowledge, do: assert(:ok = :socket.send(ctx.socket, "!"))
    Port.command(ctx.actor, "q")
    assert_receive {actor, {:data, "RESOURCE_ACTOR_OK\n"}}, 5000
    assert actor == ctx.actor
    assert_receive {^actor, {:exit_status, 0}}, 5000
  end
end
