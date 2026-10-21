defmodule GaoBus.ActivationCoordinatorTest do
  use ExUnit.Case, async: true

  alias ExDBus.Message
  alias GaoBus.{Activation, Limits}

  # The fixture is the Router owner: consume its admitted envelope and return
  # control credit while preserving every event/body/order assertion below.
  defmacrop assert_event(pattern) do
    quote do
      assert_receive {:control_work, control_token, unquote(pattern)}
      assert :ok = Limits.release_control(control_token, var!(ctx).limits)
    end
  end

  defmacrop refute_event(pattern, timeout) do
    quote do
      refute_receive {:control_work, _control_token, unquote(pattern)}, unquote(timeout)
    end
  end

  setup do
    limits = start_supervised!({Limits, name: nil})
    %{limits: limits}
  end

  test "admission claims a lease before notifying ordered launch and retains the full body",
       ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    assert :ok = Limits.release(ingress, ctx.limits)
    epoch = elem(waiter.request, 0)
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})
    assert stats(ctx).global.activation_messages == 1
    assert {:ok, view} = api(:view, [attempt, coordinator])
    assert [%{waiter: ^waiter, message: header}] = view.waiters
    assert header.body == []
    assert {:ok, :issued} = api(:commit, [attempt, 1, coordinator])
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch, ^attempt, definition}})
    assert definition == selected()
    assert :ok = api(:name_available, [waiter.destination, coordinator])

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:resolve, ^attempt, request, metadata, delivered}}
    )

    assert request == waiter.request
    assert metadata.request == waiter.request
    assert delivered.body == message.body
    assert :ok = api(:finish, [attempt, waiter.request, :delivered, coordinator])
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert stats(ctx).global.ingress_messages == 0
  end

  test "only the bound Router may inspect, commit or complete admitted work", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, _ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    intruder = owner()

    for {function, args} <- [
          {:view, [attempt, coordinator]},
          {:commit, [attempt, 1, coordinator]},
          {:finish, [attempt, waiter.request, {:terminal, :denied}, coordinator]}
        ] do
      assert {:error, :not_router} = invoke(intruder, fn -> api(function, args) end)
    end

    assert stats(ctx).global.activation_messages == 1
    assert {:ok, :issued} = api(:commit, [attempt, 1, coordinator])
  end

  test "terminal attempts without a launch commit retire notification bookkeeping", ctx do
    coordinator = coordinator(ctx, state_options: [max_attempts: 1])

    for _ <- 1..5 do
      {waiter, message, ingress} = waiting(ctx, coordinator)
      assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
      epoch = elem(waiter.request, 0)
      assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})
      assert :ok = Limits.release(ingress, ctx.limits)
      assert :ok = api(:finish, [attempt, waiter.request, {:terminal, :denied}, coordinator])

      assert_event(
        {:activation_event, ^coordinator, ^epoch, {:terminal, ^attempt, _, _, _, :denied}}
      )

      await(fn -> stats(ctx).global.activation_messages == 0 end)
      assert {:ok, %{bookkeeping: %{attempts: attempts}}} = api(:snapshot, [coordinator])
      assert map_size(attempts) == 0
      assert MapSet.size(:sys.get_state(coordinator).launch_notifications) == 0
    end
  end

  test "caller cancellation drains unissued body and makes old launch commit harmless", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    assert :ok = Limits.release(ingress, ctx.limits)
    assert :ok = Limits.release_peer(waiter.caller, ctx.limits)
    epoch = elem(waiter.request, 0)

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:terminal, ^attempt, request, _, header, :caller_down}}
    )

    assert request == waiter.request
    assert header.body == []
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert {:ok, :ignored} = api(:commit, [attempt, 1, coordinator])
    refute_event({:activation_event, ^coordinator, ^epoch, {:launch, _, _}}, 0)
  end

  test "PID1 hints keep one outstanding deferred retry and cancellation clears its references",
       ctx do
    coordinator = coordinator(ctx, state_options: [max_attempts: 1])
    {waiter, message, ingress} = waiting(ctx, coordinator)
    definition = %{selected() | backend: :systemd, unit: "example-activated.service"}
    assert {:ok, attempt} = api(:admit, [waiter, message, definition, coordinator])
    assert :ok = Limits.release(ingress, ctx.limits)
    epoch = elem(waiter.request, 0)
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})

    assert :ok = api(:defer_systemd, [attempt, coordinator])
    deferred = :sys.get_state(coordinator)
    assert deferred.deferred_systemd == MapSet.new([attempt])
    assert deferred.launch_notifications == MapSet.new()
    assert :ok = api(:name_available, ["org.freedesktop.systemd1", coordinator])
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})

    # The Router fixture deliberately leaves this retry outstanding. Repeated
    # ownership hints cannot manufacture further outstanding notifications.
    for _ <- 1..64 do
      assert :ok = api(:name_available, ["org.freedesktop.systemd1", coordinator])
      state = :sys.get_state(coordinator)
      assert :queue.len(state.effects) <= 1
      assert state.launch_notifications == MapSet.new([attempt])
      assert MapSet.size(state.deferred_systemd) <= 1
      assert MapSet.subset?(state.deferred_systemd, MapSet.new([attempt]))
      assert map_size(state.bookkeeping.attempts) == 1
      assert map_size(state.bookkeeping.units) == 1
    end

    refute_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, _}}, 0)
    assert stats(ctx).global.activation_messages == 1
    assert :ok = api(:defer_systemd, [attempt, coordinator])
    assert :sys.get_state(coordinator).deferred_systemd == MapSet.new([attempt])
    assert :ok = Limits.release_peer(waiter.caller, ctx.limits)

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:terminal, ^attempt, request, _, _, :caller_down}}
    )

    assert request == waiter.request
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    state = :sys.get_state(coordinator)
    assert state.bookkeeping.attempts == %{}
    assert state.bookkeeping.units == %{}
    assert state.messages == %{}
    assert state.timers == %{}
    assert :queue.is_empty(state.effects)
    assert state.launch_notifications == MapSet.new()
    assert state.deferred_systemd == MapSet.new()
    assert stats(ctx).global.ingress_messages == 0

    assert :ok = api(:name_available, ["org.freedesktop.systemd1", coordinator])
    _ = :sys.get_state(coordinator)
    refute_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, _}}, 0)
  end

  test "systemd launch view binds the exact issuer after its representative retires", ctx do
    coordinator = coordinator(ctx)
    definition = %{selected() | backend: :systemd, unit: "example-activated.service"}
    owner_identity = {self(), {make_ref(), ":1.9"}}
    {first, first_message, first_ingress} = waiting(ctx, coordinator)
    assert {:ok, issuer} = api(:admit, [first, first_message, definition, coordinator])
    assert :ok = Limits.release(first_ingress, ctx.limits)

    {second, second_message, second_ingress} = waiting(ctx, coordinator)
    second = %{second | destination: "org.example.Other"}
    second_message = %{second_message | destination: second.destination}
    assert {:ok, member} = api(:admit, [second, second_message, definition, coordinator])
    assert :ok = Limits.release(second_ingress, ctx.limits)
    assert {:ok, :issued} = api(:commit_systemd, [issuer, 1, owner_identity, coordinator])
    assert {:ok, :coalesced} = api(:commit_systemd, [member, 1, owner_identity, coordinator])
    epoch = elem(issuer, 0)

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:launch_systemd, ^issuer, ^definition, ^owner_identity}}
    )

    assert {:ok, initial} = api(:systemd_view, [definition.unit, issuer, coordinator])
    assert Enum.map(initial, & &1.attempt) == [issuer, member]
    assert {:error, :unknown_unit} = api(:systemd_view, [definition.unit, member, coordinator])

    assert {:error, :unknown_unit} =
             api(
               :systemd_view,
               [definition.unit, {make_ref(), elem(issuer, 1)}, coordinator]
             )

    assert {:error, :unknown_unit} =
             api(
               :systemd_view,
               [definition.unit, {epoch, make_ref()}, coordinator]
             )

    intruder = owner()

    assert {:error, :not_router} =
             invoke(intruder, fn ->
               api(:systemd_view, [definition.unit, issuer, coordinator])
             end)

    assert :ok = api(:name_available, [first.destination, coordinator])
    assert_event({:activation_event, ^coordinator, ^epoch, {:resolve, ^issuer, _, _, _}})
    assert :ok = api(:finish, [issuer, first.request, :delivered, coordinator])
    await(fn -> stats(ctx).global.activation_messages == 1 end)
    refute Map.has_key?(:sys.get_state(coordinator).bookkeeping.attempts, issuer)

    assert {:ok, [%{attempt: ^member, waiter: metadata}]} =
             api(:systemd_view, [definition.unit, issuer, coordinator])

    assert metadata.request == second.request
    assert {:error, :unknown_unit} = api(:systemd_view, [definition.unit, member, coordinator])

    assert :ok = api(:systemd_failure, [definition.unit, :denied, coordinator])

    assert_event(
      {:activation_event, ^coordinator, ^epoch, {:terminal, ^member, _, _, _, :denied}}
    )

    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert :sys.get_state(coordinator).bookkeeping.units == %{}
  end

  test "reissuing a retired systemd unit rejects its old local launch issuer", ctx do
    coordinator = coordinator(ctx, state_options: [max_attempts: 1])
    definition = %{selected() | backend: :systemd, unit: "example-activated.service"}
    owner_identity = {self(), {make_ref(), ":1.9"}}
    {old_waiter, old_message, old_ingress} = waiting(ctx, coordinator)
    assert {:ok, old_issuer} = api(:admit, [old_waiter, old_message, definition, coordinator])
    assert :ok = Limits.release(old_ingress, ctx.limits)
    assert {:ok, :issued} = api(:commit_systemd, [old_issuer, 1, owner_identity, coordinator])
    epoch = elem(old_issuer, 0)

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:launch_systemd, ^old_issuer, ^definition, ^owner_identity}}
    )

    assert :ok = api(:name_available, [old_waiter.destination, coordinator])
    assert_event({:activation_event, ^coordinator, ^epoch, {:resolve, ^old_issuer, _, _, _}})
    assert :ok = api(:finish, [old_issuer, old_waiter.request, :delivered, coordinator])
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert :sys.get_state(coordinator).bookkeeping.units == %{}

    {current_waiter, current_message, current_ingress} = waiting(ctx, coordinator)

    assert {:ok, current_issuer} =
             api(
               :admit,
               [current_waiter, current_message, definition, coordinator]
             )

    assert current_issuer != old_issuer
    assert elem(current_issuer, 0) == epoch
    assert :ok = Limits.release(current_ingress, ctx.limits)
    assert {:ok, :issued} = api(:commit_systemd, [current_issuer, 1, owner_identity, coordinator])

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:launch_systemd, ^current_issuer, ^definition, ^owner_identity}}
    )

    assert {:ok, [%{attempt: ^current_issuer}]} =
             api(:systemd_view, [definition.unit, current_issuer, coordinator])

    assert {:error, :unknown_unit} =
             api(:systemd_view, [definition.unit, old_issuer, coordinator])

    assert {:error, :unknown_unit} =
             api(
               :systemd_view,
               [definition.unit, {make_ref(), elem(current_issuer, 1)}, coordinator]
             )

    assert {:error, :unknown_unit} =
             api(
               :systemd_view,
               [definition.unit, {epoch, make_ref()}, coordinator]
             )

    assert stats(ctx).global.activation_messages == 1
    assert map_size(:sys.get_state(coordinator).bookkeeping.units) == 1

    assert :ok = api(:systemd_failure, [definition.unit, :denied, coordinator])

    assert_event(
      {:activation_event, ^coordinator, ^epoch, {:terminal, ^current_issuer, _, _, _, :denied}}
    )

    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert :sys.get_state(coordinator).bookkeeping.units == %{}
  end

  test "natural deadline retains a body queued to Router until exact completion", ctx do
    coordinator = coordinator(ctx, state_options: [service_start_timeout: 250])
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    assert :ok = Limits.release(ingress, ctx.limits)
    assert {:ok, :issued} = api(:commit, [attempt, 1, coordinator])
    assert :ok = api(:name_available, [waiter.destination, coordinator])
    epoch = elem(waiter.request, 0)
    assert_event({:activation_event, ^coordinator, ^epoch, {:resolve, ^attempt, _, _, _}})

    await(fn ->
      {:ok, snapshot} = api(:snapshot, [coordinator])

      get_in(snapshot.bookkeeping.attempts, [attempt, :waiters, waiter.request, :pending_terminal]) ==
        :timed_out
    end)

    assert stats(ctx).global.activation_messages == 1
    assert stats(ctx).global.activation_bytes == 2048
    refute_event({:activation_event, ^coordinator, ^epoch, {:terminal, _, _, _, _, _}}, 0)
    assert :ok = api(:finish, [attempt, waiter.request, {:terminal, :timed_out}, coordinator])

    assert_event(
      {:activation_event, ^coordinator, ^epoch, {:terminal, ^attempt, _, _, header, :timed_out}}
    )

    assert header.body == []
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert :ok = api(:finish, [attempt, waiter.request, {:terminal, :timed_out}, coordinator])
    refute_event({:activation_event, ^coordinator, ^epoch, {:terminal, _, _, _, _, _}}, 0)
  end

  test "old epoch and mismatched request completion cannot retire current body", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, _ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])

    assert :ok =
             api(:finish, [
               {make_ref(), elem(attempt, 1)},
               waiter.request,
               {:terminal, :denied},
               coordinator
             ])

    assert :ok =
             api(:finish, [
               attempt,
               {elem(waiter.request, 0), make_ref()},
               {:terminal, :denied},
               coordinator
             ])

    assert stats(ctx).global.activation_messages == 1
    assert :ok = api(:finish, [attempt, waiter.request, {:terminal, :denied}, coordinator])
    await(fn -> stats(ctx).global.activation_messages == 0 end)
  end

  test "changed definition is refused at current-generation launch commit", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    assert :ok = Limits.release(ingress, ctx.limits)

    assert :ok =
             api(:reload, [2, %{waiter.destination => %{selected() | key: :changed}}, coordinator])

    assert {:ok, :ok} = api(:commit, [attempt, 2, coordinator])
    epoch = elem(waiter.request, 0)

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:terminal, ^attempt, _, _, _, :definition_changed}}
    )

    await(fn -> stats(ctx).global.activation_messages == 0 end)
    refute_event({:activation_event, ^coordinator, ^epoch, {:launch, _, _}}, 0)
  end

  test "coordinator death reclaims admitted leases through monitored Limits", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    epoch = elem(waiter.request, 0)
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})
    assert stats(ctx).control.count == 1
    assert :ok = Limits.release(ingress, ctx.limits)
    monitor = Process.monitor(coordinator)
    Process.exit(coordinator, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, :killed}
    await(fn -> stats(ctx).global.activation_messages == 0 and stats(ctx).control.count == 0 end)
    assert stats(ctx).global.ingress_messages == 0
  end

  test "Router death retires the coordinator rather than stranding authority work", ctx do
    router = owner()
    coordinator = coordinator(ctx, router: router)
    monitor = Process.monitor(coordinator)
    router_monitor = Process.monitor(router)
    Process.exit(router, :kill)
    assert_receive {:DOWN, ^router_monitor, :process, ^router, :killed}
    assert_receive {:DOWN, ^monitor, :process, ^coordinator, {:router_down, :killed}}
  end

  test "terminal capacity refusal precedes admission and releases the incoming lease", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)

    tokens =
      for _ <- 1..512 do
        assert {:ok, token} = Limits.reserve_control(self(), 1, ctx.limits)
        token
      end

    assert {:error, :control_capacity} = api(:admit, [waiter, message, selected(), coordinator])

    assert {:ok, %{messages: 0, bookkeeping: %{attempts: attempts}}} =
             api(:snapshot, [coordinator])

    assert attempts == %{}
    assert stats(ctx).global.activation_messages == 0
    assert stats(ctx).control.count == 512
    assert {:ok, _epoch} = api(:epoch, [coordinator])
    refute_event({:activation_event, ^coordinator, _, _}, 0)
    assert :ok = Limits.release(ingress, ctx.limits)
    for token <- tokens, do: assert(:ok == Limits.release_control(token, ctx.limits))
    assert stats(ctx).control.count == 0
  end

  test "source DOWN settles through retained terminal capacity without leaking credit", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    epoch = elem(waiter.request, 0)
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})
    assert stats(ctx).control.count == 1
    assert :ok = Limits.release(ingress, ctx.limits)
    monitor = Process.monitor(waiter.caller)
    send(waiter.caller, :stop)
    assert_receive {:DOWN, ^monitor, :process, _caller, :normal}

    assert_event(
      {:activation_event, ^coordinator, ^epoch, {:terminal, ^attempt, _, _, _, :caller_down}}
    )

    await(fn -> stats(ctx).global.activation_messages == 0 and stats(ctx).control.count == 0 end)
    assert stats(ctx).global.ingress_messages == 0
  end

  test "launch notification saturation settles through pre-admitted terminal credit", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)

    tokens =
      for _ <- 1..511 do
        assert {:ok, token} = Limits.reserve_control(self(), 1, ctx.limits)
        token
      end

    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    epoch = elem(waiter.request, 0)

    assert_event(
      {:activation_event, ^coordinator, ^epoch, {:terminal, ^attempt, _, _, _, :limits_exceeded}}
    )

    refute_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, _}}, 0)
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert {:ok, ^epoch} = api(:epoch, [coordinator])
    assert :ok = Limits.release(ingress, ctx.limits)
    for token <- tokens, do: assert(:ok == Limits.release_control(token, ctx.limits))
    assert stats(ctx).control.count == 0
  end

  test "terminal backend errors fit the reserved envelope even with combining text", ctx do
    coordinator = coordinator(ctx)
    {waiter, message, ingress} = waiting(ctx, coordinator)
    assert {:ok, attempt} = api(:admit, [waiter, message, selected(), coordinator])
    epoch = elem(waiter.request, 0)
    assert_event({:activation_event, ^coordinator, ^epoch, {:launch_commit, ^attempt}})
    text = "a" <> String.duplicate("\u0301", 10_000)

    assert :ok =
             api(:backend_result, [
               attempt,
               {:error, {:backend_error, "org.example.Error", text}},
               coordinator
             ])

    assert_event(
      {:activation_event, ^coordinator, ^epoch,
       {:terminal, ^attempt, _, _, _, {:backend_error, name, bounded}}}
    )

    assert name == "org.example.Error"
    assert byte_size(bounded) <= 4096
    assert String.valid?(bounded)
    await(fn -> stats(ctx).global.activation_messages == 0 end)
    assert :ok = Limits.release(ingress, ctx.limits)
    assert stats(ctx).control.count == 0
  end

  defp selected, do: %{key: :definition, backend: :helper, unit: nil}

  defp coordinator(ctx, opts \\ []) do
    assert Code.ensure_loaded?(Activation), "missing supervised activation coordinator"

    start_supervised!(%{
      id: make_ref(),
      start:
        {Activation, :start_link,
         [
           [
             name: nil,
             limits: ctx.limits,
             router: Keyword.get(opts, :router, self()),
             state_options: Keyword.get(opts, :state_options, [])
           ]
         ]},
      restart: :temporary
    })
  end

  defp waiting(ctx, coordinator) do
    peer = owner()
    assert :ok = Limits.acquire(peer, %{uid: 1000, gid: 1000, pid: 123}, ctx.limits)
    assert {:ok, ingress} = Limits.reserve_ingress(peer, 2048, ctx.limits)
    {:ok, epoch} = api(:epoch, [coordinator])
    request = {epoch, make_ref()}
    incarnation = {make_ref(), ":1.1"}

    identity = %{
      caller: peer,
      caller_incarnation: incarnation,
      request_key: request,
      deadline: System.monotonic_time(:millisecond) + 5000
    }

    assert {:ok, lease} =
             Limits.reserve_activation(ingress, identity, 2048, [], coordinator, ctx.limits)

    waiter = %{
      caller: peer,
      caller_incarnation: incarnation,
      request: request,
      serial: {epoch, incarnation, 1},
      kind: :automatic,
      message_type: :method_call,
      flags: 0,
      destination: "org.example.Activated",
      generation: 1,
      definition: selected().key,
      deadline: identity.deadline,
      lease: lease
    }

    message =
      Message.method_call("/org/example", "org.example.Service", "Request",
        serial: 1,
        destination: waiter.destination,
        body: [String.duplicate("a", 1024)],
        signature: "s",
        sender: ":1.1"
      )

    {waiter, message, ingress}
  end

  defp api(function, args) do
    assert function_exported?(Activation, function, length(args)),
           "missing coordinator API #{function}"

    apply(Activation, function, args)
  end

  defp stats(ctx) do
    assert {:ok, stats} = Limits.snapshot(ctx.limits)
    stats
  end

  defp owner, do: start_supervised!({Task, &owner_loop/0}, id: make_ref())

  defp owner_loop do
    receive do
      {:invoke, from, reference, fun} ->
        send(from, {reference, fun.()})
        owner_loop()

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

  defp await(predicate), do: await(predicate, System.monotonic_time(:millisecond) + 3000)

  defp await(predicate, deadline) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(predicate, deadline)
    end
  end
end
