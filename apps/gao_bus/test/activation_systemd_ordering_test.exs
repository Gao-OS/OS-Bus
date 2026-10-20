defmodule GaoBus.ActivationSystemdOrderingTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Activation, Config, Limits, NameRegistry, Policy, Router}

  @bus "org.freedesktop.DBus"
  @pid1 "org.freedesktop.systemd1"
  @activated "org.example.Activated"
  @other "org.example.Other"
  @unit "example-activated.service"
  @failure "org.freedesktop.DBus.Error.Spawn.ServiceNotFound"
  @moduletag :tmp_dir

  setup ctx do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    services = Path.join(ctx.tmp_dir, "services")
    File.mkdir!(services)

    File.write!(
      Path.join(services, @pid1 <> ".service"),
      "[D-BUS Service]\nName=#{@pid1}\nExec=/bin/false\nUser=root\n"
    )

    for name <- [@activated, @other] do
      File.write!(
        Path.join(services, name <> ".service"),
        "[D-BUS Service]\nName=#{name}\nExec=/bin/false\nUser=root\nSystemdService=#{@unit}\n"
      )
    end

    path = Path.join(ctx.tmp_dir, "system.conf")

    File.write!(
      path,
      "<busconfig><type>system</type><user>messagebus</user><servicedir>#{services}</servicedir><policy context=\"default\"><allow user=\"*\"/><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>"
    )

    accounts = %{
      users: %{"root" => 0, "messagebus" => 4, "client" => 1000},
      groups: %{"root" => 0, "messagebus" => 4, "client" => 1000},
      memberships: %{0 => [0], 4 => [4], 1000 => [1000]},
      user_records: %{
        "root" => %{name: "root", uid: 0, gid: 0, groups: [0], provenance: nil},
        "messagebus" => %{name: "messagebus", uid: 4, gid: 4, groups: [4], provenance: nil},
        "client" => %{name: "client", uid: 1000, gid: 1000, groups: [1000], provenance: nil}
      }
    }

    assert {:ok, config} = Config.load(path, accounts: accounts)
    start_supervised!(Limits)
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!({Policy, rules: config})
    start_supervised!(GaoBus.Ids)
    activation_mode = Map.get(ctx, :activation_mode, :systemd)

    router =
      start_supervised!({Router, activation: %{mode: activation_mode, service_start_timeout: 10_000}})

    coordinator = start_supervised!({Activation, state_options: [service_start_timeout: 10_000]})
    client = peer(":1.1", 1000)
    manager = peer(":1.2", 0)
    if Map.get(ctx, :manager_connected, true), do: own(manager, @pid1)

    %{
      client: client,
      manager: manager,
      config: config,
      coordinator: coordinator,
      router: router,
      router_monitor: Process.monitor(router)
    }
  end

  test "terminal failure before queued systemd launch prevents a stale request", ctx do
    gate = gate_call(ctx.coordinator, &match?({:commit_systemd, _, _, _}, &1))
    assert :ok = Router.route(request(301), ctx.client)
    assert_receive {:coordinator_gated, coordinator, ^gate}, 1000
    assert coordinator == ctx.coordinator

    # Router is awaiting commit; this genuine peer signal reaches its mailbox
    # before the coordinator can emit the asynchronous launch notification.
    assert :ok = Router.route(failure(302), ctx.manager)
    send(coordinator, {:release_coordinator, gate})

    assert_receive {:seen, client,
                    %Message{reply_serial: 301, error_name: @failure, body: ["missing unit"]}},
                   1000

    assert client == ctx.client
    assert_drained(ctx)
    peer_barrier(ctx.manager)
    refute_receive {:seen, _, %Message{member: "ActivationRequest"}}, 0
    assert_same_router(ctx)
  end

  test "terminal failure before queued resolution prevents forwarding retained work", ctx do
    assert :ok = Router.route(request(311), ctx.client)
    manager = ctx.manager
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest", body: [@unit]}}, 1000
    target = peer(":1.3", 1000)

    gate = gate_call(ctx.coordinator, &match?({:event, {:name_available, @activated}}, &1))
    assert :ok = Router.route(bus_call("RequestName", 312, [@activated, 0], "su"), target)
    assert_receive {:coordinator_gated, coordinator, ^gate}, 1000
    assert coordinator == ctx.coordinator

    # Name acquisition has happened. The coordinator's resolution transition
    # precedes failure, but its notification will be queued behind this signal.
    assert :ok = Router.route(failure(313), manager)
    send(coordinator, {:release_coordinator, gate})

    assert_receive {:seen, client,
                    %Message{reply_serial: 311, error_name: @failure, body: ["missing unit"]}},
                   1000

    assert client == ctx.client
    assert_drained(ctx)
    peer_barrier(target)
    refute_receive {:seen, ^target, %Message{member: "Work", serial: 311}}, 0
    assert :sys.get_state(Router).pending.entries == %{}
    assert_same_router(ctx)
  end

  @tag manager_connected: false
  test "launch refusal reaches a shared unit after its original representative retires", ctx do
    assert :ok = Router.route(request(321), ctx.client)

    second =
      Message.method_call("/work", "org.example.Work", "Work", serial: 322, destination: @other)

    assert :ok = Router.route(second, ctx.client)
    await(fn -> MapSet.size(:sys.get_state(ctx.coordinator).deferred_systemd) == 2 end)
    bookkeeping = :sys.get_state(ctx.coordinator).bookkeeping
    attempts = Map.new(bookkeeping.attempts, fn {key, attempt} -> {attempt.name, key} end)
    first_attempt = Map.fetch!(attempts, @activated)
    second_attempt = Map.fetch!(attempts, @other)
    target = peer(":1.3", 1000)

    deny = %{
      selector: :mandatory,
      rules: [
        %{
          effect: :deny,
          attributes: %{
            "receive_interface" => "org.freedesktop.systemd1.Activator",
            "receive_member" => "ActivationRequest"
          }
        }
      ]
    }

    assert {:ok, _generation} =
             Policy.reload(%{ctx.config | policies: ctx.config.policies ++ [deny]})

    {owner_gate, launch_gate} = gate_owner_hint_and_launch(ctx.router, first_attempt)
    assert :ok = Router.route(bus_call("RequestName", 323, [@pid1, 0], "su"), ctx.manager)
    assert_receive {:router_gated, :owner_hint, router, ^owner_gate}, 1000
    assert router == ctx.router

    # This is trusted name-registry fixture acquisition, not wire ownership
    # qualification. Its real ownership hint must already be in Router's mailbox
    # before PID1's hint can enqueue the deferred launch-commit notifications.
    assert {:ok, 1} = NameRegistry.request_name(@activated, 0, target, ":1.3")
    send(router, {:release_router, owner_gate})
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 321}}, 1000
    assert_receive {:router_gated, :launch, ^router, ^launch_gate}, 1000

    # Prove the failure targets a surviving unit member rather than assuming
    # that original representative retirement happened at the desired boundary.
    bookkeeping = :sys.get_state(ctx.coordinator).bookkeeping
    refute Map.has_key?(bookkeeping.attempts, first_attempt)
    assert %{issued: true, waiters: waiters} = bookkeeping.attempts[second_attempt]
    assert map_size(waiters) == 1
    unit = bookkeeping.units[{elem(second_attempt, 0), @unit}]
    assert unit.issued
    assert unit.attempts == MapSet.new([second_attempt])
    send(router, {:release_router, launch_gate})

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 322,
                      error_name: "org.freedesktop.DBus.Error.AccessDenied"
                    }},
                   1000

    assert client == ctx.client
    assert_drained(ctx)
    bookkeeping = :sys.get_state(ctx.coordinator).bookkeeping
    assert bookkeeping.attempts == %{}
    assert bookkeeping.units == %{}
    refute Map.has_key?(:sys.get_state(Router).pending.entries, {ctx.client, 322})
    peer_barrier(ctx.manager)
    refute_receive {:seen, _, %Message{member: "ActivationRequest"}}, 0
    assert_same_router(ctx)
  end

  @tag activation_mode: :systemd_helper
  test "systemd failure in mixed activation mode reaches the automatic caller", ctx do
    assert :ok = Router.route(request(331), ctx.client)
    manager = ctx.manager
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest", body: [@unit]}}, 1000

    assert :ok = Router.route(failure(332), manager)
    client = ctx.client

    assert_receive {:seen, ^client,
                    %Message{
                      type: :error,
                      reply_serial: 331,
                      error_name: @failure,
                      body: ["missing unit"]
                    }},
                   1000

    assert_drained(ctx)
    bookkeeping = :sys.get_state(ctx.coordinator).bookkeeping
    assert bookkeeping.attempts == %{}
    assert bookkeeping.units == %{}
    assert :sys.get_state(ctx.router).pending.entries == %{}
    assert_same_router(ctx)
  end

  defp gate_owner_hint_and_launch(router, first_attempt) do
    test = self()
    owner_gate = make_ref()
    launch_gate = make_ref()

    debug = fn state, event, _process ->
      gate =
        case event do
          {:in,
           {:control_work, _token,
            {:emit_signal, "/org/freedesktop/DBus", @bus, "NameOwnerChanged", "sss",
             [@pid1, "", _new], nil}}} ->
            {:owner_hint, owner_gate}

          {:in,
           {:control_work, _token,
            {:activation_event, _coordinator, _epoch,
             {:launch_systemd, ^first_attempt, _definition, _owner}}}} ->
            {:launch, launch_gate}

          _ ->
            nil
        end

      if gate do
        {kind, token} = gate
        send(test, {:router_gated, kind, self(), token})

        receive do
          {:release_router, ^token} -> :ok
        end
      end

      state
    end

    assert :ok = :sys.install(router, {debug, nil})

    on_exit(fn ->
      send(router, {:release_router, owner_gate})
      send(router, {:release_router, launch_gate})
    end)

    {owner_gate, launch_gate}
  end

  defp gate_call(coordinator, matches?) do
    test = self()
    gate = make_ref()

    debug = fn state, event, _process ->
      case event do
        {:in, {:"$gen_call", _from, request}} ->
          if matches?.(request) do
            send(test, {:coordinator_gated, self(), gate})

            receive do
              {:release_coordinator, ^gate} -> :ok
            end
          end

        _ ->
          :ok
      end

      state
    end

    assert :ok = :sys.install(coordinator, {debug, nil})
    on_exit(fn -> send(coordinator, {:release_coordinator, gate}) end)
    gate
  end

  defp peer(name, uid) do
    test = self()
    pid = start_supervised!({Task, fn -> peer_loop(test) end}, id: make_ref())
    credentials = %{uid: uid, gid: uid, pid: 123, groups: [uid], unique_name: name}
    assert :ok = Limits.acquire(pid, credentials)
    assert :ok = Limits.auth_completed(pid)
    Router.register_peer(pid, name, credentials)
    assert :ok = NameRegistry.register_unique(name, pid)
    _ = :sys.get_state(Router)
    assert_receive {:seen, ^pid, %Message{member: "NameAcquired", body: [^name]}}, 1000
    pid
  end

  defp peer_loop(test) do
    receive do
      {:send_message, message, {token, _queued_at}} ->
        assert :ok = Limits.release(token)
        send(test, {:seen, self(), message})
        peer_loop(test)

      {:barrier, caller, token} ->
        send(caller, {:peer_barrier, self(), token})
        peer_loop(test)
    end
  end

  defp peer_barrier(peer) do
    _ = :sys.get_state(Router)
    token = make_ref()
    send(peer, {:barrier, self(), token})
    assert_receive {:peer_barrier, ^peer, ^token}, 1000
  end

  defp own(target, name) do
    assert :ok = Router.route(bus_call("RequestName", 99, [name, 0], "su"), target)
    assert_receive {:seen, ^target, %Message{reply_serial: 99, body: [1]}}, 1000
    _ = :sys.get_state(Router)
  end

  defp request(serial) do
    Message.method_call("/work", "org.example.Work", "Work",
      serial: serial,
      destination: @activated
    )
  end

  defp failure(serial) do
    Message.signal(
      "/org/freedesktop/systemd1",
      "org.freedesktop.systemd1.Activator",
      "ActivationFailure",
      serial: serial,
      destination: @bus,
      signature: "sss",
      body: [@unit, @failure, "missing unit"]
    )
  end

  defp bus_call(member, serial, body, signature) do
    Message.method_call("/org/freedesktop/DBus", @bus, member,
      serial: serial,
      destination: @bus,
      body: body,
      signature: signature
    )
  end

  defp assert_drained(ctx) do
    await(fn ->
      assert {:ok, stats} = Limits.snapshot()
      stats.global.activation_messages == 0 and stats.global.ingress_messages == 0
    end)

    _ = :sys.get_state(ctx.coordinator)
    _ = :sys.get_state(Router)
    assert :sys.get_state(ctx.coordinator).messages == %{}
  end

  defp assert_same_router(ctx) do
    assert Process.whereis(Router) == ctx.router
    monitor = ctx.router_monitor
    refute_receive {:DOWN, ^monitor, :process, _pid, _reason}, 0
  end

  defp await(predicate), do: await(predicate, System.monotonic_time(:millisecond) + 1000)

  defp await(predicate, deadline) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(predicate, deadline)
    end
  end
end
