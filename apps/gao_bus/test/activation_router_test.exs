defmodule GaoBus.ActivationRouterTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Activation, Config, Limits, NameRegistry, Policy, Router}

  @bus "org.freedesktop.DBus"
  @pid1 "org.freedesktop.systemd1"
  @activated "org.example.Activated"
  @other "org.example.Other"
  @unit "example-activated.service"
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

    start_supervised!(
      {Router,
       activation: %{
         mode: Map.get(ctx, :activation_mode, :systemd),
         service_start_timeout: Map.get(ctx, :service_timeout, 2500)
       }}
    )

    start_supervised!(
      {DynamicSupervisor, name: GaoBus.Activation.HelperSupervisor, strategy: :one_for_one}
    )

    coordinator =
      start_supervised!(
        {Activation, state_options: [service_start_timeout: Map.get(ctx, :service_timeout, 2500)]}
      )

    client = peer(":1.1", 1000)
    %{client: client, config: config, coordinator: coordinator}
  end

  @tag activation_mode: :helper
  test "unbound helper proves no launch and returns its distinct setup error", ctx do
    assert :ok = Router.route(request(@activated, 201), ctx.client)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 201,
                      error_name: "org.freedesktop.DBus.Error.Spawn.FailedToSetup"
                    }},
                   3000

    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 0 end)
    assert :sys.get_state(ctx.coordinator).bookkeeping.children == %{}
    assert DynamicSupervisor.which_children(GaoBus.Activation.HelperSupervisor) == []

    assert :ok =
             Router.route(bus_call("Ping", 202, [], "", interface: @bus <> ".Peer"), ctx.client)

    assert_receive {:seen, ^client, %Message{type: :method_return, reply_serial: 202}}, 1000
  end

  @tag activation_mode: :helper
  test "no-auto-start never reserves a helper or an activation lease", ctx do
    assert :ok = Router.route(request(@activated, 203, flags: 2), ctx.client)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 203,
                      error_name: "org.freedesktop.DBus.Error.NameHasNoOwner"
                    }},
                   1000

    assert client == ctx.client
    assert :sys.get_state(ctx.coordinator).bookkeeping.children == %{}
    assert :sys.get_state(ctx.coordinator).helpers == %{}
    assert stats().global.activation_messages == 0
    assert DynamicSupervisor.which_children(GaoBus.Activation.HelperSupervisor) == []
  end

  @tag activation_mode: :helper
  test "authorized name acquisition after helper reservation suppresses the queued launch", ctx do
    target = peer(":1.2", 0)
    test = self()
    gate = make_ref()
    workers = GaoBus.Activation.HelperSupervisor
    client = ctx.client

    # Observe every actual start call, including a worker that could exit before
    # the final which_children check. This does not substitute a fake supervisor.
    observe_starts = fn count, event, _process ->
      case event do
        {:in, {:"$gen_call", _from, {:start_child, _child}}} ->
          count + 1

        {:in, {:"$gen_call", _from, :count_children}} ->
          send(test, {:helper_start_count, gate, count})
          count

        _ ->
          count
      end
    end

    # OTP has sent the commit reply before this outgoing debug event. Router can
    # authorize RequestName while the coordinator's reserved launch is gated.
    gate_commit = fn phase, event, _process ->
      case {phase, event} do
        {:waiting, {:out, {:ok, :issued}, _from, state}} ->
          send(test, {:helper_reserved, gate, state.bookkeeping, state.helpers})

          receive do
            {:release_helper_launch, ^gate} -> :ok
          after
            2000 -> raise "helper launch barrier was not released"
          end

          :released

        _ ->
          phase
      end
    end

    assert :ok = :sys.install(workers, {observe_starts, 0})
    assert :ok = :sys.install(ctx.coordinator, {gate_commit, :waiting})
    on_exit(fn -> send(ctx.coordinator, {:release_helper_launch, gate}) end)
    message = request(@activated, 204, flags: 1, signature: "s", body: ["reserved payload"])
    bytes = byte_size(Message.encode_message(message))
    assert :ok = Router.route(message, ctx.client, bytes)

    assert_receive {:helper_reserved, ^gate, bookkeeping, helpers}, 1000
    assert [{attempt, %{issued: true, owned: false}}] = Map.to_list(bookkeeping.attempts)
    assert %{phase: :reserved, name: @activated} = bookkeeping.children[attempt]
    assert map_size(bookkeeping.children) == 1
    assert helpers == %{}
    assert stats().global.activation_messages == 1
    assert stats().global.activation_bytes == bytes
    assert stats().global.ingress_bytes == bytes

    # Do not use own/3's Router barrier here: NameOwnerChanged may wait on the
    # gated coordinator after RequestName has already returned successfully.
    assert :ok = Router.route(bus_call("RequestName", 205, [@activated, 0], "su"), target)
    assert_receive {:seen, ^target, %Message{reply_serial: 205, body: [1]}}, 1000
    assert {:ok, ^target} = NameRegistry.resolve(@activated)
    send(ctx.coordinator, {:release_helper_launch, gate})

    expected = %{message | sender: ":1.1"}
    assert_receive {:seen, ^target, ^expected}, 1000
    await_queue_retirement()
    assert_activation_retired(ctx.coordinator)
    assert :sys.get_state(ctx.coordinator).helpers == %{}
    assert :sys.get_state(Router).activation_claims == %{}
    assert :sys.get_state(Router).pending.entries == %{}
    assert DynamicSupervisor.which_children(workers) == []
    assert %{active: 0} = DynamicSupervisor.count_children(workers)
    assert_receive {:helper_start_count, ^gate, 0}, 1000

    # Fence the recipient's mailbox before checking for a second delivery.
    ref = make_ref()
    send(target, {:delivery_barrier, test, ref})
    assert_receive {:delivery_barrier, ^ref}, 1000
    refute_receive {:seen, ^target, %Message{member: "Work", serial: 204}}, 0
    refute_receive {:seen, ^client, %Message{reply_serial: 204}}, 0

    assert :ok =
             Router.route(bus_call("Ping", 206, [], "", interface: @bus <> ".Peer"), ctx.client)

    assert_receive {:seen, client, %Message{type: :method_return, reply_serial: 206}}, 1000
    assert client == ctx.client
    await_queue_retirement()
  end

  test "automatic PID1 waiting preserves exact source bytes and does not obstruct healthy traffic",
       ctx do
    message = request(@pid1, 11, body: ["retained"], signature: "s")
    bytes = byte_size(Message.encode_message(message))
    assert :ok = Router.route(message, ctx.client, bytes)
    await(fn -> stats().global.activation_messages == 1 end)
    assert stats().global.activation_bytes == bytes
    assert stats().global.ingress_bytes == bytes
    assert :sys.get_state(Router).pending.entries == %{}

    assert :ok =
             Router.route(bus_call("Ping", 12, [], "", interface: @bus <> ".Peer"), ctx.client)

    assert_receive {:seen, client, %Message{type: :method_return, reply_serial: 12}}, 1000
    assert client == ctx.client
    target = peer(":1.2", 0)
    own(target, @pid1)

    assert_receive {:seen, ^target,
                    %Message{member: "Work", serial: 11, sender: ":1.1", body: ["retained"]}},
                   1000

    await(fn ->
      stats().global.activation_messages == 0 and stats().global.ingress_messages == 0
    end)

    assert %{callee: ^target} = :sys.get_state(Router).pending.entries[{ctx.client, 11}]
  end

  test "explicit starts honor NO_AUTO_START and return eventual SUCCESS then ALREADY_RUNNING",
       ctx do
    assert :ok =
             Router.route(
               bus_call("StartServiceByName", 21, [@pid1, 0], "su", flags: 2),
               ctx.client
             )

    await(fn -> stats().global.activation_messages == 1 end)
    target = peer(":1.2", 0)
    own(target, @pid1)

    assert_receive {:seen, client,
                    %Message{type: :method_return, reply_serial: 21, signature: "u", body: [1]}},
                   1000

    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 0 end)
    assert :ok = Router.route(bus_call("StartServiceByName", 22, [@pid1, 0], "su"), ctx.client)

    assert_receive {:seen, ^client, %Message{type: :method_return, reply_serial: 22, body: [2]}},
                   1000

    assert :sys.get_state(Router).pending.entries == %{}
  end

  test "explicit start of the bus itself is already running", ctx do
    assert :ok = Router.route(bus_call("StartServiceByName", 23, [@bus, 0], "su"), ctx.client)

    assert_receive {:seen, client, %Message{type: :method_return, reply_serial: 23, body: [2]}},
                   1000

    assert client == ctx.client
    assert stats().global.activation_messages == 0
  end

  @tag :capture_log
  test "indeterminate admitted call tears down the epoch and reclaims leases", ctx do
    assert :ok = Router.route(request(@pid1, 24), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)
    router = Process.whereis(Router)
    router_monitor = Process.monitor(router)
    coordinator_monitor = Process.monitor(ctx.coordinator)
    test = self()
    gate = make_ref()
    # A real OTP debug handler gates the admission after dequeue, before claim.
    # No timing race or production-only test hook is required.
    debug = fn state, event, _process ->
      case event do
        {:in, {:"$gen_call", _from, {:admit, _waiter, _message, _definition}}} ->
          send(test, {:admission_gated, self(), gate})
          receive do: ({:release_admission, ^gate} -> :ok)

        _ ->
          :ok
      end

      state
    end

    assert :ok = :sys.install(ctx.coordinator, {debug, nil})
    on_exit(fn -> send(ctx.coordinator, {:release_admission, gate}) end)
    assert :ok = Router.route(request(@pid1, 25), ctx.client)
    assert_receive {:admission_gated, coordinator, ^gate}, 1000
    assert coordinator == ctx.coordinator

    assert_receive {:DOWN, ^router_monitor, :process, ^router,
                    {:activation_failed, :activation_unavailable}},
                   6500

    send(coordinator, {:release_admission, gate})

    assert_receive {:DOWN, ^coordinator_monitor, :process, ^coordinator,
                    {:router_down, {:activation_failed, :activation_unavailable}}},
                   1000

    await(fn ->
      stats().global.activation_messages == 0 and stats().global.ingress_messages == 0
    end)
  end

  test "NO_AUTO_START does not admit calls or directed signals", ctx do
    assert :ok = Router.route(request(@pid1, 31, flags: 2), ctx.client)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 31,
                      error_name: "org.freedesktop.DBus.Error.NameHasNoOwner"
                    }},
                   1000

    assert client == ctx.client

    signal =
      Message.signal("/work", "org.example.Work", "Notice",
        serial: 32,
        destination: @pid1,
        flags: 2
      )

    assert :ok = Router.route(signal, ctx.client)
    _ = :sys.get_state(Router)
    assert stats().global.activation_messages == 0
  end

  test "directed no-reply signals still wait and deliver without reply correlation", ctx do
    signal =
      Message.signal("/work", "org.example.Work", "Notice",
        serial: 41,
        destination: @pid1,
        flags: 1,
        signature: "s",
        body: ["signal"]
      )

    assert :ok = Router.route(signal, ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)
    target = peer(":1.2", 0)
    own(target, @pid1)

    assert_receive {:seen, ^target, %Message{type: :signal, member: "Notice", body: ["signal"]}},
                   1000

    await(fn -> stats().global.activation_messages == 0 end)
    assert :sys.get_state(Router).pending.entries == %{}
    refute_receive {:seen, _, %Message{reply_serial: 41}}, 0
  end

  test "activation serial claims also protect an earlier waiter from direct-call reuse", ctx do
    assert :ok = Router.route(request(@pid1, 51), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)
    target = peer(":1.2", 1000)
    assert :ok = Router.route(request(":1.2", 51), ctx.client)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 51,
                      error_name: "org.freedesktop.DBus.Error.AccessDenied"
                    }},
                   1000

    assert client == ctx.client
    refute_receive {:seen, ^target, %Message{member: "Work"}}, 0
    assert stats().global.activation_messages == 1
    own(target, @pid1)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 51}}, 1000
    await(fn -> stats().global.activation_messages == 0 end)
  end

  test "queued delivery uses current send policy and releases its serial after denial", ctx do
    assert :ok = Router.route(request(@pid1, 61), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)

    deny = %{
      selector: :mandatory,
      rules: [
        %{
          effect: :deny,
          attributes: %{"send_interface" => "org.example.Work", "send_member" => "Work"}
        }
      ]
    }

    assert {:ok, _generation} =
             Policy.reload(%{ctx.config | policies: ctx.config.policies ++ [deny]})

    target = peer(":1.2", 0)
    own(target, @pid1)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 61,
                      error_name: "org.freedesktop.DBus.Error.AccessDenied"
                    }},
                   1000

    assert client == ctx.client
    refute_receive {:seen, ^target, %Message{member: "Work"}}, 0
    await(fn -> stats().global.activation_messages == 0 end)
    assert :sys.get_state(Router).pending.entries == %{}
    assert {:ok, _generation} = Policy.reload(ctx.config)
    assert :ok = Router.route(request(@pid1, 61), ctx.client)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 61}}, 1000
  end

  @tag service_timeout: 200
  test "natural activation timeout returns TimedOut and reclaims all queue credit", ctx do
    assert :ok = Router.route(request(@pid1, 71), ctx.client)

    assert_receive {:seen, client,
                    %Message{reply_serial: 71, error_name: "org.freedesktop.DBus.Error.TimedOut"}},
                   1000

    assert client == ctx.client

    await(fn ->
      stats().global.activation_messages == 0 and stats().global.ingress_messages == 0
    end)

    assert :sys.get_state(Router).pending.entries == %{}
  end

  test "caller death drains waiting work without replaying into a later owner", ctx do
    assert :ok = Router.route(request(@pid1, 81), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)
    monitor = Process.monitor(ctx.client)
    Process.exit(ctx.client, :kill)
    assert_receive {:DOWN, ^monitor, :process, client, :killed}
    assert client == ctx.client

    await(fn ->
      stats().global.activation_messages == 0 and stats().global.ingress_messages == 0
    end)

    target = peer(":1.2", 0)
    own(target, @pid1)
    refute_receive {:seen, ^target, %Message{member: "Work", serial: 81}}, 0
  end

  test "shared systemd units emit one directed request and resolve each name separately", ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    assert :ok = Router.route(request(@activated, 101), ctx.client)
    assert :ok = Router.route(request(@other, 102), ctx.client)

    assert_receive {:seen, ^manager,
                    %Message{
                      type: :signal,
                      sender: @bus,
                      destination: @pid1,
                      path: "/org/freedesktop/DBus",
                      interface: "org.freedesktop.systemd1.Activator",
                      member: "ActivationRequest",
                      signature: "s",
                      body: [@unit],
                      fds: []
                    }},
                   1000

    await(fn -> stats().global.activation_messages == 2 end)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    first = peer(":1.3", 1000)
    own(first, @activated)
    assert_receive {:seen, ^first, %Message{serial: 101, member: "Work"}}, 1000
    await(fn -> stats().global.activation_messages == 1 end)
    second = peer(":1.4", 1000)
    own(second, @other)
    assert_receive {:seen, ^second, %Message{serial: 102, member: "Work"}}, 1000
    await(fn -> stats().global.activation_messages == 0 end)
  end

  @tag service_timeout: 750
  test "an issued systemd request times out naturally and permits a fresh same-unit retry", ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    assert :ok = Router.route(request(@activated, 211), ctx.client)
    assert_activation_request(manager)

    [{attempt, %{issued: true}}] =
      Map.to_list(:sys.get_state(ctx.coordinator).bookkeeping.attempts)

    assert_receive {:seen, client,
                    %Message{reply_serial: 211, error_name: "org.freedesktop.DBus.Error.TimedOut"}},
                   1500

    assert client == ctx.client
    await_queue_retirement()
    assert_activation_retired(ctx.coordinator)
    assert :sys.get_state(Router).pending.entries == %{}

    assert :ok = Router.route(request(@activated, 212, flags: 1), ctx.client)
    assert_activation_request(manager)

    [{retry, %{issued: true}}] =
      Map.to_list(:sys.get_state(ctx.coordinator).bookkeeping.attempts)

    refute retry == attempt
    _ = :sys.get_state(Router)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    target = peer(":1.3", 1000)
    own(target, @activated)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 212}}, 1000
    await_queue_retirement()
    assert_activation_retired(ctx.coordinator)
  end

  @tag service_timeout: 1500
  test "last caller cancellation retains an issued unit until its original deadline", ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    caller = peer(":1.3", 1000)
    assert :ok = Router.route(request(@activated, 221), caller)
    assert_activation_request(manager)

    [{attempt, %{issued: true, deadline: deadline}}] =
      Map.to_list(:sys.get_state(ctx.coordinator).bookkeeping.attempts)

    monitor = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^caller, :killed}, 1000
    await_queue_retirement()
    state = :sys.get_state(ctx.coordinator)
    assert System.monotonic_time(:millisecond) < deadline

    assert [{^attempt, %{issued: true, deadline: ^deadline, waiters: waiters}}] =
             Map.to_list(state.bookkeeping.attempts)

    assert waiters == %{}
    assert state.bookkeeping.requests == %{}
    assert state.bookkeeping.serials == %{}
    assert state.messages == %{}
    assert state.bookkeeping.children == %{}

    assert [{_, %{issued: true, deadline: ^deadline, attempts: members}}] =
             Map.to_list(state.bookkeeping.units)

    assert members == MapSet.new([attempt])
    assert state.bookkeeping.attempts[attempt].timer_deadline == deadline
    assert Map.keys(state.timers) == [attempt]
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0

    await(fn -> :sys.get_state(ctx.coordinator).bookkeeping.attempts == %{} end, deadline + 1000)
    assert_activation_retired(ctx.coordinator)
    assert :ok = Router.route(request(@activated, 222, flags: 1), ctx.client)
    assert_activation_request(manager)

    [{retry, %{issued: true}}] =
      Map.to_list(:sys.get_state(ctx.coordinator).bookkeeping.attempts)

    refute retry == attempt
    _ = :sys.get_state(Router)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    target = peer(":1.4", 1000)
    own(target, @activated)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 222}}, 1000
    refute_receive {:seen, ^target, %Message{member: "Work", serial: 221}}, 0
    await_queue_retirement()
    assert_activation_retired(ctx.coordinator)
  end

  @tag service_timeout: 3000
  test "authorized name ownership retires an empty issued unit without replaying canceled work",
       ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    caller = peer(":1.3", 1000)
    assert :ok = Router.route(request(@activated, 231), caller)
    assert_activation_request(manager)

    [{attempt, %{issued: true, deadline: deadline}}] =
      Map.to_list(:sys.get_state(ctx.coordinator).bookkeeping.attempts)

    monitor = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^caller, :killed}, 1000
    await_queue_retirement()
    state = :sys.get_state(ctx.coordinator)
    assert System.monotonic_time(:millisecond) < deadline

    assert [{^attempt, %{issued: true, waiters: waiters}}] =
             Map.to_list(state.bookkeeping.attempts)

    assert waiters == %{}
    target = peer(":1.4", 1000)

    assert {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"} =
             NameRegistry.get_name_owner(@activated)

    assert :ok =
             Router.emit_signal(
               "/org/freedesktop/DBus",
               @bus,
               "NameOwnerChanged",
               "sss",
               [@activated, "", ":1.4"]
             )

    _ = :sys.get_state(Router)
    state = :sys.get_state(ctx.coordinator)

    assert [{^attempt, %{issued: true, waiters: waiters}}] =
             Map.to_list(state.bookkeeping.attempts)

    assert waiters == %{}

    assert {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"} =
             NameRegistry.get_name_owner(@activated)

    refute_receive {:seen, ^target, %Message{member: "Work", serial: 231}}, 0
    own(target, @activated)
    assert System.monotonic_time(:millisecond) < deadline
    await(fn -> :sys.get_state(ctx.coordinator).bookkeeping.attempts == %{} end)
    assert System.monotonic_time(:millisecond) < deadline
    assert_activation_retired(ctx.coordinator)
    refute_receive {:seen, ^target, %Message{member: "Work", serial: 231}}, 0
    assert :sys.get_state(Router).pending.entries == %{}

    for {healthy, serial} <- [{manager, 232}, {ctx.client, 233}] do
      assert :ok =
               Router.route(bus_call("Ping", serial, [], "", interface: @bus <> ".Peer"), healthy)

      assert_receive {:seen, ^healthy, %Message{type: :method_return, reply_serial: ^serial}},
                     1000
    end

    assert :ok = Router.route(bus_call("ReleaseName", 234, [@activated], "s"), target)

    assert_receive {:seen, ^target, %Message{type: :method_return, reply_serial: 234, body: [1]}},
                   1000

    assert :ok = Router.route(request(@activated, 235, flags: 1), ctx.client)
    assert_activation_request(manager)

    [{retry, %{issued: true}}] =
      Map.to_list(:sys.get_state(ctx.coordinator).bookkeeping.attempts)

    refute retry == attempt
    own(target, @activated)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 235}}, 1000
    refute_receive {:seen, ^target, %Message{member: "Work", serial: 231}}, 0
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    await_queue_retirement()
    assert_activation_retired(ctx.coordinator)
    assert :sys.get_state(Router).pending.entries == %{}
  end

  test "unit launch waits for PID1 connection without launching its false executable", ctx do
    assert :ok = Router.route(request(@activated, 111), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)

    assert :ok =
             Router.route(bus_call("Ping", 112, [], "", interface: @bus <> ".Peer"), ctx.client)

    assert_receive {:seen, client, %Message{reply_serial: 112, type: :method_return}}, 1000
    assert client == ctx.client
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest", body: [@unit]}}, 1000
    target = peer(":1.3", 1000)
    own(target, @activated)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 111}}, 1000
    await(fn -> stats().global.activation_messages == 0 end)
  end

  test "only the current authenticated systemd owner can fail a shared issued unit", ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    assert :ok = Router.route(request(@activated, 121), ctx.client)
    assert :ok = Router.route(request(@other, 122), ctx.client)
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 1000
    await(fn -> stats().global.activation_messages == 2 end)
    intruder = peer(":1.3", 0)

    failure =
      Message.signal(
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Activator",
        "ActivationFailure",
        serial: 123,
        sender: ":1.2",
        destination: @bus,
        signature: "sss",
        body: [@unit, "org.freedesktop.DBus.Error.Spawn.ServiceNotFound", "missing unit"]
      )

    assert :ok = Router.route(failure, intruder)
    _ = :sys.get_state(Router)
    assert stats().global.activation_messages == 2
    assert :ok = Router.route(failure, manager)

    for serial <- [121, 122] do
      assert_receive {:seen, client,
                      %Message{
                        reply_serial: ^serial,
                        error_name: "org.freedesktop.DBus.Error.Spawn.ServiceNotFound",
                        body: ["missing unit"]
                      }},
                     1000

      assert client == ctx.client
    end

    await(fn ->
      stats().global.activation_messages == 0 and stats().global.ingress_messages == 0
    end)

    refute_receive {:seen, ^intruder, %Message{type: :error}}, 0
    refute_receive {:seen, ^intruder, %Message{type: :method_return}}, 0
  end

  test "last caller cancellation retires deferred unit launch before PID1 connects", ctx do
    assert :ok = Router.route(request(@activated, 131), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)
    monitor = Process.monitor(ctx.client)
    Process.exit(ctx.client, :kill)
    assert_receive {:DOWN, ^monitor, :process, client, :killed}
    assert client == ctx.client

    await(fn ->
      stats().global.activation_messages == 0 and stats().global.ingress_messages == 0
    end)

    manager = peer(":1.2", 0)
    own(manager, @pid1)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
  end

  @tag service_timeout: 100
  test "deferred timeout retires attempts and units before a later PID1 connection", ctx do
    assert :ok = Router.route(request(@activated, 141), ctx.client)

    assert_receive {:seen, client,
                    %Message{reply_serial: 141, error_name: "org.freedesktop.DBus.Error.TimedOut"}},
                   1000

    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 0 end)
    bookkeeping = :sys.get_state(ctx.coordinator).bookkeeping
    assert bookkeeping.attempts == %{}
    assert bookkeeping.units == %{}
    assert MapSet.size(:sys.get_state(ctx.coordinator).launch_notifications) == 0
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    assert :ok = Router.route(request(@other, 142), ctx.client)
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest", body: [@unit]}}, 1000
  end

  test "a shared deferred unit survives the first caller's cancellation", ctx do
    remaining = peer(":1.9", 1000)
    assert :ok = Router.route(request(@activated, 151), ctx.client)
    assert :ok = Router.route(request(@other, 152), remaining)
    await(fn -> stats().global.activation_messages == 2 end)
    monitor = Process.monitor(ctx.client)
    Process.exit(ctx.client, :kill)
    assert_receive {:DOWN, ^monitor, :process, client, :killed}
    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 1 end)
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest", body: [@unit]}}, 1000
    target = peer(":1.3", 1000)
    own(target, @other)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 152}}, 1000
    await(fn -> stats().global.activation_messages == 0 end)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
  end

  test "target ownership before PID1 retires the deferred launch without later replay", ctx do
    assert :ok = Router.route(request(@activated, 161), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)
    target = peer(":1.3", 1000)
    own(target, @activated)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 161}}, 1000
    await(fn -> stats().global.activation_messages == 0 end)
    assert :sys.get_state(ctx.coordinator).bookkeeping.attempts == %{}
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
  end

  test "deferred launch uses current caller policy when PID1 connects", ctx do
    assert :ok = Router.route(request(@activated, 171), ctx.client)
    await(fn -> stats().global.activation_messages == 1 end)

    deny = %{
      selector: :mandatory,
      rules: [
        %{
          effect: :deny,
          attributes: %{"send_interface" => "org.example.Work", "send_member" => "Work"}
        }
      ]
    }

    assert {:ok, _generation} =
             Policy.reload(%{ctx.config | policies: ctx.config.policies ++ [deny]})

    manager = peer(":1.2", 0)
    own(manager, @pid1)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 171,
                      error_name: "org.freedesktop.DBus.Error.AccessDenied"
                    }},
                   1000

    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 0 end)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
  end

  test "recipient XML denial prevents the authority ActivationRequest", ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)

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

    assert :ok = Router.route(request(@activated, 181), ctx.client)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 181,
                      error_name: "org.freedesktop.DBus.Error.AccessDenied"
                    }},
                   1000

    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 0 end)
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
  end

  test "daemon XML receive denial ignores a genuine ActivationFailure without a signal reply",
       ctx do
    manager = peer(":1.2", 0)
    own(manager, @pid1)
    assert :ok = Router.route(request(@activated, 191), ctx.client)
    assert_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 1000

    deny = %{
      selector: :mandatory,
      rules: [
        %{
          effect: :deny,
          attributes: %{
            "receive_interface" => "org.freedesktop.systemd1.Activator",
            "receive_member" => "ActivationFailure"
          }
        }
      ]
    }

    assert {:ok, _generation} =
             Policy.reload(%{ctx.config | policies: ctx.config.policies ++ [deny]})

    failure =
      Message.signal(
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Activator",
        "ActivationFailure",
        serial: 192,
        destination: @bus,
        signature: "sss",
        body: [@unit, "org.example.Failed", "denied failure"]
      )

    assert :ok = Router.route(failure, manager)
    _ = :sys.get_state(Router)
    assert stats().global.activation_messages == 1
    refute_receive {:seen, ^manager, %Message{type: :error}}, 0
    refute_receive {:seen, ^manager, %Message{type: :method_return}}, 0
    target = peer(":1.3", 1000)
    own(target, @activated)
    assert_receive {:seen, ^target, %Message{member: "Work", serial: 191}}, 1000
    await(fn -> stats().global.activation_messages == 0 end)
  end

  test "a replaced systemd owner cannot fail work owned by the current manager", ctx do
    old_manager = peer(":1.2", 0)
    own(old_manager, @pid1, 1)
    assert :ok = Router.route(request(@activated, 201), ctx.client)
    assert_receive {:seen, ^old_manager, %Message{member: "ActivationRequest"}}, 1000
    manager = peer(":1.3", 0)
    own(manager, @pid1, 2)

    failure =
      Message.signal(
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Activator",
        "ActivationFailure",
        serial: 202,
        destination: @bus,
        signature: "sss",
        body: [@unit, "org.example.Failed", "new owner failure"]
      )

    assert :ok = Router.route(failure, old_manager)
    _ = :sys.get_state(Router)
    assert stats().global.activation_messages == 1
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    assert :ok = Router.route(failure, manager)

    assert_receive {:seen, client,
                    %Message{
                      reply_serial: 201,
                      error_name: "org.example.Failed",
                      body: ["new owner failure"]
                    }},
                   1000

    assert client == ctx.client
    await(fn -> stats().global.activation_messages == 0 end)
  end

  defp assert_activation_request(manager) do
    assert_receive {:seen, ^manager,
                    %Message{
                      type: :signal,
                      sender: @bus,
                      destination: @pid1,
                      path: "/org/freedesktop/DBus",
                      interface: "org.freedesktop.systemd1.Activator",
                      member: "ActivationRequest",
                      signature: "s",
                      body: [@unit],
                      fds: []
                    }},
                   1000
  end

  defp await_queue_retirement do
    await(fn ->
      global = stats().global

      Enum.all?(
        ~w(activation_messages activation_bytes activation_fds ingress_messages ingress_bytes ingress_fds egress_messages egress_bytes egress_fds)a,
        &(Map.fetch!(global, &1) == 0)
      )
    end)
  end

  defp assert_activation_retired(coordinator) do
    state = :sys.get_state(coordinator)
    assert state.bookkeeping.attempts == %{}
    assert state.bookkeeping.units == %{}
    assert state.bookkeeping.children == %{}
    assert state.bookkeeping.names == %{}
    assert state.bookkeeping.requests == %{}
    assert state.bookkeeping.serials == %{}
    assert state.messages == %{}
    assert state.timers == %{}
    assert state.launch_notifications == MapSet.new()
    assert state.deferred_systemd == MapSet.new()
    assert :queue.is_empty(state.effects)
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

      {:delivery_barrier, caller, ref} ->
        send(caller, {:delivery_barrier, ref})
        peer_loop(test)
    end
  end

  defp own(target, name, flags \\ 0) do
    assert :ok = Router.route(bus_call("RequestName", 99, [name, flags], "su"), target)
    assert_receive {:seen, ^target, %Message{reply_serial: 99, body: [1]}}, 1000
    _ = :sys.get_state(Router)
    :ok
  end

  defp request(destination, serial, opts \\ []) do
    Message.method_call(
      "/work",
      "org.example.Work",
      "Work",
      [serial: serial, destination: destination] ++ opts
    )
  end

  defp bus_call(member, serial, body, signature, opts \\ []) do
    Message.method_call(
      "/org/freedesktop/DBus",
      Keyword.get(opts, :interface, @bus),
      member,
      [serial: serial, destination: @bus, body: body, signature: signature] ++
        Keyword.delete(opts, :interface)
    )
  end

  defp stats do
    assert {:ok, stats} = Limits.snapshot()
    stats
  end

  defp await(predicate), do: await(predicate, System.monotonic_time(:millisecond) + 1000)

  defp await(predicate, deadline) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(predicate, deadline)
    end
  end
end
