defmodule GaoBus.ActivationRuntimeTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Activation, Config, Limits, NameRegistry, Policy, Router}

  @bus "org.freedesktop.DBus"
  @manager "org.freedesktop.systemd1"
  @service "org.example.TimeoutService"
  @unit "timeout-service.service"
  @moduletag :tmp_dir

  setup ctx do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(ctx.tmp_dir, "services")
    File.mkdir!(directory)

    File.write!(
      Path.join(directory, @service <> ".service"),
      "[D-BUS Service]\nName=#{@service}\nExec=/bin/false\nUser=root\nSystemdService=#{@unit}\n"
    )

    path = Path.join(ctx.tmp_dir, "system.conf")

    File.write!(path, """
    <busconfig><type>system</type><user>root</user>
      <servicedir>#{directory}</servicedir>
      <limit name="service_start_timeout">#{ctx.service_timeout}</limit>
      <policy context="default"><allow user="*"/><allow own="*"/>
        <allow send_destination="*"/><allow receive_sender="*"/>
      </policy>
    </busconfig>
    """)

    accounts = %{
      users: %{"root" => 0, "client" => 1000},
      groups: %{"root" => 0, "client" => 1000},
      memberships: %{0 => [0], 1000 => [1000]},
      user_records: %{
        "root" => %{name: "root", uid: 0, gid: 0, groups: [0], provenance: nil},
        "client" => %{name: "client", uid: 1000, gid: 1000, groups: [1000], provenance: nil}
      }
    }

    assert {:ok, config} = Config.load(path, accounts: accounts)
    timeout = Map.fetch!(config.limits, "service_start_timeout")
    assert timeout == ctx.service_timeout
    start_supervised!(Limits)
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!({Policy, rules: config})
    start_supervised!(GaoBus.Ids)
    start_supervised!({Router, activation: %{mode: :systemd, service_start_timeout: timeout}})

    coordinator =
      start_supervised!({Activation, state_options: [service_start_timeout: timeout]})

    client = peer(":1.1", 1000)
    manager = peer(":1.2", 0)
    own(manager, @manager)
    fence(client)
    fence(manager)
    baseline = stats()
    assert baseline.reservations == 0
    %{client: client, manager: manager, coordinator: coordinator, baseline: baseline}
  end

  @tag service_timeout: 0
  test "zero XML timeout returns TimedOut for automatic activation without launch or credit",
       ctx do
    assert_zero_timeout(ctx, work(101))
  end

  @tag service_timeout: 0
  test "zero XML timeout returns TimedOut for explicit activation without launch or credit",
       ctx do
    assert_zero_timeout(ctx, bus_call("StartServiceByName", 102, [@service, 0], "su"))
  end

  @tag service_timeout: 2500
  test "positive XML timeout issues the actual activation request and completes waiting delivery",
       ctx do
    assert :ok = Router.route(work(103), ctx.client)
    manager = ctx.manager

    assert_receive {:seen, ^manager,
                    %Message{
                      type: :signal,
                      sender: @bus,
                      destination: @manager,
                      path: "/org/freedesktop/DBus",
                      interface: "org.freedesktop.systemd1.Activator",
                      member: "ActivationRequest",
                      signature: "s",
                      body: [@unit],
                      fds: []
                    }},
                   1000

    assert %{activation_messages: 1, ingress_messages: 1} = stats().global
    assert [_] = Map.values(:sys.get_state(ctx.coordinator).bookkeeping.attempts)
    recipient = peer(":1.3", 0)
    own(recipient, @service)

    assert_receive {:seen, ^recipient, %Message{member: "Work", serial: 103, sender: ":1.1"}},
                   1000

    assert :ok =
             Router.route(
               Message.method_return(103, serial: 104, destination: ":1.1"),
               recipient
             )

    client = ctx.client
    assert_receive {:seen, ^client, %Message{type: :method_return, reply_serial: 103}}, 1000
    _ = :sys.get_state(Router)
    fence(recipient)
    fence(client)
    assert stats().reservations == 0
    assert stats().global.activation_messages == 0
    assert stats().global.ingress_messages == 0
    assert stats().global.egress_messages == 0
    assert_retired(ctx.coordinator)
    assert :sys.get_state(Router).pending.entries == %{}
    assert :sys.get_state(Router).activation_claims == %{}
  end

  defp assert_zero_timeout(ctx, message) do
    test = self()
    reference = make_ref()

    # Observe real coordinator admission, including transient attempts that
    # could retire before the final state checks. No backend or authority stub.
    observe = fn count, event, _process ->
      case event do
        {:in, {:"$gen_call", _from, {:admit, _waiter, _message, _definition}}} ->
          send(test, {:activation_admitted, reference})
          count + 1

        _ ->
          count
      end
    end

    assert :ok = :sys.install(ctx.coordinator, {observe, 0})
    assert :ok = Router.route(message, ctx.client)
    serial = message.serial
    client = ctx.client
    assert_receive {:seen, ^client, %Message{type: :error, reply_serial: ^serial} = reply}, 1000
    _ = :sys.get_state(Router)
    assert_retired(ctx.coordinator)
    fence(ctx.manager)
    fence(client)
    refute_receive {:activation_admitted, ^reference}, 0
    manager = ctx.manager
    refute_receive {:seen, ^manager, %Message{member: "ActivationRequest"}}, 0
    assert stats() == ctx.baseline
    assert :sys.get_state(Router).pending.entries == %{}
    assert :sys.get_state(Router).activation_claims == %{}

    assert :ok =
             Router.route(
               Message.method_call("/org/freedesktop/DBus", @bus <> ".Peer", "Ping",
                 serial: serial + 1000,
                 destination: @bus
               ),
               client
             )

    ping_serial = serial + 1000

    assert_receive {:seen, ^client, %Message{type: :method_return, reply_serial: ^ping_serial}},
                   1000

    _ = :sys.get_state(Router)
    fence(client)
    assert stats() == ctx.baseline
    assert reply.error_name == "org.freedesktop.DBus.Error.TimedOut"
  end

  defp assert_retired(coordinator) do
    state = :sys.get_state(coordinator)

    for key <- [:attempts, :names, :requests, :serials, :units, :children] do
      assert Map.fetch!(state.bookkeeping, key) == %{}
    end

    assert state.messages == %{}
    assert state.timers == %{}
    assert state.helpers == %{}
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

      {:fence, reference} ->
        send(test, {:fenced, self(), reference})
        peer_loop(test)
    end
  end

  defp fence(peer) do
    reference = make_ref()
    send(peer, {:fence, reference})
    assert_receive {:fenced, ^peer, ^reference}, 1000
  end

  defp own(peer, name) do
    assert :ok = Router.route(bus_call("RequestName", 99, [name, 0], "su"), peer)
    assert_receive {:seen, ^peer, %Message{reply_serial: 99, body: [1]}}, 1000
    _ = :sys.get_state(Router)
  end

  defp work(serial),
    do:
      Message.method_call("/work", "org.example.Work", "Work",
        serial: serial,
        destination: @service
      )

  defp bus_call(member, serial, body, signature),
    do:
      Message.method_call("/org/freedesktop/DBus", @bus, member,
        serial: serial,
        destination: @bus,
        signature: signature,
        body: body
      )

  defp stats do
    assert {:ok, snapshot} = Limits.snapshot()
    snapshot
  end
end
