defmodule GaoBus.PeerUnknownHeaderTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-unknown-header-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)

    rules = [
      %{action: :connect, effect: :allow, match: %{uid: uid}},
      %{action: :own, effect: :deny, match: %{}},
      %{action: :send, effect: :allow, match: %{uid: uid, destination: "org.freedesktop.DBus"}},
      %{action: :receive, effect: :allow, match: %{uid: uid, sender: "org.freedesktop.DBus"}}
    ]

    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(Limits)
    start_supervised!({GaoBus.Policy, rules: rules})
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!(Router)
    start_supervised!({PeerSupervisor, max_children: 8})
    path = Path.join(directory, "bus")

    start_supervised!(
      {GaoBus.Listener, socket_path: path, socket_mode: 0o600, peer_options: [auth_limits: []]}
    )

    %{path: path}
  end

  @tag timeout: 60_000
  test "a valid unknown string header preserves GetId and registered peer health", ctx do
    baseline = authority()

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_unknown_header_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        args: ["-S", "-B", actor, ctx.path]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)

    assert %{
             "event" => "ready",
             "observer" => observer_name,
             "bus_id" => bus_id,
             "identity" => %{"pid" => actor_pid, "uid" => uid, "gid" => gid},
             "frame" => frame
           } = ready = actor_reply(port)

    native_identity = GaoBus.Unix.Native.identity()
    assert uid == native_identity.uid and gid == native_identity.gid
    assert {:ok, observer} = NameRegistry.resolve(observer_name)
    observer_monitor = Process.monitor(observer)
    await(fn -> clean_peer?(observer) and quiet?() end)
    observer_authority = authority()
    Port.command(port, "open\n")

    assert %{
             "event" => "opened",
             "source" => source_name,
             "connection" => %{"pid" => ^actor_pid},
             "peer_credentials" => credentials
           } = opened = actor_reply(port)

    assert credentials == [String.to_integer(System.pid()), uid, gid]
    assert source_name != observer_name
    assert {:ok, source} = NameRegistry.resolve(source_name)
    source_monitor = Process.monitor(source)
    await(fn -> clean_peer?(source) and quiet?() end)
    Port.command(port, "send\n")

    assert %{
             "event" => "completed",
             "source" => ^source_name,
             "observer" => ^observer_name,
             "bus_id" => ^bus_id,
             "frame" => ^frame,
             "writes" => [^frame, follow_up],
             "reply_serials" => [3, 4],
             "receipts" => [extension_reply, follow_up_reply],
             "received_fds" => 0,
             "buffered_hex" => "",
             "socket_pending" => false
           } = completed = actor_reply(port)

    refute follow_up == frame
    check_reply(extension_reply, 3, source_name, bus_id)
    check_reply(follow_up_reply, 4, source_name, bus_id)
    assert {:ok, ^source} = NameRegistry.resolve(source_name)
    assert {:ok, ^observer} = NameRegistry.resolve(observer_name)
    await(fn -> clean_peer?(source) and clean_peer?(observer) and quiet?() end)
    evidence("UNKNOWN_HEADER_CASE", %{input: ready, registration: opened, observation: completed})
    Port.command(port, "close\n")

    assert %{"event" => "closed", "source" => ^source_name} = closed = actor_reply(port)
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 3000
    await(fn -> authority() == observer_authority and children() == [observer] end)
    evidence("UNKNOWN_HEADER_CLOSED", Map.put(closed, "authority_restored", true))
    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "observer" => ^observer_name,
             "bus_id" => ^bus_id
           } = result = actor_reply(port)

    assert_receive {^port, {:exit_status, 0}}, 3000
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 3000
    await(fn -> authority() == baseline and children() == [] end)
    :ok = stop_supervised(GaoBus.Listener)
    refute File.exists?(ctx.path)

    evidence(
      "UNKNOWN_HEADER_SUMMARY",
      Map.merge(result, %{
        "authority_restored" => true,
        "accounting_restored" => true,
        "socket_removed" => true
      })
    )
  end

  defp check_reply(row, serial, destination, body) do
    assert %{
             "type" => 2,
             "fields" => %{
               "5" => ^serial,
               "6" => ^destination,
               "7" => "org.freedesktop.DBus",
               "8" => "s"
             },
             "body" => ^body
           } = row
  end

  defp clean_peer?(peer) do
    state = :sys.get_state(peer, 3000)

    state.state == :connected and state.buffer == <<>> and state.auth.buffer == <<>> and
      not state.auth.unix_fd_negotiated and state.incoming_fds == [] and state.route_wait == nil
  end

  defp children, do: Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))

  defp authority do
    {:ok, accounting} = Limits.snapshot()

    %{
      core: Enum.map([Router, NameRegistry, Limits, GaoBus.Policy], &Process.whereis/1),
      peers: :sys.get_state(Router, 3000).peers,
      names: Enum.sort(NameRegistry.list_names()),
      accounting: accounting
    }
  end

  defp quiet? do
    {:ok, accounting} = Limits.snapshot()

    accounting.reservations == 0 and
      Enum.all?(accounting.global, fn {metric, value} ->
        metric in [:connections, :authenticating] or value == 0
      end)
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 3000) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "unknown-header state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
