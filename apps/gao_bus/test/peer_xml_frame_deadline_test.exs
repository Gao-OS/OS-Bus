defmodule GaoBus.PeerXmlFrameDeadlineTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  setup do
    # The outer headless runner owns this VM; never stop or adopt another bus.
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    {:ok, _} = Application.ensure_all_started(:crypto)
    %{uid: uid, gid: gid} = identity = GaoBus.Unix.Native.identity()
    assert uid in 1..0xFFFFFFFE
    assert gid in 1..0xFFFFFFFE

    assert %{uid: ^uid, gid: ^gid, real_uid: ^uid, real_gid: ^gid} =
             identity

    directory =
      Path.join(System.tmp_dir!(), "gb-xd-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    path = Path.join(directory, "bus")
    config_path = Path.join(directory, "system.conf")

    values = %{
      profile: :system,
      lifecycle: :embedded,
      inherited_listener: false,
      cluster: false,
      socket_path: path,
      config_file: config_path,
      runtime_invocation: %{},
      resource_limits: %{},
      policy_rules: [],
      config_options: [
        accounts: %{
          users: %{"bus" => uid},
          groups: %{"bus" => gid},
          memberships: %{uid => [gid]}
        }
      ]
    }

    previous = Map.new(values, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    Enum.each(values, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
        {key, :error} -> Application.delete_env(:gao_bus, key)
      end)
    end)

    File.write!(config_path, """
    <busconfig><type>system</type><user>#{uid}</user><auth>EXTERNAL</auth>
      <limit name="max_completed_connections">4</limit>
      <limit name="max_incomplete_connections">2</limit>
      <limit name="max_connections_per_user">4</limit>
      <limit name="max_names_per_connection">4</limit>
      <limit name="max_match_rules_per_connection">1</limit>
      <limit name="max_replies_per_connection">8</limit>
      <limit name="reply_timeout">3000</limit>
      <limit name="auth_timeout">10000</limit>
      <limit name="pending_fd_timeout">5000</limit>
      <limit name="max_message_size">4096</limit>
      <limit name="max_message_unix_fds">1</limit>
      <limit name="max_incoming_bytes">16384</limit>
      <limit name="max_outgoing_bytes">16384</limit>
      <limit name="max_incoming_unix_fds">1</limit>
      <limit name="max_outgoing_unix_fds">1</limit>
      <policy context="default"><deny user="*"/><allow user="#{uid}"/></policy>
      <policy user="#{uid}">
        <allow own="org.foundation.XmlDeadlineObserver"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="Hello" send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="GetId" send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="RequestName" send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="GetNameOwner" send_type="method_call"/>
        <allow receive_sender="org.freedesktop.DBus" receive_type="method_return"/>
        <allow receive_sender="org.freedesktop.DBus" receive_interface="org.freedesktop.DBus" receive_member="NameAcquired" receive_type="signal"/>
      </policy>
    </busconfig>
    """)

    core = start_supervised!(%{id: :xml_core, start: {GaoBus.Application, :start, [:normal, []]}})
    assert %{type: :other, uid: ^uid} = File.stat!(path)
    File.chmod!(path, 0o600)
    listener = Process.whereis(GaoBus.Listener)
    listener_options = :sys.get_state(listener, 1500).peer_options

    %{
      path: path,
      identity: %{uid: uid, gid: gid},
      core: core,
      listener: listener,
      listener_options: listener_options
    }
  end

  @tag timeout: 60_000
  test "PRO-04 compiled XML incomplete call expires without renewing its deadline", ctx do
    %{uid: uid, gid: gid} = ctx.identity

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_xml_frame_deadline_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: ["-B", actor, ctx.path, Integer.to_string(uid), Integer.to_string(gid)]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)

    assert %{
             "event" => "ready",
             "observer" => observer_name,
             "owned" => "org.foundation.XmlDeadlineObserver" = owned,
             "actor_pid" => actor_pid,
             "uid" => ^uid,
             "gid" => ^gid,
             "auth" => auth_hex,
             "ok" => ok_hex,
             "hello" => hello_hex,
             "get_id" => get_id_hex,
             "bus_id" => bus_id
           } = ready = actor_reply(port)

    assert Base.decode16!(auth_hex, case: :lower) == external_auth(uid)
    assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
    hello = Base.decode16!(hello_hex, case: :lower)
    get_id = Base.decode16!(get_id_hex, case: :lower)
    assert digest(hello) == "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31"
    assert digest(get_id) == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"
    assert {:ok, observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> registered?(observer, observer_name, actor_pid, ctx.identity) and quiet?() end)
    before = authority(observer)
    evidence("XML_DEADLINE_INPUT", ready)

    Port.command(port, "open\n")

    assert %{"event" => "opened", "source" => source_name, "auth" => ^auth_hex, "ok" => ^ok_hex} =
             opened = actor_reply(port)

    setup_writes = [auth_hex, Base.encode16("BEGIN\r\n" <> hello <> get_id, case: :lower)]
    assert opened["writes"] == setup_writes
    await(fn -> length(children()) == 2 end)
    assert [source] = children() -- [observer]
    assert {:ok, ^source} = resolve(source_name)
    source_monitor = Process.monitor(source)
    await(fn -> registered?(source, source_name, actor_pid, ctx.identity) and quiet?() end)
    connected = authority(observer)

    started_at = System.monotonic_time(:millisecond)
    Port.command(port, "first-byte\n")

    assert %{"event" => "partial", "prefix" => "6c", "target" => target_hex} =
             partial = actor_reply(port)

    target = Base.decode16!(target_hex, case: :lower)

    assert target ==
             binary_part(get_id, 0, 8) <>
               <<3::little-32>> <>
               binary_part(get_id, 12, byte_size(get_id) - 12)

    assert partial["writes"] == setup_writes ++ ["6c"]
    await(fn -> retained?(source, <<?l>>, uid) end)
    initial = peer_state(source)
    evidence("XML_DEADLINE_FIRST_BYTE", deadline_evidence(source, initial))

    # Frozen Runtime reaches this native assertion with the actual byte retained.
    assert {timer, token} = initial.frame_timer
    assert is_reference(timer) and is_reference(token)
    assert is_integer(initial.frame_deadline)
    assert initial.frame_deadline >= started_at + 5000
    assert initial.frame_deadline <= System.monotonic_time(:millisecond) + 5000
    assert remaining = Process.read_timer(timer)
    assert remaining in 1..5000
    assert initial.frame_timeout_ms == 5000
    assert ctx.listener_options[:frame_timeout_ms] == 5000
    assert peer_state(observer).frame_timeout_ms == 5000

    admission = %{
      "auth_timeout" => 10000,
      "max_completed_connections" => 4,
      "max_connections_per_user" => 4,
      "max_incomplete_connections" => 2
    }

    xml = ctx.listener_options[:xml_limits]
    assert Map.take(xml, Map.keys(admission)) == admission
    assert initial.xml_limits == admission
    observer_state = peer_state(observer)
    assert observer_state.xml_limits == admission

    frame_options = %{
      max_bytes: 4096,
      max_fds: 1,
      pending_fd_timeout: 5000,
      max_output_bytes: 134_217_728
    }

    assert initial.frame_options == frame_options
    assert observer_state.frame_options == frame_options
    assert xml["max_message_size"] == frame_options.max_bytes
    assert xml["max_message_unix_fds"] == frame_options.max_fds
    assert xml["pending_fd_timeout"] == frame_options.pending_fd_timeout
    await(fn -> authority(observer) == with_frame_bytes(connected, source, 1, uid) end)

    Port.command(port, "grow\n")
    assert %{"event" => "grown", "prefix" => prefix_hex} = grown = actor_reply(port)
    prefix = binary_part(target, 0, 16)
    assert Base.decode16!(prefix_hex, case: :lower) == prefix

    assert grown["writes"] ==
             partial["writes"] ++ [Base.encode16(binary_part(target, 1, 15), case: :lower)]

    await(fn -> retained?(source, prefix, uid) end)
    grown_state = peer_state(source)
    assert grown_state.frame_timer == {timer, token}
    assert grown_state.frame_deadline == initial.frame_deadline
    assert grown_state.frame_timeout_ms == 5000
    assert Process.read_timer(timer) in 1..remaining
    await(fn -> authority(observer) == with_frame_bytes(connected, source, 16, uid) end)
    evidence("XML_DEADLINE_GROWN", deadline_evidence(source, grown_state))

    Port.command(port, "held\n")

    assert %{
             "event" => "held",
             "source" => ^source_name,
             "prefix" => ^prefix_hex,
             "buffered_hex" => "",
             "socket_pending" => false
           } = held = actor_reply(port)

    evidence("XML_DEADLINE_HELD", held)
    assert retained?(source, prefix, uid)
    assert peer_state(source).frame_timer == {timer, token}
    assert peer_state(source).frame_deadline == initial.frame_deadline
    await(fn -> authority(observer) == with_frame_bytes(connected, source, 16, uid) end)
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0
    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0

    # No expiry injection or client close: allow the unchanged timer to fire.
    down_bound = started_at + 6500 - System.monotonic_time(:millisecond)
    assert down_bound > 0
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, down_bound
    elapsed = System.monotonic_time(:millisecond) - started_at
    assert elapsed in 5000..6500
    Port.command(port, "observe-close\n")

    assert %{"event" => "closed", "disposition" => "automatic-eof", "terminal_hex" => ""} =
             closed = actor_reply(port)

    evidence("XML_DEADLINE_CLOSED", closed)
    await(fn -> authority(observer) == before end)
    assert {:error, :name_not_found} = resolve(source_name)
    assert {:ok, ^observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(owned)

    Port.command(port, "settled\n")

    assert %{
             "event" => "settled",
             "observer" => ^observer_name,
             "owned" => ^owned,
             "bus_id" => ^bus_id
           } = settled = actor_reply(port)

    evidence("XML_DEADLINE_SETTLED", settled)
    await(fn -> authority(observer) == before end)
    assert Process.whereis(GaoBus.Supervisor) == ctx.core
    assert Process.whereis(GaoBus.Listener) == ctx.listener
    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "observer" => ^observer_name,
             "owned" => ^owned,
             "bus_id" => ^bus_id
           } = result = actor_reply(port)

    assert_receive {^port, {:exit_status, 0}}, 3000
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500

    await(fn ->
      {:ok, accounting} = snapshot()

      children() == [] and :sys.get_state(Router, 1500).peers == %{} and
        names() == ["org.freedesktop.DBus"] and accounting.peers == %{} and
        accounting.global.connections == 0 and quiet?()
    end)

    core_monitor = Process.monitor(ctx.core)
    listener_monitor = Process.monitor(ctx.listener)
    assert :ok = stop_supervised(:xml_core)
    assert_receive {:DOWN, ^core_monitor, :process, _, :shutdown}, 1500
    assert_receive {:DOWN, ^listener_monitor, :process, _, :shutdown}, 1500
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    refute File.exists?(ctx.path)

    evidence(
      "XML_DEADLINE_SUMMARY",
      Map.merge(result, %{
        "elapsed_ms" => elapsed,
        "started_at" => started_at,
        "frame_deadline" => initial.frame_deadline
      })
    )
  end

  defp external_auth(uid),
    do: <<0>> <> "AUTH EXTERNAL " <> Base.encode16(Integer.to_string(uid), case: :lower) <> "\r\n"

  defp registered?(peer, name, actor_pid, %{uid: uid, gid: gid}) do
    state = peer_state(peer)

    state.state == :connected and state.unique_name == name and state.auth.phase == :connected and
      state.credentials == Map.put(state.auth.credentials, :unique_name, name) and
      match?(%{uid: ^uid, gid: ^gid, pid: ^actor_pid}, state.auth.credentials) and
      state.auth.buffer == <<>> and
      state.auth.total_bytes == byte_size(external_auth(uid)) + byte_size("BEGIN\r\n") and
      state.buffer == <<>> and state.incoming_fds == [] and not state.auth.unix_fd_negotiated and
      state.frame_timer == nil and state.frame_deadline == nil and state.route_wait == nil and
      state.registration_timer == nil and
      state.pending_fd_timer == nil and state.pending_fd_deadline == nil and
      state.current_output == nil and state.output_queue == {[], []}
  end

  defp retained?(peer, prefix, uid) do
    state = peer_state(peer)
    {:ok, accounting} = snapshot()

    state.state == :connected and state.buffer == prefix and state.incoming_fds == [] and
      not state.auth.unix_fd_negotiated and state.pending_fd_timer == nil and
      state.pending_fd_deadline == nil and state.route_wait == nil and
      state.current_output == nil and state.output_queue == {[], []} and
      accounting.peers[peer].frame_bytes == byte_size(prefix) and
      accounting.peers[peer].frame_fds == 0 and accounting.uids[uid].frame_fds == 0 and
      accounting.global.frame_fds == 0
  end

  # Do not retain or print socket/native resource handles.
  defp peer_state(peer), do: Map.drop(:sys.get_state(peer, 1500), [:socket, :native_socket])

  defp deadline_evidence(peer, state) do
    {:ok, accounting} = snapshot()
    {timer, token} = state.frame_timer || {nil, nil}

    %{
      peer: inspect(peer),
      credentials: state.credentials,
      buffer: Base.encode16(state.buffer, case: :lower),
      frame_timer: inspect(timer),
      frame_token: inspect(token),
      frame_deadline: state.frame_deadline,
      frame_timeout_ms: state.frame_timeout_ms,
      observed_at: System.monotonic_time(:millisecond),
      remaining_ms: if(timer, do: Process.read_timer(timer)),
      incoming_fds: state.incoming_fds,
      frame_bytes: accounting.peers[peer].frame_bytes,
      frame_fds: accounting.peers[peer].frame_fds
    }
  end

  defp authority(observer) do
    registry = :sys.get_state(NameRegistry, 1500)
    {:ok, accounting} = snapshot()

    %{
      core:
        Enum.map(
          [
            GaoBus.Supervisor,
            GaoBus.Ids,
            GaoBus.PeerRegistry,
            Router,
            NameRegistry,
            Limits,
            GaoBus.Policy,
            GaoBus.MatchRules,
            GaoBus.Policy.Capability,
            GaoBus.Activation.HelperSupervisor,
            GaoBus.Activation,
            PeerSupervisor,
            GaoBus.Listener
          ],
          &Process.whereis/1
        ),
      router: Map.delete(:sys.get_state(Router, 1500), :next_serial),
      registry: registry,
      names: Enum.sort(:ets.tab2list(registry.names)),
      uniques: Enum.sort(:ets.tab2list(registry.uniques)),
      reverse_names: Enum.sort(:ets.tab2list(registry.pid_names)),
      matches: :sys.get_state(GaoBus.MatchRules, 1500),
      match_entries: Enum.sort(:ets.tab2list(:gao_bus_match_rules)),
      capabilities: Enum.sort(:ets.tab2list(:gao_bus_capabilities)),
      policy: GaoBus.Policy.snapshot(),
      observer:
        Map.take(peer_state(observer), [
          :unique_name,
          :credentials,
          :auth,
          :state,
          :buffer,
          :incoming_fds,
          :frame_timer,
          :frame_deadline,
          :frame_options,
          :frame_timeout_ms,
          :pending_fd_timer,
          :pending_fd_deadline,
          :registration_timer,
          :xml_limits,
          :route_wait,
          :current_output,
          :output_queue
        ]),
      accounting: accounting
    }
  end

  defp with_frame_bytes(state, source, bytes, uid) do
    accounting =
      state.accounting
      |> update_in([:global, :frame_bytes], &(&1 + bytes))
      |> update_in([:uids, uid, :frame_bytes], &(&1 + bytes))
      |> update_in([:peers, source, :frame_bytes], &(&1 + bytes))

    %{state | accounting: accounting}
  end

  defp children, do: Enum.map(GenServer.call(PeerSupervisor, :which_children, 1500), &elem(&1, 1))
  defp snapshot, do: GenServer.call(Limits, :snapshot, 1500)
  defp names, do: GenServer.call(NameRegistry, :list_names, 1500)
  defp resolve(name), do: GenServer.call(NameRegistry, {:resolve, name}, 1500)
  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp quiet? do
    {:ok, accounting} = snapshot()

    accounting.reservations == 0 and accounting.global.frame_bytes == 0 and
      accounting.global.frame_fds == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "XML frame deadline state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
