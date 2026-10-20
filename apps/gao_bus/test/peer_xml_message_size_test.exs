defmodule GaoBus.PeerXmlMessageSizeTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @owned "org.foundation.XmlMessageSizeObserver"

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
      Path.join(System.tmp_dir!(), "gb-xs-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    assert %{uid: ^uid, gid: ^gid, type: :directory, mode: directory_mode} = File.stat!(directory)
    assert Bitwise.band(directory_mode, 0o7777) == 0o700
    path = Path.join(directory, "bus")
    assert byte_size(path) < 108
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
        <allow own="org.foundation.XmlMessageSizeObserver"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="Hello" send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="GetId" send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="RequestName" send_type="method_call"/>
        <allow send_destination="org.freedesktop.DBus" send_interface="org.freedesktop.DBus" send_member="GetNameOwner" send_type="method_call"/>
        <allow receive_sender="org.freedesktop.DBus" receive_type="method_return"/>
        <allow receive_sender="org.freedesktop.DBus" receive_type="error"/>
        <allow receive_sender="org.freedesktop.DBus" receive_interface="org.freedesktop.DBus" receive_member="NameAcquired" receive_type="signal"/>
      </policy>
    </busconfig>
    """)

    options = Keyword.put(values.config_options, :daemon_uid, uid)
    assert {:ok, config} = GaoBus.Config.load(config_path, options)
    assert config.settings == %{type: :system, user: uid, auth: ["EXTERNAL"]}
    assert config.daemon_uid == uid

    assert {:ok, plan} =
             GaoBus.Config.Runtime.compile(
               config,
               %{profile: :system, socket_path: path, safety_limits: %{}},
               identity
             )

    assert plan.configuration == config
    assert plan.profile == :system

    assert plan.xml_limits == %{
             "max_completed_connections" => 4,
             "max_incomplete_connections" => 2,
             "max_connections_per_user" => 4,
             "max_names_per_connection" => 4,
             "max_match_rules_per_connection" => 1,
             "max_replies_per_connection" => 8,
             "reply_timeout" => 3000,
             "auth_timeout" => 10000,
             "pending_fd_timeout" => 5000,
             "max_message_size" => 4096,
             "max_message_unix_fds" => 1,
             "max_incoming_bytes" => 16384,
             "max_outgoing_bytes" => 16384,
             "max_incoming_unix_fds" => 1,
             "max_outgoing_unix_fds" => 1,
             "service_start_timeout" => 25000,
             "max_pending_service_starts" => 512
           }

    assert plan.peer_options == [xml_limits: plan.xml_limits, frame_timeout_ms: 5000]
    assert plan.listener_options == [socket_path: path, peer_options: plan.peer_options]
    assert plan.router_options[:max_output_bytes] == 134_217_728

    # Application independently loads and compiles the file; no plan is forwarded.
    core = start_supervised!(%{id: :xml_core, start: {GaoBus.Application, :start, [:normal, []]}})
    assert %{type: :other, uid: ^uid, gid: ^gid} = File.stat!(path)
    File.chmod!(path, 0o600)
    assert Bitwise.band(File.stat!(path).mode, 0o7777) == 0o600
    listener = Process.whereis(GaoBus.Listener)
    listener_options = :sys.get_state(listener, 1500).peer_options
    assert listener_options == plan.peer_options
    {:ok, empty_accounting} = snapshot()
    empty_authority = authority(nil)
    # Ordinary requests initialize Router's policy cache before the final comparison.
    empty_authority =
      put_in(empty_authority, [:router, :policy_snapshot], GaoBus.Policy.snapshot())

    %{
      path: path,
      identity: %{uid: uid, gid: gid},
      core: core,
      listener: listener,
      listener_options: listener_options,
      empty_accounting: empty_accounting,
      empty_authority: empty_authority
    }
  end

  @tag timeout: 60_000
  test "PRO-04 compiled XML admits 4096 bytes and rejects a prefix advertising 4097", ctx do
    %{uid: uid, gid: gid} = ctx.identity
    body4096 = wire_string(:binary.copy("x", 3955))
    body4097 = wire_string(:binary.copy("x", 3956))
    packet4096 = frame("GetId", 3, body4096, "s")
    packet4097 = frame("GetId", 6, body4097, "s")
    prefix4097 = binary_part(packet4097, 0, 16)
    assert byte_size(packet4096) == 4096
    assert byte_size(packet4097) == 4097
    assert prefix4097 == <<?l, 1, 0, 1, 3961::little-32, 6::little-32, 119::little-32>>
    frame_hex = hex(packet4096)
    prefix_hex = hex(prefix4097)

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_xml_message_size_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: ["-B", actor, ctx.path, Integer.to_string(uid), Integer.to_string(gid)]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)
    assert {:os_pid, actor_pid} = Port.info(port, :os_pid)

    assert %{
             "event" => "ready",
             "observer" => observer_name,
             "owned" => @owned,
             "actor_pid" => ^actor_pid,
             "uid" => ^uid,
             "gid" => ^gid,
             "auth" => auth_hex,
             "ok" => ok_hex,
             "hello" => hello_hex,
             "get_id" => get_id_hex,
             "bus_id" => bus_id,
             "frame4096" => ^frame_hex,
             "prefix4097" => ^prefix_hex,
             "frame_lengths" => [4096, 4097],
             "pending_fds" => 0
           } = ready = actor_reply(port)

    assert Base.decode16!(auth_hex, case: :lower) == external_auth(uid)
    assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
    hello = Base.decode16!(hello_hex, case: :lower)
    get_id = Base.decode16!(get_id_hex, case: :lower)
    assert digest(hello) == "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31"
    assert digest(get_id) == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"
    assert {:ok, observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> registered?(observer, observer_name, actor_pid, ctx.identity) and quiet?() end)
    before = authority(observer)
    assert_projection(observer, ctx.listener_options)
    evidence("XML_MESSAGE_SIZE_INPUT", ready)

    Port.command(port, "open\n")

    assert %{
             "event" => "opened",
             "source" => source_name,
             "auth" => ^auth_hex,
             "ok" => ^ok_hex,
             "pending_fds" => 0
           } =
             opened = actor_reply(port)

    setup_writes = [auth_hex, Base.encode16("BEGIN\r\n" <> hello <> get_id, case: :lower)]
    assert opened["writes"] == setup_writes
    assert source_name != observer_name
    await(fn -> length(children()) == 2 end)
    assert [source] = children() -- [observer]
    assert {:ok, ^source} = resolve(source_name)
    source_monitor = Process.monitor(source)
    await(fn -> registered?(source, source_name, actor_pid, ctx.identity) and quiet?() end)
    assert_projection(source, ctx.listener_options)
    connected = authority(observer)
    source_before = peer_authority(source)

    Port.command(port, "size4096\n")

    assert %{
             "event" => "size4096",
             "source" => ^source_name,
             "error" => error,
             "source_health" => source_health,
             "observer_health" => first_health,
             "observer_health_ms" => first_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = accepted = actor_reply(port)

    assert_invalid_args(error, source_name)
    assert_health(source_health, source_name, bus_id, 4)
    assert_health(first_health, observer_name, bus_id, 10)
    assert first_ms >= 0 and first_ms <= 1000

    source_probe = [
      frame("GetNameOwner", 4, wire_string(source_name), "s"),
      frame("GetId", 5, <<>>, "")
    ]

    assert accepted["writes"] == setup_writes ++ [frame_hex] ++ Enum.map(source_probe, &hex/1)
    await(fn -> authority(observer) == connected and peer_authority(source) == source_before end)
    assert registered?(source, source_name, actor_pid, ctx.identity)
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0
    refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0

    Port.command(port, "size4097\n")

    assert %{
             "event" => "sent4097",
             "source" => ^source_name,
             "prefix" => ^prefix_hex,
             "sent_bytes" => 16,
             "advertised_bytes" => 4097,
             "pending_fds" => 0
           } = sent = actor_reply(port)

    assert sent["writes"] == accepted["writes"] ++ [prefix_hex]
    # No advertised body, client read/close, or injected expiry before actual normal DOWN.
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
    Port.command(port, "observe-close\n")

    assert %{
             "event" => "closed",
             "disposition" => "automatic-eof",
             "terminal_hex" => "",
             "source_socket_open" => true,
             "pending_fds" => 0
           } =
             closed = actor_reply(port)

    await(fn -> authority(observer) == before end)
    assert {:error, :name_not_found} = resolve(source_name)
    assert {:ok, ^observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(@owned)

    Port.command(port, "settled\n")

    assert %{
             "event" => "settled",
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "health" => final_health,
             "observer_health_ms" => final_ms,
             "buffered_hex" => "",
             "socket_pending" => false,
             "pending_fds" => 0
           } = settled = actor_reply(port)

    assert_health(final_health, observer_name, bus_id, 12)
    assert final_ms >= 0 and final_ms <= 1000
    await(fn -> authority(observer) == before end)
    refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0
    assert Process.whereis(GaoBus.Supervisor) == ctx.core
    assert Process.whereis(GaoBus.Listener) == ctx.listener

    evidence("XML_MESSAGE_SIZE_CASE", %{
      accepted: accepted,
      sent: sent,
      closed: closed,
      settled: settled,
      source_down: "normal",
      source_down_bound_ms: 1500,
      authority_unchanged_after4096: true,
      authority_restored_after4097: true
    })

    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "observer" => ^observer_name,
             "owned" => @owned,
             "bus_id" => ^bus_id,
             "boundaries" => [4096, 4097],
             "frame4096" => ^frame_hex,
             "prefix4097" => ^prefix_hex,
             "error" => ^error,
             "source_health" => ^source_health,
             "observer_health" => [^first_health, ^final_health],
             "observer_health_ms" => [^first_ms, ^final_ms],
             "disposition" => "automatic-eof",
             "pending_fds" => 0
           } = result = actor_reply(port)

    assert_receive {^port, {:exit_status, 0}}, 3000
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500

    await(fn ->
      {:ok, accounting} = snapshot()

      children() == [] and :sys.get_state(Router, 1500).peers == %{} and
        names() == ["org.freedesktop.DBus"] and accounting == ctx.empty_accounting and
        authority(nil) == ctx.empty_authority
    end)

    assert {:error, :name_not_found} = resolve(observer_name)
    assert {:error, :name_not_found} = resolve(@owned)

    core_monitor = Process.monitor(ctx.core)
    listener_monitor = Process.monitor(ctx.listener)
    assert :ok = stop_supervised(:xml_core)
    assert_receive {:DOWN, ^core_monitor, :process, _, :shutdown}, 1500
    assert_receive {:DOWN, ^listener_monitor, :process, _, :shutdown}, 1500
    assert Process.whereis(GaoBus.Supervisor) == nil
    assert Process.whereis(GaoBus.Listener) == nil
    refute File.exists?(ctx.path)

    evidence("XML_MESSAGE_SIZE_SUMMARY", result)
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

  defp assert_projection(peer, options) do
    state = peer_state(peer)

    admission = %{
      "auth_timeout" => 10000,
      "max_completed_connections" => 4,
      "max_connections_per_user" => 4,
      "max_incomplete_connections" => 2
    }

    assert Map.take(options[:xml_limits], Map.keys(admission)) == admission
    assert state.xml_limits == admission
    assert state.frame_timeout_ms == options[:frame_timeout_ms]
    assert state.frame_timeout_ms == 5000

    assert state.frame_options == %{
             max_bytes: 4096,
             max_fds: 1,
             pending_fd_timeout: 5000,
             max_output_bytes: 134_217_728
           }

    assert options[:xml_limits]["max_message_size"] == state.frame_options.max_bytes
    assert options[:xml_limits]["max_message_unix_fds"] == state.frame_options.max_fds
    assert options[:xml_limits]["pending_fd_timeout"] == state.frame_options.pending_fd_timeout
  end

  # Do not retain or print socket/native resource handles.
  defp peer_state(peer), do: Map.drop(:sys.get_state(peer, 1500), [:socket, :native_socket])

  defp peer_authority(nil), do: nil

  defp peer_authority(peer) do
    Map.take(peer_state(peer), [
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
    ])
  end

  # Independent complete D-Bus fixed/header/body construction, without ExDBus encoding.
  defp frame(member, serial, body, signature) do
    fields = [
      {1, "o", wire_string("/org/freedesktop/DBus")},
      {2, "s", wire_string("org.freedesktop.DBus")},
      {3, "s", wire_string(member)},
      {6, "s", wire_string("org.freedesktop.DBus")},
      {8, "g", <<byte_size(signature)>> <> signature <> <<0>>}
    ]

    header =
      Enum.reduce(fields, <<>>, fn {code, type, value}, acc ->
        pad(acc, 8) <> <<code, 1>> <> type <> <<0>> <> value
      end)

    <<?l, 1, 0, 1, byte_size(body)::little-32, serial::little-32, byte_size(header)::little-32>> <>
      pad(header, 8) <> body
  end

  defp wire_string(value), do: <<byte_size(value)::little-32>> <> value <> <<0>>

  defp pad(bytes, alignment),
    do: bytes <> :binary.copy(<<0>>, rem(alignment - rem(byte_size(bytes), alignment), alignment))

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  defp assert_invalid_args(row, name) do
    assert row["type"] == 3

    assert row["fields"] == %{
             "4" => "org.freedesktop.DBus.Error.InvalidArgs",
             "5" => 3,
             "6" => name,
             "7" => "org.freedesktop.DBus",
             "8" => "s"
           }

    assert row["body"] == hex(wire_string("Arguments do not match the bus method signature"))
  end

  defp assert_health(rows, name, bus_id, serial) do
    assert [owner, id] = rows

    for {row, reply_serial, body} <- [
          {owner, serial, hex(wire_string(name))},
          {id, serial + 1, bus_id}
        ] do
      assert row["type"] == 2

      assert row["fields"] == %{
               "5" => reply_serial,
               "6" => name,
               "7" => "org.freedesktop.DBus",
               "8" => "s"
             }

      assert row["body"] == body
    end
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
      observer: peer_authority(observer),
      accounting: accounting
    }
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
    ready? = predicate.()
    assert System.monotonic_time(:millisecond) < deadline, "XML message-size state deadline"

    unless ready? do
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
