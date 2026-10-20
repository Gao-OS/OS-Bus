defmodule GaoBus.PeerBodySignatureTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @owned "org.foundation.BodySignatureObserver"
  @target "org.foundation.BodySignatureTarget"

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    assert %{uid: uid, gid: gid, real_uid: uid, real_gid: gid} = GaoBus.Unix.Native.identity()
    assert uid in 1..0xFFFFFFFE
    assert gid in 1..0xFFFFFFFE

    directory =
      Path.join(System.tmp_dir!(), "gb-bs-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    assert %{uid: ^uid, gid: ^gid, type: :directory, mode: directory_mode} = File.stat!(directory)
    assert Bitwise.band(directory_mode, 0o7777) == 0o700

    rules =
      Enum.map(
        [:connect, :own, :send, :receive],
        &%{action: &1, effect: :allow, match: %{uid: uid}}
      )

    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(Limits)
    start_supervised!({GaoBus.Policy, rules: rules})
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!(Router)
    start_supervised!({PeerSupervisor, max_children: 8})
    {:ok, empty_accounting} = snapshot()
    path = Path.join(directory, "bus")
    assert byte_size(path) < 108
    start_supervised!({GaoBus.Listener, socket_path: path, socket_mode: 0o600})
    assert %{uid: ^uid, gid: ^gid, mode: socket_mode} = File.stat!(path)
    assert Bitwise.band(socket_mode, 0o7777) == 0o600
    %{path: path, identity: %{uid: uid, gid: gid}, empty_accounting: empty_accounting}
  end

  for family <- [:absent, :empty] do
    @tag timeout: 60_000
    test "PRO-04 nonempty RequestName body with #{family} header8 closes only its source", ctx do
      family = unquote(family)
      case_name = Atom.to_string(family)
      %{uid: uid, gid: gid} = ctx.identity
      body = pad(wire_string(@target), 4) <> <<0::little-32>>
      packet = frame("RequestName", 3, body, family)
      frame_hex = Base.encode16(packet, case: :lower)
      body_hex = Base.encode16(body, case: :lower)

      expected_error =
        if family == :absent, do: :missing_body_signature, else: :trailing_body_bytes

      assert {:error, ^expected_error} = ExDBus.Message.decode_message(packet)

      python =
        System.find_executable("python3") || flunk("required independent Python actor missing")

      actor = Path.expand("fixtures/peer_body_signature_actor.py", __DIR__)

      port =
        Port.open({:spawn_executable, python}, [
          :binary,
          :exit_status,
          {:line, 16_384},
          args: ["-B", actor, ctx.path, case_name, Integer.to_string(uid), Integer.to_string(gid)]
        ])

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)
      assert {:os_pid, actor_pid} = Port.info(port, :os_pid)

      assert %{
               "event" => "ready",
               "case" => ^case_name,
               "observer" => observer_name,
               "owned" => @owned,
               "target" => @target,
               "actor_pid" => ^actor_pid,
               "uid" => ^uid,
               "gid" => ^gid,
               "auth" => auth_hex,
               "ok" => ok_hex,
               "hello" => hello_hex,
               "get_id" => get_id_hex,
               "bus_id" => bus_id,
               "frame" => ^frame_hex,
               "body" => ^body_hex,
               "pending_fds" => 0
             } = ready = actor_reply(port)

      assert Base.decode16!(auth_hex, case: :lower) == external_auth(uid)
      assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
      hello = frame("Hello", 1, <<>>, :absent)
      get_id = frame("GetId", 2, <<>>, :absent)
      assert Base.decode16!(hello_hex, case: :lower) == hello
      assert Base.decode16!(get_id_hex, case: :lower) == get_id
      assert {:ok, observer} = resolve(observer_name)
      assert {:ok, ^observer} = resolve(@owned)
      observer_monitor = Process.monitor(observer)
      await(fn -> registered?(observer, observer_name, actor_pid, ctx.identity) and quiet?() end)
      before = authority(observer)
      assert_target_absent()
      evidence("BODY_SIGNATURE_INPUT", ready)
      Port.command(port, "open\n")

      assert %{
               "event" => "opened",
               "case" => ^case_name,
               "source" => source_name,
               "auth" => ^auth_hex,
               "ok" => ^ok_hex,
               "pending_fds" => 0
             } = opened = actor_reply(port)

      assert opened["writes"] == [
               auth_hex,
               Base.encode16("BEGIN\r\n" <> hello <> get_id, case: :lower)
             ]

      await(fn -> length(children()) == 2 end)
      assert [source] = children() -- [observer]
      assert {:ok, ^source} = resolve(source_name)
      source_monitor = Process.monitor(source)
      await(fn -> registered?(source, source_name, actor_pid, ctx.identity) and quiet?() end)
      assert_target_absent()
      Port.command(port, "send\n")

      assert %{
               "event" => "sent",
               "case" => ^case_name,
               "frame" => ^frame_hex,
               "body" => ^body_hex,
               "pending_fds" => 0
             } = sent = actor_reply(port)

      assert sent["writes"] == opened["writes"] ++ [frame_hex]
      # The actor has not closed or read the malformed source socket.
      assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
      Port.command(port, "observe-close\n")

      assert %{
               "event" => "closed",
               "case" => ^case_name,
               "disposition" => "automatic-eof",
               "terminal_hex" => "",
               "source_socket_open" => true,
               "pending_fds" => 0
             } = closed = actor_reply(port)

      await(fn -> authority(observer) == before end)
      assert_target_absent()
      Port.command(port, "settled\n")

      assert %{
               "event" => "settled",
               "case" => ^case_name,
               "observer" => ^observer_name,
               "owned" => @owned,
               "bus_id" => ^bus_id,
               "health" => health,
               "buffered_hex" => "",
               "socket_pending" => false,
               "pending_fds" => 0
             } = settled = actor_reply(port)

      assert [_, _] = health
      await(fn -> authority(observer) == before end)
      assert {:ok, ^observer} = resolve(observer_name)
      assert {:ok, ^observer} = resolve(@owned)
      assert_target_absent()
      refute_receive {:DOWN, ^observer_monitor, :process, ^observer, _}, 0

      evidence("BODY_SIGNATURE_CASE", %{
        case: case_name,
        opened: opened,
        sent: sent,
        closed: closed,
        settled: settled,
        source_down: "normal",
        source_down_bound_ms: 1500,
        authority_restored: true
      })

      Port.command(port, "stop\n")

      assert %{
               "event" => "result",
               "result" => "PASS",
               "case" => ^case_name,
               "cases" => 1,
               "observer" => ^observer_name,
               "owned" => @owned,
               "target" => @target,
               "bus_id" => ^bus_id,
               "frame" => ^frame_hex,
               "body" => ^body_hex,
               "health" => ^health,
               "disposition" => "automatic-eof",
               "pending_fds" => 0
             } = result = actor_reply(port)

      assert_receive {^port, {:exit_status, 0}}, 3000
      assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500

      await(fn ->
        {:ok, accounting} = snapshot()

        children() == [] and :sys.get_state(Router, 1500).peers == %{} and
          names() == ["org.freedesktop.DBus"] and accounting == ctx.empty_accounting
      end)

      assert_target_absent()
      :ok = stop_supervised(GaoBus.Listener)
      refute File.exists?(ctx.path)
      evidence("BODY_SIGNATURE_SUMMARY", result)
    end
  end

  # Independent complete D-Bus fixed/header/body construction, without ExDBus encoding.
  defp frame(member, serial, body, signature) do
    fields = [
      {1, "o", wire_string("/org/freedesktop/DBus")},
      {2, "s", wire_string("org.freedesktop.DBus")},
      {3, "s", wire_string(member)},
      {6, "s", wire_string("org.freedesktop.DBus")}
    ]

    fields = if signature == :empty, do: fields ++ [{8, "g", <<0, 0>>}], else: fields

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

  defp external_auth(uid) do
    encoded = Base.encode16(Integer.to_string(uid), case: :lower)
    <<0>> <> "AUTH EXTERNAL " <> encoded <> "\r\n"
  end

  defp assert_target_absent do
    assert {:error, :name_not_found} = resolve(@target)

    assert {:error, "org.freedesktop.DBus.Error.NameHasNoOwner"} =
             GenServer.call(NameRegistry, {:list_queued_owners, @target}, 1500)
  end

  defp registered?(peer, name, actor_pid, %{uid: uid, gid: gid}) do
    state = peer_state(peer)

    state.state == :connected and state.unique_name == name and state.auth.phase == :connected and
      state.credentials == Map.put(state.auth.credentials, :unique_name, name) and
      match?(%{uid: ^uid, gid: ^gid, pid: ^actor_pid}, state.auth.credentials) and
      state.auth.buffer == <<>> and
      state.auth.total_bytes == byte_size(external_auth(uid)) + byte_size("BEGIN\r\n") and
      state.buffer == <<>> and state.incoming_fds == [] and not state.auth.unix_fd_negotiated and
      state.frame_timer == nil and state.frame_deadline == nil and
      state.frame_timeout_ms == 5000 and state.route_wait == nil and
      state.current_output == nil and state.output_queue == {[], []}
  end

  # Never retain socket/native resource handles in a fixture snapshot.
  defp peer_state(peer), do: Map.drop(:sys.get_state(peer, 1500), [:socket, :native_socket])

  defp authority(observer) do
    registry = :sys.get_state(NameRegistry, 1500)
    {:ok, accounting} = snapshot()

    %{
      core:
        Enum.map(
          [
            GaoBus.Ids,
            Router,
            NameRegistry,
            Limits,
            GaoBus.Policy,
            GaoBus.MatchRules,
            GaoBus.Policy.Capability,
            PeerSupervisor
          ],
          &Process.whereis/1
        ),
      # Normal registration/replies advance only the monotonic output serial.
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

  defp children,
    do: Enum.map(GenServer.call(PeerSupervisor, :which_children, 1500), &elem(&1, 1))

  defp snapshot, do: GenServer.call(Limits, :snapshot, 1500)
  defp names, do: GenServer.call(NameRegistry, :list_names, 1500)
  defp resolve(name), do: GenServer.call(NameRegistry, {:resolve, name}, 1500)

  defp quiet? do
    {:ok, accounting} = snapshot()

    accounting.reservations == 0 and accounting.global.frame_bytes == 0 and
      accounting.global.frame_fds == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "body-signature state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
