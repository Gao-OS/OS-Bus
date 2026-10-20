defmodule GaoBus.PeerFixedHeaderLengthsTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  @header_max 67_108_864
  @message_cap 67_108_888

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = String.to_integer(System.get_env("OS_BUS_FIXED_HEADER_UID", "1101"))
    gid = String.to_integer(System.get_env("OS_BUS_FIXED_HEADER_GID", "1101"))
    assert uid in 1..0xFFFFFFFE
    assert gid in 1..0xFFFFFFFE

    assert %{uid: ^uid, gid: ^gid, real_uid: ^uid, real_gid: ^gid} =
             GaoBus.Unix.Native.identity()

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-fixed-header-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    xml = %{"max_message_size" => @message_cap}

    rules =
      Enum.map(
        [:connect, :own, :send, :receive],
        &%{action: &1, effect: :allow, match: %{uid: uid}}
      )

    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!({Limits, xml_limits: xml})
    start_supervised!({GaoBus.Policy, rules: rules})
    start_supervised!({NameRegistry, xml_limits: xml})
    start_supervised!({GaoBus.MatchRules, xml_limits: xml})
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!(Router)
    start_supervised!({PeerSupervisor, max_children: 8})
    path = Path.join(directory, "bus")

    start_supervised!(
      {GaoBus.Listener, socket_path: path, socket_mode: 0o600, peer_options: [xml_limits: xml]}
    )

    %{path: path, identity: %{uid: uid, gid: gid}}
  end

  for endian <- [:little, :big] do
    @tag timeout: 60_000
    test "PRO-04 #{endian} header-array length is validated from its fixed prefix", ctx do
      endian = unquote(endian)
      order = Atom.to_string(endian)
      %{uid: uid, gid: gid} = ctx.identity

      python =
        System.find_executable("python3") || flunk("required independent Python actor missing")

      actor = Path.expand("fixtures/peer_fixed_header_lengths_actor.py", __DIR__)

      port =
        Port.open({:spawn_executable, python}, [
          :binary,
          :exit_status,
          {:line, 16_384},
          args: ["-B", actor, ctx.path, order]
        ])

      on_exit(fn -> if Port.info(port), do: Port.close(port) end)

      assert %{
               "event" => "ready",
               "endian" => ^order,
               "observer" => observer_name,
               "owned" => "org.foundation.FixedHeaderObserver" = owned,
               "actor_pid" => actor_pid,
               "uid" => ^uid,
               "gid" => ^gid,
               "auth" => auth_hex,
               "ok" => ok_hex,
               "hello" => hello_hex,
               "get_id" => get_id_hex,
               "bus_id" => bus_id,
               "message_cap" => @message_cap
             } = ready = actor_reply(port)

      auth = external_auth(uid)
      assert Base.decode16!(auth_hex, case: :lower) == auth
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
      evidence("FIXED_HEADER_INPUT", ready)

      for {family, length} <- [{"valid", @header_max}, {"invalid", @header_max + 1}] do
        Port.command(port, "open-#{family}\n")

        assert %{
                 "event" => "opened",
                 "family" => ^family,
                 "source" => source_name,
                 "auth" => ^auth_hex,
                 "ok" => ^ok_hex
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
        connected = authority(observer)
        prefix = fixed_header(endian, length)
        assert byte_size(prefix) == 16
        Port.command(port, "prefix-#{family}\n")

        assert %{"event" => "sent", "family" => ^family, "prefix" => prefix_hex} =
                 sent = actor_reply(port)

        assert Base.decode16!(prefix_hex, case: :lower) == prefix
        assert sent["writes"] == opened["writes"] ++ [prefix_hex]

        if family == "valid" do
          await(fn -> held?(source, source_name, actor_pid, prefix, ctx.identity) end)
          await(fn -> authority(observer) == with_frame_bytes(connected, source, 16, uid) end)
          refute_receive {:DOWN, ^source_monitor, :process, ^source, _}, 0
          Port.command(port, "held\n")

          assert %{"event" => "held", "family" => ^family, "prefix" => ^prefix_hex} =
                   actor_reply(port)

          await(fn -> held?(source, source_name, actor_pid, prefix, ctx.identity) end)
          await(fn -> authority(observer) == with_frame_bytes(connected, source, 16, uid) end)
          Port.command(port, "close-valid\n")

          assert %{
                   "event" => "closed",
                   "family" => ^family,
                   "disposition" => "client-normal-close"
                 } = actor_reply(port)

          assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
        else
          # The actor keeps this socket open until this automatic DOWN is proved.
          assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
          Port.command(port, "observe-close\n")

          assert %{
                   "event" => "closed",
                   "family" => ^family,
                   "disposition" => "automatic-eof",
                   "terminal_hex" => ""
                 } = actor_reply(port)
        end

        await(fn -> authority(observer) == before end)
        Port.command(port, "settled-#{family}\n")
        assert %{"event" => "settled", "family" => ^family} = actor_reply(port)
        await(fn -> authority(observer) == before end)
        assert {:ok, ^observer} = resolve(observer_name)
        assert {:ok, ^observer} = resolve(owned)

        evidence("FIXED_HEADER_CASE", %{
          endian: order,
          family: family,
          prefix: prefix_hex,
          bytes: 16
        })
      end

      Port.command(port, "stop\n")

      assert %{
               "event" => "result",
               "result" => "PASS",
               "endian" => ^order,
               "cases" => 2,
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

      :ok = stop_supervised(GaoBus.Listener)
      refute File.exists?(ctx.path)
      evidence("FIXED_HEADER_SUMMARY", result)
    end
  end

  defp fixed_header(:little, length),
    do: <<?l, 1, 0, 1, 0::little-32, 3::little-32, length::little-32>>

  defp fixed_header(:big, length), do: <<?B, 1, 0, 1, 0::big-32, 3::big-32, length::big-32>>

  defp external_auth(uid) do
    encoded = Base.encode16(Integer.to_string(uid), case: :lower)
    <<0>> <> "AUTH EXTERNAL " <> encoded <> "\r\n"
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
      state.frame_timeout_ms == nil and state.route_wait == nil and
      state.current_output == nil and state.output_queue == {[], []}
  end

  defp held?(peer, name, actor_pid, prefix, %{uid: uid, gid: gid}) do
    state = peer_state(peer)
    {:ok, accounting} = snapshot()

    state.state == :connected and state.unique_name == name and state.buffer == prefix and
      state.credentials == Map.put(state.auth.credentials, :unique_name, name) and
      match?(%{uid: ^uid, gid: ^gid, pid: ^actor_pid}, state.auth.credentials) and
      state.incoming_fds == [] and not state.auth.unix_fd_negotiated and
      state.frame_timer == nil and state.frame_deadline == nil and state.route_wait == nil and
      accounting.peers[peer].frame_bytes == 16 and accounting.peers[peer].frame_fds == 0
  end

  # Never retain socket/native resource handles in a fixture snapshot.
  defp peer_state(peer),
    do: Map.drop(:sys.get_state(peer, 1500), [:socket, :native_socket])

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

  defp with_frame_bytes(state, source, bytes, uid) do
    accounting =
      state.accounting
      |> update_in([:global, :frame_bytes], &(&1 + bytes))
      |> update_in([:uids, uid, :frame_bytes], &(&1 + bytes))
      |> update_in([:peers, source, :frame_bytes], &(&1 + bytes))

    %{state | accounting: accounting}
  end

  defp children,
    do: Enum.map(GenServer.call(PeerSupervisor, :which_children, 1500), &elem(&1, 1))

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
      assert System.monotonic_time(:millisecond) < deadline, "fixed-header state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
