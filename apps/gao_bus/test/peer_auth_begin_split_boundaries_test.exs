defmodule GaoBus.PeerAuthBeginSplitBoundariesTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid
    assert uid == 1101

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-auth-begin-split-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)

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
    path = Path.join(directory, "bus")

    start_supervised!(
      {GaoBus.Listener, socket_path: path, socket_mode: 0o600, peer_options: [auth_limits: []]}
    )

    %{path: path}
  end

  @tag timeout: 60_000
  test "every normal AUTH and BEGIN split preserves registration and its GetId successor", ctx do
    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_auth_begin_split_boundaries_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: ["-B", actor, ctx.path]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)

    assert %{
             "event" => "ready",
             "observer" => observer_name,
             "owned" => "org.foundation.AuthBeginSplitObserver" = owned,
             "bus_id" => bus_id,
             "actor_pid" => actor_pid,
             "uid" => 1101,
             "gid" => 1101,
             "auth" => auth_hex,
             "begin" => begin_hex,
             "ok" => ok_hex,
             "hello" => hello_hex,
             "get_id" => get_id_hex,
             "cases" => cases
           } = ready = actor_reply(port)

    auth = <<0>> <> "AUTH EXTERNAL 31313031\r\n"
    begin = "BEGIN\r\n"
    assert Base.decode16!(auth_hex, case: :lower) == auth
    assert Base.decode16!(begin_hex, case: :lower) == begin
    assert byte_size(auth) == 25
    assert byte_size(begin) == 7
    assert <<"OK ", _guid::binary-size(32), "\r\n">> = Base.decode16!(ok_hex, case: :lower)
    hello = Base.decode16!(hello_hex, case: :lower)
    get_id = Base.decode16!(get_id_hex, case: :lower)
    assert byte_size(hello) == 128
    assert byte_size(get_id) == 128
    assert digest(hello) == "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31"
    assert digest(get_id) == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"

    assert cases ==
             Enum.map(1..24, &%{"family" => "AUTH", "split" => &1}) ++
               Enum.map(1..6, &%{"family" => "BEGIN", "split" => &1})

    assert {:ok, observer} = resolve(observer_name)
    assert {:ok, ^observer} = resolve(owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> quiet?() end)
    before = authority()
    evidence("AUTH_BEGIN_SPLIT_INPUT", ready)

    for {%{"family" => family, "split" => split}, index} <- Enum.with_index(cases) do
      Port.command(port, "next\n")

      assert %{"event" => "opened", "index" => ^index, "family" => ^family, "split" => ^split} =
               actor_reply(port)

      await(fn -> length(children()) == 2 end)
      assert [source] = children() -- [observer]
      source_monitor = Process.monitor(source)
      Port.command(port, "prefix\n")

      assert %{
               "event" => "partial",
               "index" => ^index,
               "family" => ^family,
               "split" => ^split,
               "prefix" => prefix_hex
             } = partial = actor_reply(port)

      stream = if family == "AUTH", do: auth, else: begin
      prefix = binary_part(stream, 0, split)
      assert Base.decode16!(prefix_hex, case: :lower) == prefix

      await(fn ->
        state = :sys.get_state(source, 1500)
        {:ok, accounting} = snapshot()
        credits = accounting.peers[source]

        state.state == :authenticating and state.buffer == <<>> and
          state.incoming_fds == [] and state.unique_name == nil and
          not state.auth.unix_fd_negotiated and state.route_wait == nil and
          held_auth?(state, family, prefix, actor_pid) and
          credits.connections == 1 and credits.authenticating == 1 and
          credits.frame_bytes == 0 and credits.frame_fds == 0 and
          accounting.global.connections == before.accounting.global.connections + 1 and
          accounting.global.authenticating == before.accounting.global.authenticating + 1 and
          :sys.get_state(Router, 1500).peers == before.peers and
          Enum.sort(names()) == before.names and quiet?()
      end)

      assert {:ok, ^observer} = resolve(observer_name)
      assert {:ok, ^observer} = resolve(owned)
      Port.command(port, "finish\n")

      assert %{
               "event" => "completed",
               "index" => ^index,
               "family" => ^family,
               "split" => ^split,
               "source" => source_name,
               "bus_id" => ^bus_id,
               "ok" => ^ok_hex,
               "reply_serials" => [1, 2],
               "buffered_hex" => "",
               "socket_pending" => false
             } = completed = actor_reply(port)

      expected_writes =
        if family == "AUTH" do
          [prefix, binary_part(auth, split, 25 - split), begin <> hello <> get_id]
        else
          [auth, prefix, binary_part(begin, split, 7 - split) <> hello <> get_id]
        end

      assert completed["writes"] == Enum.map(expected_writes, &Base.encode16(&1, case: :lower))
      assert {:ok, ^source} = resolve(source_name)
      assert {:ok, ^observer} = resolve(observer_name)
      assert {:ok, ^observer} = resolve(owned)

      await(fn ->
        state = :sys.get_state(source, 1500)
        peers = :sys.get_state(Router, 1500).peers
        {:ok, accounting} = snapshot()

        state.state == :connected and state.unique_name == source_name and
          state.auth.phase == :connected and state.auth.total_bytes == 32 and
          state.auth.buffer == <<>> and state.buffer == <<>> and state.incoming_fds == [] and
          not state.auth.unix_fd_negotiated and
          state.credentials == Map.put(state.auth.credentials, :unique_name, source_name) and
          state.route_wait == nil and Enum.sort(Map.keys(peers)) == Enum.sort([observer, source]) and
          peers[source].unique_name == source_name and
          Enum.sort(names()) == Enum.sort([source_name | before.names]) and
          accounting.peers[source].authenticating == 0 and quiet?()
      end)

      Port.command(port, "close\n")

      assert %{"event" => "closed", "index" => ^index, "family" => ^family, "split" => ^split} =
               actor_reply(port)

      assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
      await(fn -> authority() == before end)
      Port.command(port, "settled\n")

      evidence(
        "AUTH_BEGIN_SPLIT_CASE",
        completed
        |> Map.put("held_prefix_verified", true)
        |> Map.put("held_prefix", partial)
      )
    end

    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 30,
             "auth_cases" => 24,
             "begin_cases" => 6,
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
        accounting.global.connections == 0 and accounting.global.authenticating == 0 and quiet?()
    end)

    :ok = stop_supervised(GaoBus.Listener)
    refute File.exists?(ctx.path)
    evidence("AUTH_BEGIN_SPLIT_SUMMARY", result)
  end

  defp held_auth?(state, "AUTH", prefix, actor_pid) do
    state.auth.phase == :auth and state.auth.total_bytes == 1 and
      state.auth.buffer == binary_part(prefix, 1, byte_size(prefix) - 1) and
      state.credentials == nil and trusted?(state.auth.credentials, actor_pid)
  end

  defp held_auth?(state, "BEGIN", prefix, actor_pid) do
    state.auth.phase == :authenticated and state.auth.total_bytes == 25 and
      state.auth.buffer == prefix and state.credentials == state.auth.credentials and
      trusted?(state.credentials, actor_pid)
  end

  defp trusted?(credentials, actor_pid),
    do: match?(%{uid: 1101, gid: 1101, pid: ^actor_pid}, credentials)

  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp children,
    do: Enum.map(GenServer.call(PeerSupervisor, :which_children, 1500), &elem(&1, 1))

  defp snapshot, do: GenServer.call(Limits, :snapshot, 1500)
  defp names, do: GenServer.call(NameRegistry, :list_names, 1500)
  defp resolve(name), do: GenServer.call(NameRegistry, {:resolve, name}, 1500)

  defp authority do
    {:ok, accounting} = snapshot()

    %{
      core: Enum.map([Router, NameRegistry, Limits, GaoBus.Policy], &Process.whereis/1),
      peers: :sys.get_state(Router, 1500).peers,
      names: Enum.sort(names()),
      accounting: accounting
    }
  end

  defp quiet? do
    {:ok, accounting} = snapshot()

    accounting.reservations == 0 and accounting.global.frame_bytes == 0 and
      accounting.global.frame_fds == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "AUTH/BEGIN split state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
