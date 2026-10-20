defmodule GaoBus.PeerGetIdSplitBoundariesTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-getid-split-#{System.pid()}-#{System.unique_integer([:positive])}"
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
  test "every normal GetId split preserves registered state and its GetId successor", ctx do
    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_get_id_split_boundaries_actor.py", __DIR__)

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
             "owned" => owned,
             "bus_id" => bus_id,
             "hello" => hello_hex,
             "get_id" => get_id_hex,
             "splits" => splits
           } = ready = actor_reply(port)

    hello = Base.decode16!(hello_hex, case: :lower)
    get_id = Base.decode16!(get_id_hex, case: :lower)
    assert byte_size(hello) == 128
    assert byte_size(get_id) == 128
    assert digest(hello) == "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31"
    assert digest(get_id) == "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575"
    assert splits == Enum.to_list(1..127)
    assert {:ok, observer} = NameRegistry.resolve(observer_name)
    assert {:ok, ^observer} = NameRegistry.resolve(owned)
    observer_monitor = Process.monitor(observer)
    await(fn -> quiet?() end)
    before = authority()
    evidence("GETID_SPLIT_INPUT", ready)

    for split <- splits do
      Port.command(port, "next\n")

      assert %{"event" => "opened", "split" => ^split, "source" => source_name} =
               opened = actor_reply(port)

      await(fn -> length(children()) == 2 end)
      assert [source] = children() -- [observer]
      source_monitor = Process.monitor(source)
      assert {:ok, ^source} = NameRegistry.resolve(source_name)
      assert GaoBus.Peer.get_unique_name(source) == source_name

      await(fn ->
        state = :sys.get_state(source)

        state.state == :connected and state.buffer == <<>> and state.incoming_fds == [] and
          not state.auth.unix_fd_negotiated and state.route_wait == nil and quiet?()
      end)

      Port.command(port, "prefix\n")

      assert %{"event" => "partial", "split" => ^split, "prefix" => prefix_hex} =
               partial = actor_reply(port)

      prefix = binary_part(get_id, 0, split)
      assert Base.decode16!(prefix_hex, case: :lower) == prefix

      await(fn ->
        state = :sys.get_state(source)
        {:ok, accounting} = Limits.snapshot()

        state.state == :connected and state.buffer == prefix and
          state.incoming_fds == [] and not state.auth.unix_fd_negotiated and
          accounting.peers[source].frame_bytes == split and
          accounting.peers[source].frame_fds == 0
      end)

      assert GaoBus.Peer.get_unique_name(source) == source_name
      assert {:ok, ^source} = NameRegistry.resolve(source_name)
      assert {:ok, ^observer} = NameRegistry.resolve(owned)
      Port.command(port, "finish\n")

      assert %{
               "event" => "completed",
               "split" => ^split,
               "source" => ^source_name,
               "bus_id" => ^bus_id,
               "reply_serials" => [2, 3],
               "buffered_hex" => "",
               "socket_pending" => false
             } = completed = actor_reply(port)

      assert {:ok, ^source} = NameRegistry.resolve(source_name)
      assert {:ok, ^observer} = NameRegistry.resolve(observer_name)
      assert {:ok, ^observer} = NameRegistry.resolve(owned)

      await(fn ->
        state = :sys.get_state(source)

        state.state == :connected and state.buffer == <<>> and state.incoming_fds == [] and
          not state.auth.unix_fd_negotiated and state.route_wait == nil and quiet?()
      end)

      Port.command(port, "close\n")
      assert %{"event" => "closed", "split" => ^split} = actor_reply(port)
      assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
      await(fn -> authority() == before end)
      Port.command(port, "settled\n")

      evidence(
        "GETID_SPLIT_CASE",
        completed
        |> Map.put("held_prefix_verified", true)
        |> Map.put("registration", opened)
        |> Map.put("held_prefix", partial)
      )
    end

    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 127,
             "observer" => ^observer_name,
             "owned" => ^owned,
             "bus_id" => ^bus_id
           } = result = actor_reply(port)

    assert_receive {^port, {:exit_status, 0}}, 3000
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500

    await(fn ->
      {:ok, accounting} = Limits.snapshot()

      children() == [] and :sys.get_state(Router).peers == %{} and
        NameRegistry.list_names() == ["org.freedesktop.DBus"] and
        accounting.global.connections == 0 and accounting.reservations == 0 and quiet?()
    end)

    :ok = stop_supervised(GaoBus.Listener)
    refute File.exists?(ctx.path)
    evidence("GETID_SPLIT_SUMMARY", result)
  end

  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp children, do: Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))

  defp authority do
    {:ok, accounting} = Limits.snapshot()

    %{
      core: Enum.map([Router, NameRegistry, Limits, GaoBus.Policy], &Process.whereis/1),
      peers: :sys.get_state(Router).peers,
      names: Enum.sort(NameRegistry.list_names()),
      accounting: accounting
    }
  end

  defp quiet? do
    {:ok, accounting} = Limits.snapshot()

    accounting.reservations == 0 and accounting.global.frame_bytes == 0 and
      accounting.global.frame_fds == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "GetId split state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
