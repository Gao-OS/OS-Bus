defmodule GaoBus.PeerWholeStreamTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}
  alias GaoBus.Unix.Resources

  setup do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-whole-stream-#{System.pid()}-#{System.unique_integer([:positive])}"
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
  test "one whole-stream client write authenticates and completes Hello then GetId", ctx do
    baseline = authority()

    python =
      System.find_executable("python3") || flunk("required independent Python actor missing")

    actor = Path.expand("fixtures/peer_whole_stream_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        args: ["-B", actor, ctx.path]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)

    assert %{
             "event" => "ready",
             "observer" => observer_name,
             "bus_id" => bus_id,
             "ok" => ok,
             "identity" => %{"pid" => actor_pid, "uid" => uid, "gid" => gid},
             "stream" => stream_hex,
             "stream_sha256" => stream_sha256
           } = ready = actor_reply(port)

    native_identity = GaoBus.Unix.Native.identity()
    assert uid == native_identity.uid
    assert gid == native_identity.gid
    stream = Base.decode16!(stream_hex, case: :lower)
    assert byte_size(stream) == 288
    assert digest(stream) == stream_sha256
    assert {:ok, observer} = NameRegistry.resolve(observer_name)
    observer_monitor = Process.monitor(observer)

    assert %{
             "event" => "opened",
             "connection" => %{"pid" => ^actor_pid},
             "peer_credentials" => credentials
           } = opened = actor_reply(port)

    assert credentials == [String.to_integer(System.pid()), uid, gid]
    await(fn -> length(children()) == 2 end)
    assert [source] = children() -- [observer]
    source_monitor = Process.monitor(source)

    await(fn ->
      state = :sys.get_state(source)

      state.state == :authenticating and state.auth.phase == :initial and
        state.buffer == <<>> and state.incoming_fds == [] and state.unique_name == nil and
        quiet?()
    end)

    observer_authority = Map.take(authority(), [:core, :names, :peers])
    trace_native_reads(source)
    evidence("WHOLE_STREAM_INPUT", Map.put(ready, "opened", opened))
    Port.command(port, "send\n")
    reads = read_stream(source, stream, [], <<>>, System.monotonic_time(:millisecond) + 1500)

    assert %{
             "event" => "completed",
             "family" => "C",
             "id" => "coalesced",
             "result" => "PASS",
             "source" => source_name,
             "observer" => ^observer_name,
             "bus_id" => ^bus_id,
             "ok" => ^ok,
             "stream" => ^stream_hex,
             "stream_sha256" => ^stream_sha256,
             "writes" => [^stream_hex],
             "reply_serials" => [1, 2],
             "received_fds" => 0,
             "buffered_hex" => "",
             "socket_pending" => false
           } = completed = actor_reply(port)

    assert {:ok, ^source} = NameRegistry.resolve(source_name)

    await(fn ->
      state = :sys.get_state(source)

      state.state == :connected and state.buffer == <<>> and state.auth.buffer == <<>> and
        state.auth.phase == :connected and not state.auth.unix_fd_negotiated and
        state.incoming_fds == [] and
        state.route_wait == nil and quiet?()
    end)

    evidence(
      "WHOLE_STREAM_CASE",
      Map.merge(completed, %{"native_reads" => reads, "clean_peer_state_verified" => true})
    )

    Port.command(port, "close\n")
    assert %{"event" => "closed", "source" => ^source_name} = closed = actor_reply(port)
    assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500

    await(fn ->
      {:ok, accounting} = Limits.snapshot()

      Map.take(authority(), [:core, :names, :peers]) == observer_authority and
        children() == [observer] and Map.keys(accounting.peers) == [observer] and
        accounting.global.connections == 1 and accounting.global.authenticating == 0 and quiet?()
    end)

    evidence("WHOLE_STREAM_CLOSED", Map.put(closed, "authority_restored", true))
    Port.command(port, "stop\n")

    assert %{
             "event" => "result",
             "result" => "PASS",
             "cases" => 1,
             "observer" => ^observer_name,
             "bus_id" => ^bus_id
           } = result = actor_reply(port)

    assert_receive {^port, {:exit_status, 0}}, 3000
    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500
    await(fn -> authority() == baseline and children() == [] end)
    :ok = stop_supervised(GaoBus.Listener)
    refute File.exists?(ctx.path)

    evidence(
      "WHOLE_STREAM_SUMMARY",
      Map.merge(result, %{
        "authority_restored" => true,
        "accounting_restored" => true,
        "socket_removed" => true
      })
    )
  end

  defp trace_native_reads(peer) do
    function = {Resources, :recv, 3}
    assert {:traced, false} = :erlang.trace_info(function, :traced)
    assert 1 = :erlang.trace_pattern(function, [{:_, [], [{:return_trace}]}], [])
    on_exit(fn -> :erlang.trace_pattern(function, false, []) end)
    assert 1 = :erlang.trace(peer, true, [:call, {:tracer, self()}])
  end

  defp read_stream(_peer, expected, reads, expected, _deadline), do: Enum.reverse(reads)

  defp read_stream(peer, expected, reads, consumed, deadline) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    assert_receive {:trace, ^peer, :call, {Resources, :recv, [_socket, requested, _fds]}},
                   remaining

    remaining = max(0, deadline - System.monotonic_time(:millisecond))
    assert_receive {:trace, ^peer, :return_from, {Resources, :recv, 3}, result}, remaining

    case result do
      {:ok, data, []} ->
        assert data != <<>> and byte_size(data) <= requested and requested <= 65_536
        received = consumed <> data
        assert byte_size(received) <= byte_size(expected)
        assert binary_part(expected, 0, byte_size(received)) == received

        read = %{
          "requested" => requested,
          "received_bytes" => byte_size(data),
          "received_hex" => Base.encode16(data, case: :lower),
          "received_fds" => 0
        }

        read_stream(peer, expected, [read | reads], received, deadline)

      {:error, :eagain} ->
        read_stream(peer, expected, reads, consumed, deadline)

      other ->
        flunk("unexpected whole-stream native receive: #{inspect(other)}")
    end
  end

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

    accounting.reservations == 0 and
      Enum.all?(accounting.global, fn {metric, value} ->
        metric in [:connections, :authenticating] or value == 0
      end)
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "whole-stream state deadline"
      await(predicate, deadline)
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end

  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  defp evidence(label, value), do: IO.puts([label, " ", :json.encode(value)])
end
