defmodule GaoBus.PeerCoalescedReadTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, PeerSupervisor, Router}
  alias GaoBus.Unix.Resources

  setup ctx do
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = GaoBus.Unix.Native.identity().uid

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-coalesced-#{System.pid()}-#{System.unique_integer([:positive])}"
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
    start_supervised!({Limits, limits: Map.get(ctx, :limits, %{})})
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

  test "one FD-free consuming receive contains a frame tail and two complete successors", ctx do
    exercise(ctx, "plain")
  end

  test "discarding an unknown frame keeps complete and partial successors charged", ctx do
    exercise(ctx, "unknown")
  end

  test "FD-negotiated consuming receives remain bounded by each frame", ctx do
    exercise(ctx, "negotiated")
  end

  test "unnegotiated rights close before any coalesced normal call reaches Router", ctx do
    exercise(ctx, "ancillary")
  end

  @tag limits: %{peer: %{frame_bytes: 512}}
  test "a small current frame survives insufficient optional read-ahead credits", ctx do
    exercise(ctx, "limited")
  end

  defp exercise(ctx, mode) do
    python = System.find_executable("python3") || flunk("required Python actor missing")
    actor = Path.expand("fixtures/peer_coalesced_read_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        {:line, 16_384},
        args: ["-B", actor, ctx.path, mode]
      ])

    on_exit(fn -> if Port.info(port), do: Port.close(port) end)

    assert %{
             "event" => "ready",
             "source" => source_name,
             "observer" => observer_name,
             "bus_id" => bus_id,
             "frames" => encoded
           } = actor_reply(port)

    frames = Enum.map(encoded, &Base.decode16!(&1, case: :lower))

    for {frame, serial} <- Enum.zip(frames, 10..13) do
      assert {:ok, message, <<>>} = Message.decode_message(frame)
      assert message.serial == serial

      assert message.type ==
               if(serial == 10 and mode == "unknown", do: {:unknown, 42}, else: :method_call)
    end

    [first, second, third | trailing] = frames
    partial = if mode == "unknown", do: binary_part(hd(trailing), 0, 8), else: <<>>
    tail = binary_part(first, 16, byte_size(first) - 16)
    queued = tail <> second <> third <> partial
    assert {:ok, source} = NameRegistry.resolve(source_name)
    assert {:ok, observer} = NameRegistry.resolve(observer_name)
    source_monitor = Process.monitor(source)
    observer_monitor = Process.monitor(observer)
    await(fn -> quiet?() end)
    assert :sys.get_state(source).auth.unix_fd_negotiated == (mode == "negotiated")

    Port.command(port, "prefix\n")
    assert %{"event" => "partial"} = actor_reply(port)
    prefix = binary_part(first, 0, 16)

    await(fn ->
      state = :sys.get_state(source)
      state.buffer == prefix and frame_bytes(source) == 16 and state.route_wait == nil
    end)

    trace(source)

    try do
      :ok = :sys.suspend(source)
      :ok = :sys.suspend(Router)
      Port.command(port, "queue\n")
      assert %{"event" => "queued", "bytes" => queued_bytes} = actor_reply(port)
      assert queued_bytes == byte_size(queued)
      :ok = :sys.resume(source)

      {requested, received, resources} = recv_result(source)
      assert requested <= 65_536

      if mode in ["negotiated", "limited"] do
        assert requested == byte_size(tail)
        assert received == tail
      else
        # This is the actual Resources.recv/3 return, not an actor write boundary.
        assert received == queued
        assert requested >= byte_size(received)
      end

      if mode == "ancillary" do
        assert [handle] = resources
        assert_receive {:DOWN, ^source_monitor, :process, ^source, :normal}, 1500
        assert Resources.info(handle) == {:error, :closed}
        delivered = :erlang.trace_delivered(source)
        assert_receive {:trace_delivered, ^source, ^delivered}, 1500
        refute_receive {:trace, ^source, :call, {Router, :route_frame, _arguments}}, 0
      else
        assert resources == []

        if mode == "unknown" do
          assert next_credit(source) == 16 + byte_size(queued)
          assert next_credit(source) == byte_size(second <> third <> partial)
        end

        retained =
          case mode do
            "negotiated" -> <<>>
            "limited" -> <<>>
            "unknown" -> third <> partial
            "plain" -> second <> third
          end

        await(fn ->
          state = :sys.get_state(source)

          state.buffer == retained and state.route_wait != nil and state.incoming_fds == [] and
            frame_bytes(source) == byte_size(retained)
        end)
      end

      :ok = :sys.resume(Router)
      Port.command(port, "finish\n")

      if mode in ["negotiated", "limited"] do
        for frame <- [second, third] do
          header = binary_part(frame, 0, 16)
          rest = binary_part(frame, 16, byte_size(frame) - 16)
          assert recv_chunk(source) == {16, header}
          assert recv_chunk(source) == {byte_size(rest), rest}
        end
      end

      assert %{"event" => "completed", "reply_serials" => serials, "bus_id" => ^bus_id} =
               actor_reply(port)

      expected =
        case mode do
          "unknown" -> [11, 12, 13]
          "ancillary" -> []
          _ -> [10, 11, 12]
        end

      assert serials == expected
      await(fn -> (mode == "ancillary" or :sys.get_state(source).buffer == <<>>) and quiet?() end)
    after
      resume(source)
      resume(Router)
    end

    Port.command(port, "close\n")
    assert %{"event" => "closed"} = actor_reply(port)
    assert_receive {^port, {:exit_status, 0}}, 3000

    if mode != "ancillary",
      do: assert_receive({:DOWN, ^source_monitor, :process, ^source, :normal}, 1500)

    assert_receive {:DOWN, ^observer_monitor, :process, ^observer, :normal}, 1500

    await(fn ->
      {:ok, accounting} = Limits.snapshot()

      DynamicSupervisor.which_children(PeerSupervisor) == [] and
        :sys.get_state(Router).peers == %{} and
        NameRegistry.list_names() == ["org.freedesktop.DBus"] and
        accounting.global.connections == 0 and quiet?()
    end)

    :ok = stop_supervised(GaoBus.Listener)
    refute File.exists?(ctx.path)
  end

  defp trace(peer) do
    for function <- [{Resources, :recv, 3}, {Limits, :set_frame, 3}, {Router, :route_frame, 3}] do
      assert {:traced, false} = :erlang.trace_info(function, :traced)
      assert 1 = :erlang.trace_pattern(function, [{:_, [], [{:return_trace}]}], [])
      on_exit(fn -> :erlang.trace_pattern(function, false, []) end)
    end

    assert 1 = :erlang.trace(peer, true, [:call, {:tracer, self()}])
  end

  defp recv_chunk(peer) do
    {bytes, data, resources} = recv_result(peer)
    assert resources == []
    {bytes, data}
  end

  defp recv_result(peer, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    assert_receive {:trace, ^peer, :call, {Resources, :recv, [_socket, bytes, _fds]}}, remaining
    assert_receive {:trace, ^peer, :return_from, {Resources, :recv, 3}, result}, remaining

    case result do
      {:ok, data, resources} -> {bytes, data, resources}
      {:error, :eagain} -> recv_result(peer, deadline)
      other -> flunk("unexpected native receive: #{inspect(other)}")
    end
  end

  defp next_credit(peer) do
    assert_receive {:trace, ^peer, :call, {Limits, :set_frame, [^peer, bytes, 0]}}, 1500
    bytes
  end

  defp frame_bytes(peer) do
    {:ok, accounting} = Limits.snapshot()
    assert accounting.peers[peer].frame_fds == 0
    accounting.peers[peer].frame_bytes
  end

  defp quiet? do
    {:ok, accounting} = Limits.snapshot()

    accounting.reservations == 0 and accounting.global.frame_bytes == 0 and
      accounting.global.frame_fds == 0 and accounting.global.egress_messages == 0
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "coalesced read state deadline"
      await(predicate, deadline)
    end
  end

  defp resume(process) do
    try do
      :sys.resume(process)
    catch
      :exit, _ -> :ok
    end
  end

  defp actor_reply(port) do
    assert_receive {^port, {:data, {:eol, line}}}, 3000
    :json.decode(line)
  end
end
