defmodule GaoBus.PeerWriterClosedTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, MatchRules, NameRegistry, Router}
  alias GaoBus.Unix.{Native, Resources, Writer}

  @moduletag timeout: 20_000
  @actor Path.expand("fixtures/peer_writer_closed_actor.py", __DIR__)
  @write_ms 5000
  @healthy_ms 1000
  @cleanup_ms 1000

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(System.tmp_dir!(), "gb-writer-closed-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    uid = Native.identity().uid

    settings = [
      socket_path: path,
      config_file: nil,
      profile: :session,
      cluster: false,
      capability_restrictions: false,
      resource_limits: %{peer: %{egress_bytes: 262_144, egress_messages: 8}},
      policy_rules:
        Enum.map([:connect, :own, :send, :receive], fn action ->
          %{action: action, effect: :allow, match: %{uid: uid}}
        end),
      send_timeout_ms: @write_ms
    ]

    previous = Enum.map(settings, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)

    on_exit(fn ->
      for {key, saved} <- previous do
        case saved do
          {:ok, value} -> Application.put_env(:gao_bus, key, value)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end

      File.rm_rf!(directory)
    end)

    start_supervised!(%{
      id: :writer_closed_bus,
      start: {GaoBus.Application, :start, [:normal, []]}
    })

    %{path: path, uid: uid}
  end

  test "FD-07 real read-half shutdown fails the blocked Peer writer before its deadline",
       ctx do
    python = System.find_executable("python3") || flunk("required Python actor unavailable")

    actor =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 4096},
        args: ["-B", @actor, ctx.path, System.pid()]
      ])

    on_exit(fn -> if Port.info(actor), do: Port.close(actor) end)

    assert %{
             "event" => "ready",
             "source" => source_name,
             "target" => target_name,
             "observer" => observer_name,
             "owned" => owned,
             "daemon_fds" => baseline_fds,
             "daemon_memfds" => []
           } = actor_event(actor)

    source = resolve(source_name)
    target = resolve(target_name)
    observer = resolve(observer_name)
    assert resolve(owned) == target
    monitors = Map.new([source, target, observer], &{&1, Process.monitor(&1)})
    router = Process.whereis(Router)

    authorities =
      Map.new(
        [GaoBus.Ids, Limits, NameRegistry, Router, GaoBus.Policy],
        &{&1, Process.whereis(&1)}
      )

    assert Enum.all?(authorities, fn {_module, pid} -> is_pid(pid) end)
    await(fn -> idle_credits?(stats()) end)
    assert MatchRules.has_rules?(target)
    assert :ok = :socket.setopt(:sys.get_state(target).socket, :socket, :sndbuf, 1024)

    started = now()
    continue(actor)
    assert %{"event" => "queued", "messages" => 2} = actor_event(actor)

    await(fn ->
      state = :sys.get_state(target)

      case state.current_output do
        %{writer: %{blocked: true, offset: offset, bytes: bytes}} ->
          offset > 0 and offset < byte_size(bytes) and :queue.len(state.output_queue) == 1

        _ ->
          false
      end
    end)

    state = :sys.get_state(target)
    current = state.current_output
    [queued] = :queue.to_list(state.output_queue)
    [current_fd] = current.message.fds
    [queued_fd] = queued.message.fds
    native_socket = state.native_socket
    deadline = current.writer.deadline
    assert current.writer.rights_sent
    assert queued.writer.offset == 0
    refute queued.writer.rights_sent
    assert deadline - @write_ms >= started
    assert deadline - @write_ms <= now()
    assert deadline > now()
    _ = :sys.get_state(router)
    assert %{egress_messages: 2, egress_fds: 2, egress_bytes: bytes} = stats().peers[target]
    assert bytes <= 262_144
    assert stats().global.ingress_messages == 0

    health_deadline = now() + @healthy_ms
    continue(actor)

    assert %{
             "event" => "blocked_healthy",
             "latency_ms" => latency,
             "daemon_fds" => blocked_fds,
             "daemon_memfds" => [_, _]
           } = actor_event(actor, health_deadline)

    assert latency <= @healthy_ms
    assert now() <= health_deadline
    assert blocked_fds == baseline_fds + 2
    blocked = :sys.get_state(target).current_output.writer
    assert blocked.blocked
    assert blocked.offset == current.writer.offset
    assert blocked.deadline == deadline
    for fd <- [current_fd, queued_fd], do: assert(Resources.info(fd) == {:ok, %{cloexec: true}})

    # Trace only this real writer during the controlled read-half shutdown.
    # The actor retains its write half, so EOF/expiry cannot substitute for
    # a native Writer.step error observed before the original deadline.
    assert {:traced, false} = :erlang.trace_info({Writer, :step, 3}, :traced)

    assert 1 =
             :erlang.trace_pattern({Writer, :step, 3}, [{:_, [], [{:return_trace}]}], [])

    on_exit(fn -> :erlang.trace_pattern({Writer, :step, 3}, false, []) end)
    assert 1 = :erlang.trace(target, true, [:call, {:tracer, self()}])
    fault_deadline = min(now() + @cleanup_ms, deadline - 1)
    assert now() < fault_deadline
    continue(actor)
    assert %{"event" => "read_shutdown", "rights" => 1} = actor_event(actor, fault_deadline)

    trace_context = %{
      expected_handles: current.writer.handles,
      step_time: nil,
      calls: 0,
      waits: 0,
      rows: []
    }

    {reason, failed, stepped_at} = writer_error(target, fault_deadline, trace_context, 0)
    assert reason in [:closed, :epipe]
    assert stepped_at < deadline
    assert failed.deadline == deadline
    assert failed.rights_sent
    assert failed.handles_match
    assert failed.fds == 1
    assert failed.offset >= current.writer.offset
    assert failed.offset < failed.bytes
    assert now() < deadline

    IO.puts(
      "FD07_WRITER_TERMINAL " <>
        Jason.encode!(%{
          error: Atom.to_string(reason),
          step_time: stepped_at,
          observed_time: now(),
          original_deadline: deadline,
          partial_offset: failed.offset
        })
    )

    target_ref = monitors[target]
    remaining = max(fault_deadline - now(), 0)
    assert_receive {:DOWN, ^target_ref, :process, ^target, :normal}, remaining
    assert now() < deadline

    for fd <- [current_fd, queued_fd, native_socket],
        do: assert(Resources.info(fd) == {:error, :closed})

    await(fn ->
      usage = stats()

      not Map.has_key?(usage.peers, target) and idle_credits?(usage) and
        usage.global.connections == 2 and
        NameRegistry.resolve(target_name) == {:error, :name_not_found} and
        NameRegistry.resolve(owned) == {:error, :name_not_found} and
        not MatchRules.has_rules?(target) and :sys.get_state(router).pending.entries == %{}
    end)

    assert Process.whereis(Router) == router
    assert Map.new(Map.keys(authorities), &{&1, Process.whereis(&1)}) == authorities
    continue(actor)

    assert %{
             "event" => "target_closed",
             "partial_bytes" => partial_bytes,
             "frame_bytes" => frame_bytes,
             "rights" => 1,
             "daemon_fds" => cleaned_fds,
             "daemon_memfds" => []
           } = actor_event(actor)

    # SHUT_RD may discard unread bytes; accepted bytes can never exceed the
    # last real writer offset, and no second frame or rights may arrive.
    assert partial_bytes <= failed.offset
    assert frame_bytes == byte_size(current.writer.bytes)
    assert partial_bytes > 0 and partial_bytes < frame_bytes
    assert cleaned_fds == baseline_fds - 2
    health_deadline = now() + @healthy_ms
    continue(actor)

    assert %{"event" => "failed_healthy", "latency_ms" => latency} =
             actor_event(actor, health_deadline)

    assert latency <= @healthy_ms
    assert now() <= health_deadline
    assert resolve(source_name) == source
    assert resolve(observer_name) == observer
    await(fn -> idle_credits?(stats()) end)

    continue(actor)

    assert %{"event" => "closed", "daemon_fds" => final_fds, "daemon_memfds" => []} =
             actor_event(actor)

    assert final_fds == baseline_fds - 6
    assert_receive {^actor, {:exit_status, 0}}, 1000

    for peer <- [source, observer] do
      reference = monitors[peer]
      assert_receive {:DOWN, ^reference, :process, ^peer, :normal}, 1000
    end

    await(fn ->
      usage = stats()

      usage.peers == %{} and usage.uids == %{} and idle_credits?(usage) and
        usage.global.connections == 0 and :ets.info(:gao_bus_match_rules, :size) == 0 and
        :sys.get_state(router).pending.entries == %{}
    end)

    assert NameRegistry.list_names() == ["org.freedesktop.DBus"]
    assert Map.new(Map.keys(authorities), &{&1, Process.whereis(&1)}) == authorities
  end

  defp resolve(name) do
    assert {:ok, peer} = NameRegistry.resolve(name)
    peer
  end

  defp stats do
    assert {:ok, usage} = Limits.snapshot()
    usage
  end

  defp idle_credits?(usage) do
    usage.reservations == 0 and
      Enum.all?([usage.global | Map.values(usage.peers) ++ Map.values(usage.uids)], fn counts ->
        Enum.all?(counts, fn {metric, count} -> metric == :connections or count == 0 end)
      end)
  end

  defp await(check), do: await(check, now() + @cleanup_ms)

  defp await(check, deadline) do
    unless check.() do
      assert now() < deadline, "writer closed fixture barrier deadline"
      await(check, deadline)
    end
  end

  defp writer_error(target, deadline, context, seen) do
    if seen >= 64, do: report_trace(context)
    assert seen < 64, "bounded writer trace rows"
    remaining = max(deadline - now(), 0)

    receive do
      {:trace, ^target, :call, {Writer, :step, [_socket, writer, step_time]}} ->
        context = %{
          context
          | step_time: step_time,
            calls: context.calls + 1,
            rows: [writer_row("call", writer, step_time) | context.rows]
        }

        writer_error(target, deadline, context, seen + 1)

      {:trace, ^target, :return_from, {Writer, :step, 3}, {:wait, writer}} ->
        context = %{
          context
          | step_time: nil,
            waits: context.waits + 1,
            rows: [writer_row("wait", writer, context.step_time) | context.rows]
        }

        writer_error(target, deadline, context, seen + 1)

      {:trace, ^target, :return_from, {Writer, :step, 3}, {:error, reason, writer}} ->
        assert is_integer(context.step_time)
        row = writer_row("error", writer, context.step_time)
        report_trace(%{context | rows: [Map.put(row, :reason, inspect(reason)) | context.rows]})
        failed = Map.put(row, :handles_match, writer.handles == context.expected_handles)
        {reason, failed, context.step_time}

      {:trace, ^target, :return_from, {Writer, :step, 3}, other} ->
        flunk("expected a terminal partial writer error, got #{inspect(other)}")
    after
      remaining ->
        report_trace(context)
        flunk("real writer terminal-error trace deadline")
    end
  end

  defp writer_row(kind, writer, stepped_at) do
    %{
      kind: kind,
      step_time: stepped_at,
      offset: writer.offset,
      deadline: writer.deadline,
      blocked: writer.blocked,
      rights_sent: writer.rights_sent,
      bytes: byte_size(writer.bytes),
      fds: length(writer.handles)
    }
  end

  defp report_trace(context) do
    IO.puts(
      "FD07_WRITER_TRACE " <>
        Jason.encode!(%{
          calls: context.calls,
          waits: context.waits,
          rows: Enum.reverse(context.rows)
        })
    )
  end

  defp continue(actor), do: assert(Port.command(actor, "continue\n"))
  defp actor_event(actor), do: actor_event(actor, now() + 5000)

  defp actor_event(actor, deadline) do
    remaining = max(deadline - now(), 0)

    receive do
      {^actor, {:data, {:eol, line}}} ->
        Jason.decode!(line)

      {^actor, {:exit_status, status}} ->
        flunk("writer closed actor exited with status #{status}")
    after
      remaining -> flunk("writer closed actor deadline")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
