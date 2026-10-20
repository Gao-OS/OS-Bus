defmodule GaoBus.PeerWriterExpiryTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, MatchRules, NameRegistry, Router}
  alias GaoBus.Unix.{Native, Resources}

  @moduletag timeout: 20_000
  @actor Path.expand("fixtures/peer_writer_expiry_actor.py", __DIR__)
  @write_ms 5000
  @healthy_ms 1000
  @cleanup_ms 1000

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(System.tmp_dir!(), "gb-expiry-#{System.unique_integer([:positive])}")
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

    start_supervised!(%{id: :expiry_bus, start: {GaoBus.Application, :start, [:normal, []]}})
    %{path: path, uid: uid}
  end

  test "FD-07 a real blocked Peer writer expires at its absolute deadline and retires every resource",
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

    # The actor keeps the recipient open and unread. No synthetic clock,
    # injected expiry, process kill, or explicit stop causes this DOWN.
    assert now() < deadline
    target_ref = monitors[target]
    remaining = max(deadline + @cleanup_ms - now(), 0)
    assert_receive {:DOWN, ^target_ref, :process, ^target, :normal}, remaining
    assert now() >= deadline
    assert now() <= deadline + @cleanup_ms

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
    continue(actor)

    assert %{
             "event" => "target_closed",
             "partial_bytes" => partial_bytes,
             "frame_bytes" => frame_bytes,
             "rights" => 1,
             "daemon_fds" => cleaned_fds,
             "daemon_memfds" => []
           } = actor_event(actor)

    assert partial_bytes == current.writer.offset
    assert frame_bytes == byte_size(current.writer.bytes)
    assert partial_bytes > 0 and partial_bytes < frame_bytes
    assert cleaned_fds == baseline_fds - 2
    health_deadline = now() + @healthy_ms
    continue(actor)

    assert %{"event" => "expired_healthy", "latency_ms" => latency} =
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
      assert now() < deadline, "writer expiry fixture barrier deadline"
      await(check, deadline)
    end
  end

  defp continue(actor), do: assert(Port.command(actor, "continue\n"))
  defp actor_event(actor), do: actor_event(actor, now() + 5000)

  defp actor_event(actor, deadline) do
    remaining = max(deadline - now(), 0)

    receive do
      {^actor, {:data, {:eol, line}}} ->
        Jason.decode!(line)

      {^actor, {:exit_status, status}} ->
        flunk("writer expiry actor exited with status #{status}")
    after
      remaining -> flunk("writer expiry actor deadline")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
