defmodule GaoBus.RouterFairnessTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Limits, NameRegistry}

  @moduletag timeout: 30_000
  @actor Path.expand("fixtures/router_fairness_actor.py", __DIR__)
  @healthy_ms 1000

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(System.tmp_dir!(), "gb-fairness-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    uid = GaoBus.Unix.Native.identity().uid

    settings = [
      socket_path: path,
      config_file: nil,
      profile: :session,
      cluster: false,
      capability_restrictions: false,
      resource_limits: %{
        global: %{
          connections: 24,
          ingress_bytes: 16_777_216,
          ingress_messages: 256,
          egress_bytes: 4_194_304,
          egress_messages: 256
        },
        uid: %{
          connections: 16,
          ingress_bytes: 16_777_216,
          ingress_messages: 192,
          egress_bytes: 2_097_152,
          egress_messages: 128
        },
        peer: %{
          ingress_bytes: 8_388_608,
          ingress_messages: 96,
          egress_bytes: 262_144,
          egress_messages: 8
        }
      },
      policy_rules:
        Enum.map([:connect, :own, :send, :receive], fn action ->
          %{action: action, effect: :allow, match: %{uid: uid}}
        end),
      max_matches_per_peer: 32,
      max_match_entries: 288,
      pending_call_limits: %{global: 32, per_uid: 24, per_peer: 8, timeout_ms: 5000},
      send_timeout_ms: 5000
    ]

    previous =
      Enum.map(settings, fn {key, _value} -> {key, Application.fetch_env(:gao_bus, key)} end)

    for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, saved} -> Application.put_env(:gao_bus, key, saved)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end

      File.rm_rf!(directory)
    end)

    start_supervised!(%{id: :fairness_bus, start: {GaoBus.Application, :start, [:normal, []]}})
    %{path: path, uid: uid}
  end

  test "one outstanding route per Peer serves healthy wire traffic within 1000ms during 128 broadcasts",
       ctx do
    python = System.find_executable("python3") || flunk("required Python actor unavailable")

    actor =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 16_384},
        args: ["-B", @actor, ctx.path]
      ])

    on_exit(fn -> if Port.info(actor), do: Port.close(actor) end)

    assert %{
             "event" => "ready",
             "producers" => producers,
             "receivers" => receivers,
             "observer" => observer,
             "uid" => uid
           } = actor_event(actor)

    assert uid == ctx.uid
    assert length(producers) == 2 and length(receivers) == 8
    peers = Map.new(producers ++ receivers ++ [observer], &{&1, resolve(&1)})
    monitors = Map.new(peers, fn {_name, pid} -> {pid, Process.monitor(pid)} end)
    await(fn -> idle_credits?(stats()) end)
    assert :ets.info(:gao_bus_match_rules, :size) == 256

    stalled = peers[Enum.at(receivers, 7)]
    assert :ok = :socket.setopt(:sys.get_state(stalled).socket, :socket, :sndbuf, 1024)
    router = Process.whereis(GaoBus.Router)

    # Calls remain pending after their output credits retire. Real callee
    # receipt and zero-credit fences keep preparation independent of reader
    # scheduling, while retaining the original eight-message egress cap.
    for batch <- 0..1 do
      continue(actor)
      expected = (batch + 1) * 8

      assert %{"event" => "held_batch", "batch" => ^batch, "received" => ^expected} =
               actor_event(actor)

      await(fn -> idle_credits?(stats()) end)
      assert map_size(:sys.get_state(router).pending.entries) == expected
    end

    assert map_size(:sys.get_state(router).pending.entries) == 16
    assert :ok = :sys.suspend(router)

    on_exit(fn ->
      try do
        :sys.resume(router)
      catch
        :exit, _reason -> :ok
      end
    end)

    continue(actor)
    assert %{"event" => "load_started", "broadcasts" => 128, "calls" => 16} = actor_event(actor)

    # Producer writers may block legitimately while Router is suspended. Fence
    # the callbacks after both real promotions, without waiting for sendall.
    await(fn ->
      usage = stats()
      Enum.all?(producers, &(usage.peers[peers[&1]].ingress_messages > 0))
    end)

    for name <- producers, do: :sys.get_state(peers[name])
    usage = stats()
    assert Enum.all?(producers, &(usage.peers[peers[&1]].ingress_messages == 1))
    assert usage.global.ingress_messages == 2
    assert Enum.sort(route_peers(router)) == Enum.sort(Enum.map(producers, &peers[&1]))

    continue(actor)
    assert %{"event" => "health_queued"} = actor_event(actor)
    await(fn -> stats().peers[peers[observer]].ingress_messages == 1 end)
    _ = :sys.get_state(peers[observer])
    for name <- producers, do: :sys.get_state(peers[name])
    usage = stats()
    assert Enum.all?(producers ++ [observer], &(usage.peers[peers[&1]].ingress_messages == 1))
    assert usage.global.ingress_messages == 3

    assert Enum.sort(route_peers(router)) ==
             Enum.sort(Enum.map(producers ++ [observer], &peers[&1]))

    # This controlled test measures from resume, excluding artificial suspension.
    # The independent VM's concurrent, real-UID deadline remains a separate gate.
    started = System.monotonic_time(:millisecond)
    deadline = started + @healthy_ms
    assert :ok = :sys.resume(router)
    continue(actor)
    assert %{"event" => "healthy", "latency_ms" => latency} = actor_event(actor, deadline)
    assert latency <= @healthy_ms
    assert System.monotonic_time(:millisecond) <= deadline

    continue(actor)
    assert %{"event" => "loaded", "broadcasts" => 128, "calls" => 16} = actor_event(actor)

    await(fn -> blocked_output?(stalled) end)
    assert map_size(:sys.get_state(router).pending.entries) == 16
    assert stats().global.ingress_messages == 0
    assert stats().global.egress_bytes <= 4_194_304
    assert stats().uids[uid].egress_bytes <= 2_097_152

    continue(actor)

    assert %{"event" => "postbarrier_healthy", "latency_ms" => post_latency} = actor_event(actor)
    assert post_latency <= @healthy_ms
    assert blocked_output?(stalled)
    assert map_size(:sys.get_state(router).pending.entries) == 16

    continue(actor)
    assert %{"event" => "draining"} = actor_event(actor)
    await(fn -> idle_credits?(stats()) end)
    for name <- receivers, do: :sys.get_state(peers[name])
    continue(actor)

    assert %{
             "event" => "drained",
             "broadcasts" => 128,
             "observed" => observed,
             "held_calls" => 16,
             "replies" => 16,
             "complete_admission_proof" => "NOT_MEASURED"
           } = actor_event(actor)

    assert length(observed) == 8 and Enum.all?(observed, &(&1 in 1..128))
    await(fn -> idle_credits?(stats()) and :sys.get_state(router).pending.entries == %{} end)
    continue(actor)
    assert %{"event" => "closed"} = actor_event(actor)
    assert_receive {^actor, {:exit_status, 0}}, 5000

    for {pid, reference} <- monitors do
      assert_receive {:DOWN, ^reference, :process, ^pid, :normal}, 5000
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
    assert {:ok, pid} = NameRegistry.resolve(name)
    pid
  end

  defp route_peers(router) do
    assert {:messages, messages} = Process.info(router, :messages)

    for {:"$gen_cast", {kind, _message, peer, _token, _bytes}} <- messages,
        kind in [:route, :route_frame],
        do: peer
  end

  defp blocked_output?(pid) do
    state = :sys.get_state(pid)

    case state.current_output do
      %{writer: %{blocked: true, offset: offset, bytes: bytes}} ->
        offset > 0 and offset < byte_size(bytes) and :queue.len(state.output_queue) > 0

      _ ->
        false
    end
  end

  defp stats do
    assert {:ok, usage} = Limits.snapshot()
    usage
  end

  defp idle_credits?(usage) do
    usage.reservations == 0 and
      Enum.all?(usage.global, fn {metric, count} -> metric == :connections or count == 0 end)
  end

  defp await(check), do: await(check, System.monotonic_time(:millisecond) + 3000)

  defp await(check, deadline) do
    unless check.() do
      assert System.monotonic_time(:millisecond) < deadline, "fairness fixture barrier deadline"
      await(check, deadline)
    end
  end

  defp continue(actor), do: assert(Port.command(actor, "continue\n"))

  defp actor_event(actor), do: actor_event(actor, System.monotonic_time(:millisecond) + 10_000)

  defp actor_event(actor, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^actor, {:data, {:eol, line}}} -> Jason.decode!(line)
      {^actor, {:exit_status, status}} -> flunk("fairness actor exited with status #{status}")
    after
      remaining -> flunk("fairness actor deadline; healthy response budget is #{@healthy_ms}ms")
    end
  end
end
