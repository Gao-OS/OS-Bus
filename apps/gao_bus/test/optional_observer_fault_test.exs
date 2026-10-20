defmodule GaoBus.OptionalObserverFaultTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Ids, Limits, NameRegistry, Policy, Router}

  @actor Path.expand("fixtures/optional_observer_fault_actor.py", __DIR__)
  @healthy_ms 1000
  @metrics ~w(connections authenticating ingress_messages ingress_bytes ingress_fds egress_messages egress_bytes egress_fds frame_bytes frame_fds activation_messages activation_bytes activation_fds)a
  @source "org.foundation.OptionalSource"
  @healthy "org.foundation.OptionalHealthy"
  @transient "org.foundation.OptionalTransient"

  setup do
    refute Process.whereis(GaoBus.Supervisor)
    refute Process.whereis(GaoBusWeb.PubSub)
    refute Process.whereis(GaoBusWeb.PubSub.Supervisor)
    {:ok, _} = Application.ensure_all_started(:crypto)
    {:ok, _} = Application.ensure_all_started(:phoenix_pubsub)
    directory = Path.join(System.tmp_dir!(), "gb-optional-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    uid = GaoBus.Unix.Native.identity().uid

    settings = [
      socket_path: path,
      profile: :session,
      lifecycle: :embedded,
      inherited_listener: false,
      config_file: nil,
      cluster: false,
      pubsub_name: GaoBusWeb.PubSub,
      capability_restrictions: false,
      resource_limits: %{},
      policy_rules:
        Enum.map([:connect, :own, :send, :receive], fn action ->
          %{action: action, effect: :allow, match: %{uid: uid}}
        end)
    ]

    previous = Enum.map(settings, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
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

    pubsub = start_supervised!({Phoenix.PubSub, name: GaoBusWeb.PubSub}, restart: :temporary)
    {:links, links_before} = Process.info(self(), :links)
    :ok = GaoBus.PubSub.subscribe()
    {:links, links_after} = Process.info(self(), :links)

    supervisor =
      start_supervised!(%{
        id: :optional_fault_bus,
        start: {GaoBus.Application, :start, [:normal, []]},
        type: :supervisor,
        restart: :temporary
      })

    assert Bitwise.band(File.stat!(directory).mode, 0o777) == 0o700
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600

    %{
      path: path,
      uid: uid,
      pubsub: pubsub,
      supervisor: supervisor,
      subscriber_links: links_after -- links_before
    }
  end

  @tag :capture_log
  test "FAIL-04 a real optional observer outage preserves independent traffic and authority",
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
    ready = event(actor)
    assert %{"event" => "ready", "source" => source, "healthy" => healthy} = ready
    assert ready["uid"] == ctx.uid
    assert ready["guid"] == Ids.auth_guid()
    assert ready["bus_id"] == Ids.bus_id()
    assert_receive {:name_acquired, @source, ^source}, 1000
    assert_receive {:name_acquired, @healthy, ^healthy}, 1000
    assert Process.whereis(GaoBusWeb.PubSub.Supervisor) == ctx.pubsub
    assert is_pid(Process.whereis(GaoBusWeb.PubSub))
    assert {:ok, source_peer} = NameRegistry.resolve(source)
    assert {:ok, healthy_peer} = NameRegistry.resolve(healthy)
    peers = [source_peer, healthy_peer]
    peer_monitors = Enum.map(peers, &{&1, Process.monitor(&1)})
    for peer <- peers, do: assert(:sys.get_state(peer).credentials.pid == ready["pid"])
    :ok = Policy.Capability.grant(healthy, {:own, @healthy})
    await(fn -> drained?(stats()) end)
    baseline = stats()
    assert_metrics(baseline)
    names = Enum.sort(NameRegistry.list_names())
    matches = :ets.tab2list(:gao_bus_match_rules)
    capabilities = :ets.tab2list(:gao_bus_capabilities)
    policy = Policy.snapshot()
    identity = Map.new(peers, &{&1, peer_identity(&1)})
    core = Map.new(Supervisor.which_children(ctx.supervisor), fn {id, pid, _, _} -> {id, pid} end)
    core_monitors = Enum.map([ctx.supervisor | Map.values(core)], &{&1, Process.monitor(&1)})
    backend = tree(ctx.pubsub)
    backend_monitors = Enum.map(backend, &{&1, Process.monitor(&1)})
    root_ref = Map.new(backend_monitors)[ctx.pubsub]
    router = core[Router]

    record("baseline", %{
      limits: baseline,
      core: core,
      peers: peers,
      backend: backend,
      policy: policy
    })

    assert :ok = :sys.suspend(router)

    on_exit(fn ->
      try do
        :sys.resume(router)
      catch
        :exit, _ -> :ok
      end
    end)

    continue(actor)
    assert %{"event" => "submitted", "health_serial" => 20, "source_serial" => 20} = event(actor)

    await(fn ->
      usage = stats()
      Enum.all?(peers, &(usage.peers[&1].ingress_messages == 1))
    end)

    for peer <- peers, do: :sys.get_state(peer)
    assert Enum.sort(route_peers(router)) == Enum.sort(peers)
    assert [partition] = ctx.subscriber_links
    assert partition in backend
    previous_trap_exit = Process.flag(:trap_exit, true)

    try do
      Process.exit(ctx.pubsub, :kill)
      assert_receive {:DOWN, ^root_ref, :process, pid, :killed} when pid == ctx.pubsub, 1000

      for {pid, reference} <- backend_monitors, pid != ctx.pubsub do
        assert_receive {:DOWN, ^reference, :process, ^pid, _reason}, 1000
      end

      assert_receive {:EXIT, ^partition, :shutdown}, 1000
      refute_received {:EXIT, _, _}
      record("subscriber-exit", %{partition: partition, backend: backend, reason: :shutdown})
    after
      Process.flag(:trap_exit, previous_trap_exit)
    end

    assert Process.whereis(GaoBusWeb.PubSub) == nil
    assert Process.whereis(GaoBusWeb.PubSub.Supervisor) == nil
    assert :ok = :sys.resume(router)
    continue(actor)
    result = event(actor)
    assert %{"event" => "drained", "reconnects" => 0} = result

    assert result["counts"] == %{
             "health" => 4,
             "transient_acquired" => 1,
             "transient_released" => 1
           }

    assert length(result["health_ms"]) == 4
    assert Enum.all?(result["health_ms"], &(&1 <= @healthy_ms))
    assert result["source"] == source and result["healthy"] == healthy
    assert result["guid"] == Ids.auth_guid() and result["bus_id"] == Ids.bus_id()
    await(fn -> drained?(stats()) end)
    assert stats() == baseline
    assert Enum.sort(NameRegistry.list_names()) == names
    assert {:ok, source} == NameRegistry.get_name_owner(@source)
    assert {:ok, healthy} == NameRegistry.get_name_owner(@healthy)
    assert {:error, :name_not_found} == NameRegistry.resolve(@transient)
    assert :ets.tab2list(:gao_bus_match_rules) == matches
    assert :ets.tab2list(:gao_bus_capabilities) == capabilities
    assert Policy.snapshot() == policy
    assert Map.new(peers, &{&1, peer_identity(&1)}) == identity

    assert Map.new(Supervisor.which_children(ctx.supervisor), fn {id, pid, _, _} -> {id, pid} end) ==
             core

    assert Process.whereis(GaoBus.Supervisor) == ctx.supervisor
    assert Process.whereis(GaoBusWeb.PubSub) == nil
    assert Process.whereis(GaoBusWeb.PubSub.Supervisor) == nil
    assert :sys.get_state(router).pending.entries == %{}

    for {pid, reference} <- core_monitors ++ peer_monitors do
      refute_received {:DOWN, ^reference, :process, ^pid, _}
    end

    record("outage", %{limits: stats(), core: core, actor: result, backend_down: length(backend)})
    continue(actor)
    assert %{"event" => "closed", "clients" => 2} = event(actor)
    assert_receive {^actor, {:exit_status, 0}}, 5000

    for {pid, reference} <- peer_monitors do
      assert_receive {:DOWN, ^reference, :process, ^pid, :normal}, 3000
    end

    await(fn -> stats().peers == %{} and stats().uids == %{} and drained?(stats()) end)
    final = stats()
    assert_metrics(final)
    assert Enum.all?(final.global, fn {_, value} -> value == 0 end)
    assert final.xml.global == baseline.xml.global
    assert final.xml.uids == %{}
    assert NameRegistry.list_names() == ["org.freedesktop.DBus"]
    assert :ets.tab2list(:gao_bus_match_rules) == []
    assert :ets.tab2list(:gao_bus_capabilities) == []
    assert :sys.get_state(router).peers == %{}
    assert :sys.get_state(router).pending.entries == %{}
    record("final", %{limits: final, selected: 1, executed: 1, passed: 1})
    assert :ok = stop_supervised(:optional_fault_bus)
    refute File.exists?(ctx.path)
    assert Process.whereis(GaoBus.Supervisor) == nil
  end

  defp peer_identity(pid) do
    state = :sys.get_state(pid)
    {state.unique_name, state.credentials, state.socket}
  end

  defp tree(pid) do
    [
      pid
      | Enum.flat_map(Supervisor.which_children(pid), fn
          {_id, child, :supervisor, _} when is_pid(child) -> tree(child)
          {_id, child, :worker, _} when is_pid(child) -> [child]
        end)
    ]
  end

  defp stats do
    assert {:ok, usage} = Limits.snapshot()
    usage
  end

  defp assert_metrics(usage) do
    for counts <- [usage.global | Map.values(usage.uids) ++ Map.values(usage.peers)] do
      assert Enum.sort(Map.keys(counts)) == Enum.sort(@metrics)
    end

    assert Map.keys(usage.xml) |> Enum.sort() == [:global, :limits, :queues, :uids]
  end

  defp drained?(usage) do
    usage.reservations == 0 and usage.reload_reservations == 0 and
      Enum.all?(usage.global, fn {metric, value} -> metric == :connections or value == 0 end)
  end

  defp route_peers(router) do
    assert {:messages, messages} = Process.info(router, :messages)

    for {:"$gen_cast", {kind, _message, peer, _token, _bytes}} <- messages,
        kind in [:route, :route_frame],
        do: peer
  end

  defp await(check), do: await(check, System.monotonic_time(:millisecond) + 1000)

  defp await(check, deadline) do
    unless check.() do
      assert System.monotonic_time(:millisecond) < deadline, "optional observer barrier deadline"
      await(check, deadline)
    end
  end

  defp continue(actor), do: assert(Port.command(actor, "continue\n"))

  defp event(actor) do
    assert_receive {^actor, {:data, {:eol, line}}}, 5000
    record("actor", line)
    Jason.decode!(line)
  end

  defp record(stage, value) do
    if directory = System.get_env("P08_OPTIONAL_EVIDENCE") do
      File.write!(
        Path.join(directory, stage <> ".log"),
        inspect(value, limit: :infinity) <> "\n",
        [:append]
      )
    end
  end
end
