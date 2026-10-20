# Guest-only root-owned inspection channel; never a production protocol API.
[socket, policy] = System.argv()
"isolated-vm\n" = File.read!("/etc/osbus-security-guest")
true = String.starts_with?(socket, "/run/osbus-p08/")

limits = %{
  global: %{
    connections: 8,
    ingress_messages: 128,
    ingress_bytes: 1_048_576,
    ingress_fds: 64,
    egress_messages: 128,
    egress_bytes: 1_048_576,
    egress_fds: 64
  },
  uid: %{connections: 8},
  peer: %{
    ingress_messages: 16,
    ingress_bytes: 262_144,
    ingress_fds: 16,
    egress_messages: 16,
    egress_bytes: 262_144,
    egress_fds: 16
  }
}

settings = [
  socket_path: socket,
  profile: :system,
  cluster: false,
  capability_restrictions: false,
  resource_limits: limits,
  max_names_per_peer: 4,
  max_name_entries: 32,
  max_matches_per_peer: 4,
  max_match_entries: 32,
  pending_call_limits: %{global: 16, per_uid: 8, per_peer: 4, timeout_ms: 100},
  policy_rules: elem(Code.eval_file(policy), 0)
]

for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)
{:ok, _} = Application.ensure_all_started(:gao_bus)
emit = fn value -> IO.puts("FIXTURE " <> IO.iodata_to_binary(:json.encode(value))) end

snapshot = fn gc ->
  router = :sys.get_state(GaoBus.Router)
  _ = :sys.get_state(GaoBus.NameRegistry)
  _ = :sys.get_state(GaoBus.MatchRules)
  _ = :sys.get_state(GaoBus.Policy.Capability)
  {:ok, usage} = GaoBus.Limits.snapshot()

  authorities = [
    GaoBus.Supervisor,
    GaoBus.Ids,
    GaoBus.NameRegistry,
    GaoBus.MatchRules,
    GaoBus.Policy,
    GaoBus.Policy.Capability,
    GaoBus.Limits,
    GaoBus.Router,
    GaoBus.Listener
  ]

  if gc, do: Enum.each(authorities, &:erlang.garbage_collect(Process.whereis(&1)))

  %{
    event: "snapshot",
    pid: System.pid(),
    authorities: Map.new(authorities, &{inspect(&1), inspect(Process.whereis(&1))}),
    peers:
      Enum.map(router.peers, fn {pid, info} -> %{peer: inspect(pid), name: info.unique_name} end),
    usage: %{global: usage.global, reservations: usage.reservations, peers: map_size(usage.peers)},
    pending: map_size(router.pending.entries),
    names: Enum.sort(GaoBus.NameRegistry.list_names()),
    matches: :ets.info(:gao_bus_match_rules, :size),
    capabilities: :ets.info(:gao_bus_capabilities, :size),
    processes: :erlang.system_info(:process_count),
    ports: :erlang.system_info(:port_count),
    atoms: :erlang.system_info(:atom_count),
    memory: :erlang.memory(:total),
    queues:
      Map.new(authorities, fn name ->
        {:message_queue_len, count} = Process.info(Process.whereis(name), :message_queue_len)
        {inspect(name), count}
      end)
  }
end

quiet = fn loop, deadline ->
  state = snapshot.(false)

  settled =
    state.usage.reservations == 0 and state.pending == 0 and
      state.usage.global.connections == length(state.peers) and
      Enum.all?(state.usage.global, fn {key, value} -> key == :connections or value == 0 end)

  cond do
    settled ->
      state

    System.monotonic_time(:millisecond) >= deadline ->
      raise "P08 quiescence deadline #{inspect(state)}"

    true ->
      loop.(loop, deadline)
  end
end

emit.(%{event: "ready", pid: System.pid(), settings: inspect(settings, limit: :infinity)})

Stream.repeatedly(fn -> IO.read(:stdio, :line) end)
|> Enum.reduce_while(nil, fn
  :eof, _ ->
    {:halt, nil}

  line, _ ->
    case String.trim(line) do
      "snapshot" ->
        emit.(snapshot.(false))

      "quiescent" ->
        emit.(quiet.(quiet, System.monotonic_time(:millisecond) + 3000))

      "metrics" ->
        _ = quiet.(quiet, System.monotonic_time(:millisecond) + 3000)
        emit.(snapshot.(true))

      "kill " <> name ->
        {:ok, peer} = GaoBus.NameRegistry.resolve(name)
        :ok = GaoBus.Policy.Capability.grant(name, {:own, "org.foundation.Service.KillGrant"})
        before = snapshot.(false)
        ref = Process.monitor(peer)
        Process.exit(peer, :kill)

        receive do
          {:DOWN, ^ref, :process, ^peer, :killed} -> :ok
        after
          3000 -> raise "killed Peer DOWN deadline"
        end

        state = quiet.(quiet, System.monotonic_time(:millisecond) + 3000)
        false = Enum.any?(state.peers, &(&1.peer == inspect(peer)))
        :ok = GaoBus.Router.unregister_peer(peer)
        :ok = GaoBus.Router.unregister_peer(peer)

        emit.(%{
          event: "killed",
          peer: inspect(peer),
          monitor: "DOWN:killed",
          before: before,
          snapshot: state
        })

      other ->
        raise "unknown fixture command #{inspect(other)}"
    end

    {:cont, nil}
end)

:ok = Application.stop(:gao_bus)
