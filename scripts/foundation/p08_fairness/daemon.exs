Code.require_file(Path.join(__DIR__, "collector.ex"))
Code.require_file(Path.join(__DIR__, "timing_sampler.ex"))

{socket, diagnostic_no_trace, timing_observer} =
  case System.argv() do
    [socket] -> {socket, false, false}
    [socket, "--diagnostic-no-trace"] -> {socket, true, false}
    [socket, "--diagnostic-timing"] -> {socket, true, true}
  end

"isolated-vm\n" = File.read!("/etc/osbus-security-guest")
true = String.starts_with?(socket, "/run/osbus-fairness/")
identities = [0, 1100, 1101]

rules =
  for uid <- identities,
      action <- [:connect, :own, :send, :receive],
      do: %{action: action, effect: :allow, match: %{uid: uid}}

limits = %{
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
}

settings = [
  socket_path: socket,
  profile: :system,
  cluster: false,
  capability_restrictions: false,
  resource_limits: limits,
  policy_rules: rules,
  max_matches_per_peer: 32,
  max_match_entries: 288,
  pending_call_limits: %{global: 32, per_uid: 24, per_peer: 8, timeout_ms: 5000},
  send_timeout_ms: 5000
]

for {key, value} <- settings, do: Application.put_env(:gao_bus, key, value)
{:ok, _} = Application.ensure_all_started(:gao_bus)
collector = GaoBusFairnessCollector.start()
_ = :crypto.hash(:sha256, "fixture-warm")

unless diagnostic_no_trace do
  :erlang.trace_pattern({GaoBus.Limits, :reserve_egress, 5}, [{:_, [], [{:return_trace}]}], [])
end

trace_flags = if diagnostic_no_trace, do: [], else: [:send, :call]

unless diagnostic_no_trace do
  :erlang.trace(Process.whereis(GaoBus.Router), true, trace_flags ++ [{:tracer, collector}])
end

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

  peers =
    for {pid, info} <- router.peers do
      try do
        state = :sys.get_state(pid)
        {:message_queue_len, mailbox} = Process.info(pid, :message_queue_len)
        output = state.current_output

        %{
          peer: inspect(pid),
          name: info.unique_name,
          mailbox: mailbox,
          queue: :queue.len(state.output_queue),
          buffer_bytes: byte_size(state.buffer),
          current_output:
            if(output,
              do: %{
                offset: output.writer.offset,
                bytes: byte_size(output.writer.bytes),
                blocked: output.writer.blocked
              },
              else: nil
            )
        }
      catch
        :exit, reason -> %{peer: inspect(pid), name: info.unique_name, departed: inspect(reason)}
      end
    end

  if gc do
    Enum.each(authorities, &:erlang.garbage_collect(Process.whereis(&1)))
    Enum.each(Map.keys(router.peers), &:erlang.garbage_collect/1)
  end

  %{
    event: "snapshot",
    pid: System.pid(),
    peers: peers,
    authorities: Map.new(authorities, &{inspect(&1), inspect(Process.whereis(&1))}),
    names: Enum.sort(GaoBus.NameRegistry.list_names()),
    matches: :ets.info(:gao_bus_match_rules, :size),
    capabilities: :ets.info(:gao_bus_capabilities, :size),
    usage: %{
      global: usage.global,
      uids: Map.new(usage.uids, fn {uid, counts} -> {to_string(uid), counts} end),
      reservations: usage.reservations,
      peers: map_size(usage.peers)
    },
    pending: map_size(router.pending.entries),
    pending_entries:
      Enum.map(router.pending.entries, fn {{caller, serial}, value} ->
        %{caller: inspect(caller), serial: serial, callee: inspect(value.callee)}
      end),
    router_mailbox: elem(Process.info(Process.whereis(GaoBus.Router), :message_queue_len), 1),
    atoms: :erlang.system_info(:atom_count),
    processes: :erlang.system_info(:process_count),
    ports: :erlang.system_info(:port_count),
    memory: :erlang.memory(:total)
  }
end

quiet = fn loop, deadline ->
  state = snapshot.(false)

  settled =
    state.pending == 0 and state.usage.reservations == 0 and
      Enum.all?(state.usage.global, fn {key, value} -> key == :connections or value == 0 end)

  cond do
    settled ->
      state

    System.monotonic_time(:millisecond) >= deadline ->
      raise "quiescence deadline #{inspect(state)}"

    true ->
      loop.(loop, deadline)
  end
end

emit.(%{
  event: "ready",
  pid: System.pid(),
  settings: inspect(settings, limit: :infinity),
  diagnostic_no_trace: diagnostic_no_trace,
  trace_flags: inspect(trace_flags)
})

Stream.repeatedly(fn -> IO.read(:stdio, :line) end)
|> Enum.reduce_while(nil, fn
  :eof, sampler ->
    if sampler, do: GaoBusFairnessTimingSampler.stop(sampler)
    {:halt, nil}

  line, sampler ->
    next_sampler =
      case String.trim(line) do
        "timing-start" when timing_observer ->
          router = :sys.get_state(GaoBus.Router)

          targets =
            [
              {Process.whereis(GaoBus.Router), "Router"},
              {Process.whereis(GaoBus.Limits), "Limits"},
              {Process.whereis(GaoBus.NameRegistry), "NameRegistry"}
            ] ++
              Enum.map(router.peers, fn {pid, info} -> {pid, info.unique_name} end)

          pid =
            GaoBusFairnessTimingSampler.start(
              Path.join(Path.dirname(socket), "timing-sampler.jsonl"),
              targets
            )

          emit.(%{event: "timing_started", sampler: inspect(pid), targets: length(targets)})
          pid

        "timing-stop" when timing_observer ->
          emit.(GaoBusFairnessTimingSampler.stop(sampler))
          nil

        "inspect" ->
          emit.(snapshot.(false))
          sampler

        "metrics" ->
          _ = quiet.(quiet, System.monotonic_time(:millisecond) + 3000)
          emit.(snapshot.(true))

        "trace" ->
          _ = :sys.get_state(GaoBus.Router)
          ref = :erlang.trace_delivered(Process.whereis(GaoBus.Router))

          receive do
            {:trace_delivered, _pid, ^ref} -> :ok
          after
            3000 -> raise "trace delivery deadline"
          end

          emit.(GaoBusFairnessCollector.snapshot(collector))

        "stall " <> name ->
          {:ok, peer} = GaoBus.NameRegistry.resolve(name)
          :ok = :socket.setopt(:sys.get_state(peer).socket, :socket, :sndbuf, 1024)
          emit.(%{event: "stalled", peer: inspect(peer), name: name})

        "kill " <> name ->
          {:ok, peer} = GaoBus.NameRegistry.resolve(name)
          :ok = GaoBus.Policy.Capability.grant(name, {:own, "org.foundation.Victim"})
          before = snapshot.(false)
          ref = Process.monitor(peer)
          Process.exit(peer, :kill)

          receive do
            {:DOWN, ^ref, :process, ^peer, :killed} -> :ok
          after
            3000 -> raise "victim DOWN deadline"
          end

          deadline = System.monotonic_time(:millisecond) + 3000

          await = fn await ->
            state = snapshot.(false)

            if Enum.any?(state.peers, &(&1.peer == inspect(peer))) or state.capabilities != 0 or
                 "org.foundation.Victim" in state.names or state.matches != 256 or
                 state.usage.global.connections != 11 do
              if System.monotonic_time(:millisecond) >= deadline,
                do: raise("victim cleanup deadline")

              await.(await)
            else
              state
            end
          end

          after_state = await.(await)

          emit.(%{
            event: "killed",
            peer: inspect(peer),
            monitor: "DOWN:killed",
            before: before,
            after: after_state
          })

        other ->
          raise "unknown fixture command #{inspect(other)}"
      end

    retained =
      if String.trim(line) in ["timing-start", "timing-stop"], do: next_sampler, else: sampler

    {:cont, retained}
end)

:erlang.trace(Process.whereis(GaoBus.Router), false, [:send, :call])
:erlang.trace_pattern({GaoBus.Limits, :reserve_egress, 5}, false, [])
send(collector, :stop)
:ok = Application.stop(:gao_bus)
