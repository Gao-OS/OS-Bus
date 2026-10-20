defmodule GaoBus.Foundation.PRO05.Resources do
  @moduledoc false

  @core [
    GaoBus.Supervisor,
    GaoBus.Ids,
    GaoBus.PeerRegistry,
    GaoBus.Router,
    GaoBus.NameRegistry,
    GaoBus.Limits,
    GaoBus.Policy,
    GaoBus.MatchRules,
    GaoBus.Policy.Capability,
    GaoBus.PeerSupervisor,
    GaoBus.Listener
  ]
  @process_metrics [:reductions, :memory, :total_heap_size, :stack_size, :message_queue_len]
  @memory_metrics [:total, :processes_used, :binary, :ets, :atom_used]
  @vm_metrics [:reductions, :atom_count, :process_count, :port_count]
  @timeout 1500

  def core do
    Map.new(@core, fn name -> {Atom.to_string(name), identity(Process.whereis(name))} end)
  end

  def capture(source \\ nil, observer \\ nil, budget_ms \\ @timeout) do
    true = is_integer(budget_ms) and budget_ms > 0 and budget_ms <= @timeout
    deadline = System.monotonic_time(:millisecond) + budget_ms
    identities = core()
    authority = read("authority", fn -> authority(identities, deadline) end)

    processes =
      Map.new(@core, fn name ->
        {Atom.to_string(name), process_sample(Process.whereis(name))}
      end)
      |> Map.merge(%{"source" => process_sample(source), "observer" => process_sample(observer)})

    vm =
      read("vm", fn ->
        _ = remaining!(deadline)
        vm_sample()
      end)

    errors =
      authority.errors ++
        vm.errors ++
        Enum.flat_map(processes, fn {name, sample} ->
          if sample.complete, do: [], else: [%{field: name, reason: sample.error}]
        end) ++
        if(Enum.any?(identities, fn {_name, pid} -> is_nil(pid) end),
          do: [%{field: "core", reason: "missing_core_process"}],
          else: []
        ) ++
        if(identities == core(),
          do: [],
          else: [%{field: "core", reason: "identity_changed_during_sample"}]
        ) ++
        if(System.monotonic_time(:millisecond) < deadline,
          do: [],
          else: [%{field: "sample", reason: "capture_deadline"}]
        )

    %{
      complete: errors == [],
      errors: errors,
      authority: authority.value,
      resources: %{
        core: identities,
        processes: processes,
        vm: vm.value,
        complete: errors == []
      }
    }
  end

  def process_sample(nil),
    do: %{status: "absent", pid: nil, metrics: nil, complete: true, error: nil}

  def process_sample(pid) when is_pid(pid) do
    case Process.info(pid, @process_metrics) do
      nil ->
        %{status: "absent", pid: identity(pid), metrics: nil, complete: true, error: nil}

      values ->
        metrics = Map.new(values)

        if valid_metrics?(metrics, @process_metrics) do
          %{status: "live", pid: identity(pid), metrics: metrics, complete: true, error: nil}
        else
          %{
            status: "incomplete",
            pid: identity(pid),
            metrics: nil,
            complete: false,
            error: "incomplete_process_metrics"
          }
        end
    end
  end

  # This projection is pure: synthetic maps suffice to test comparability.
  def process_delta(current, baseline) do
    cond do
      not complete_process?(current) or not complete_process?(baseline) ->
        incomparable(current, "incomplete")

      current.status != "live" ->
        incomparable(current, if(is_nil(current.pid), do: "absent", else: "departed"))

      baseline.status != "live" ->
        incomparable(current, "no_live_baseline")

      current.pid != baseline.pid ->
        incomparable(current, "replaced")

      true ->
        %{
          status: current.status,
          pid: current.pid,
          comparable: true,
          reason: nil,
          metrics: metric_delta(current.metrics, baseline.metrics)
        }
    end
  end

  def delta(sample, baseline) do
    names = Enum.uniq(Map.keys(sample.processes) ++ Map.keys(baseline.processes))

    %{
      processes:
        Map.new(names, fn name ->
          {name,
           process_delta(Map.get(sample.processes, name), Map.get(baseline.processes, name))}
        end),
      vm: vm_delta(sample.vm, baseline.vm)
    }
  end

  def authority_tables(match_rules_state, capability_state, match_rules_rows, capability_rows) do
    %{
      match_rules_state: opaque_term(match_rules_state),
      capability_state: opaque_term(capability_state),
      match_rules_table: table_projection(match_rules_rows),
      capabilities_table: table_projection(capability_rows)
    }
  end

  defp authority(identities, deadline) do
    router_pid = Process.whereis(GaoBus.Router)
    true = is_pid(router_pid)
    router = :sys.get_state(router_pid, remaining!(deadline))
    registry = :sys.get_state(GaoBus.NameRegistry, remaining!(deadline))
    match_rules_state = :sys.get_state(GaoBus.MatchRules, remaining!(deadline))
    capability_state = :sys.get_state(GaoBus.Policy.Capability, remaining!(deadline))
    _ = remaining!(deadline)
    match_rules_rows = :ets.tab2list(:gao_bus_match_rules)
    _ = remaining!(deadline)
    capability_rows = :ets.tab2list(:gao_bus_capabilities)

    tables =
      authority_tables(match_rules_state, capability_state, match_rules_rows, capability_rows)

    {:ok, usage} = GenServer.call(GaoBus.Limits, :snapshot, remaining!(deadline))
    {:ok, _generation, _rules} = policy = GaoBus.Policy.snapshot()

    peers =
      for {pid, info} <- router.peers do
        %{
          name: info.unique_name,
          credentials: info.credentials,
          peer: identity(pid),
          names:
            Enum.sort(
              GenServer.call(GaoBus.NameRegistry, {:names_for, pid}, remaining!(deadline))
            ),
          match_rules: :ets.match(:gao_bus_match_rules, {pid, :_, :_, :_}) != [],
          capabilities: length(:ets.lookup(:gao_bus_capabilities, info.unique_name))
        }
      end

    queues =
      for {name, owner, unique, flags, queue} <- :ets.tab2list(registry.names) do
        %{
          name: name,
          owner: identity(owner),
          unique: unique,
          flags: flags,
          queue:
            for {pid, queued_unique, queued_flags} <- queue do
              %{peer: identity(pid), unique: queued_unique, flags: queued_flags}
            end
        }
      end

    %{
      core: identities,
      router: identity(router_pid),
      peers: Enum.sort_by(peers, & &1.peer),
      names: Enum.sort(GenServer.call(GaoBus.NameRegistry, :list_names, remaining!(deadline))),
      queues: Enum.sort_by(queues, & &1.name),
      usage: %{
        global: usage.global,
        reservations: usage.reservations,
        peers:
          usage.peers
          |> Enum.map(fn {pid, counts} -> %{peer: identity(pid), counts: counts} end)
          |> Enum.sort_by(& &1.peer),
        uids:
          usage.uids
          |> Enum.map(fn {uid, counts} -> %{uid: uid, counts: counts} end)
          |> Enum.sort_by(& &1.uid)
      },
      policy: inspect(policy, limit: :infinity)
    }
    |> Map.merge(tables)
  end

  defp table_projection(rows) do
    rows
    |> Enum.sort_by(&:erlang.term_to_binary(&1, [:deterministic]))
    |> opaque_term()
  end

  defp opaque_term(term),
    do: term |> :erlang.term_to_binary([:deterministic]) |> Base.encode64()

  def loaded_module_names(loaded) do
    loaded
    |> Enum.map(fn {module, _source} -> Atom.to_string(module) end)
    |> Enum.sort()
  end

  defp vm_sample do
    # Diagnostic only: retain the finite loaded-module table, not the atom table.
    loaded_modules = loaded_module_names(:code.all_loaded())

    sample = %{
      identity: System.pid(),
      reductions: elem(:erlang.statistics(:reductions), 0),
      memory: Map.take(Map.new(:erlang.memory()), @memory_metrics),
      atom_count: :erlang.system_info(:atom_count),
      process_count: :erlang.system_info(:process_count),
      port_count: :erlang.system_info(:port_count),
      loaded_modules: loaded_modules
    }

    true = valid_vm?(sample)
    sample
  end

  defp vm_delta(current, baseline) do
    if valid_vm?(current) and valid_vm?(baseline) and current.identity == baseline.identity do
      @vm_metrics
      |> Map.new(fn metric ->
        {metric, Map.fetch!(current, metric) - Map.fetch!(baseline, metric)}
      end)
      |> Map.put(:memory, metric_delta(current.memory, baseline.memory))
      |> Map.put(:loaded_modules_added, current.loaded_modules -- baseline.loaded_modules)
      |> Map.put(:comparable, true)
    else
      nil
    end
  end

  defp complete_process?(%{status: "live", pid: pid, complete: true, metrics: metrics})
       when is_binary(pid),
       do: valid_metrics?(metrics, @process_metrics)

  defp complete_process?(%{status: "absent", pid: pid, complete: true, metrics: nil})
       when is_nil(pid) or is_binary(pid),
       do: true

  defp complete_process?(_sample), do: false

  defp valid_vm?(%{identity: identity, memory: memory} = vm) when is_binary(identity),
    do: valid_metrics?(vm, @vm_metrics) and valid_metrics?(memory, @memory_metrics)

  defp valid_vm?(_sample), do: false

  defp valid_metrics?(metrics, keys) when is_map(metrics),
    do: Enum.all?(keys, &is_integer(Map.get(metrics, &1)))

  defp valid_metrics?(_metrics, _keys), do: false

  defp incomparable(current, reason) do
    %{
      status:
        if(is_map(current), do: Map.get(current, :status, "incomplete"), else: "incomplete"),
      pid: if(is_map(current), do: Map.get(current, :pid), else: nil),
      comparable: false,
      reason: reason,
      metrics: nil
    }
  end

  defp metric_delta(current, baseline),
    do: Map.new(current, fn {key, value} -> {key, value - Map.fetch!(baseline, key)} end)

  defp identity(nil), do: nil
  defp identity(pid), do: inspect(pid)

  defp remaining!(deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    if remaining <= 0, do: raise("resource capture deadline")
    remaining
  end

  defp read(field, reader) do
    %{value: reader.(), errors: []}
  rescue
    error -> %{value: nil, errors: [%{field: field, reason: Exception.message(error)}]}
  catch
    kind, reason -> %{value: nil, errors: [%{field: field, reason: inspect({kind, reason})}]}
  end
end
