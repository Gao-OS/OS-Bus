Code.require_file(Path.join(__DIR__, "resource_probe.exs"))
ExUnit.start()

defmodule GaoBus.Foundation.PRO05.ResourcesTest do
  use ExUnit.Case, async: true

  alias GaoBus.Foundation.PRO05.Resources

  @metrics %{
    reductions: 100,
    memory: 200,
    total_heap_size: 30,
    stack_size: 4,
    message_queue_len: 0
  }

  test "only a complete live sample of the same PID has process deltas" do
    before = live("peer-1", @metrics)

    after_sample =
      live("peer-1", %{
        reductions: 125,
        memory: 180,
        total_heap_size: 30,
        stack_size: 5,
        message_queue_len: 2
      })

    assert %{
             comparable: true,
             reason: nil,
             metrics: %{
               reductions: 25,
               memory: -20,
               total_heap_size: 0,
               stack_size: 1,
               message_queue_len: 2
             }
           } = Resources.process_delta(after_sample, before)
  end

  test "absent baseline retains raw new-incarnation counters without inventing deltas" do
    current = live("peer-2", @metrics)

    assert %{comparable: false, reason: "no_live_baseline", metrics: nil} =
             Resources.process_delta(current, absent(nil))

    assert current.metrics == @metrics
  end

  test "departed process has no final reductions or fabricated zero metrics" do
    assert %{status: "absent", pid: "peer-1", comparable: false, reason: "departed", metrics: nil} =
             Resources.process_delta(absent("peer-1"), live("peer-1", @metrics))

    assert %{comparable: false, reason: "absent", metrics: nil} =
             Resources.process_delta(absent(nil), absent(nil))
  end

  test "a replacement PID is incomparable even when its metrics happen to match" do
    assert %{comparable: false, reason: "replaced", metrics: nil} =
             Resources.process_delta(live("replacement", @metrics), live("original", @metrics))
  end

  test "incomplete reads and missing endpoints remain explicit and incomparable" do
    incomplete = %{status: "incomplete", pid: "peer-1", metrics: nil, complete: false}

    assert %{status: "incomplete", comparable: false, reason: "incomplete", metrics: nil} =
             Resources.process_delta(incomplete, live("peer-1", @metrics))

    assert %{comparable: false, reason: "incomplete", metrics: nil} =
             Resources.process_delta(nil, live("peer-1", @metrics))

    partial = live("peer-1", Map.delete(@metrics, :reductions))

    assert %{comparable: false, reason: "incomplete", metrics: nil} =
             Resources.process_delta(partial, live("peer-1", @metrics))
  end

  test "resource projection keeps per-role process comparability and raw VM endpoint deltas" do
    baseline = %{
      processes: %{"source" => absent(nil), "observer" => live("observer", @metrics)},
      vm: vm("guest-1", 1000, 20_000)
    }

    current = %{
      processes: %{
        "source" => live("source-1", @metrics),
        "observer" => live("observer", @metrics)
      },
      vm: vm("guest-1", 1050, 19_000)
    }

    delta = Resources.delta(current, baseline)
    assert %{metrics: nil, comparable: false} = delta.processes["source"]
    assert %{metrics: %{reductions: 0}, comparable: true} = delta.processes["observer"]
    assert %{comparable: true, reductions: 50, memory: %{total: -1000}} = delta.vm
    assert current.processes["source"].metrics == @metrics
  end

  test "missing or replaced VM endpoints never become zero deltas" do
    baseline = %{processes: %{}, vm: vm("guest-1", 100, 200)}
    assert %{vm: nil} = Resources.delta(%{processes: %{}, vm: nil}, baseline)
    assert %{vm: nil} = Resources.delta(%{processes: %{}, vm: vm("guest-2", 100, 200)}, baseline)
  end

  test "loaded module projection retains deterministic names without source paths" do
    loaded = [
      {Inspect.Tuple, ~c"/runtime/inspect.beam"},
      {:logger, :preloaded},
      {Enum, ~c"/enum.beam"}
    ]

    assert Resources.loaded_module_names(loaded) == [
             "Elixir.Enum",
             "Elixir.Inspect.Tuple",
             "logger"
           ]

    assert Resources.loaded_module_names(Enum.reverse(loaded)) ==
             Resources.loaded_module_names(loaded)
  end

  test "VM module delta contains only newly loaded names relative to the same VM" do
    baseline = %{
      processes: %{},
      vm: %{vm("guest-1", 100, 200) | loaded_modules: ["Existing", "Unloaded"]}
    }

    current = %{
      processes: %{},
      vm: %{vm("guest-1", 100, 200) | loaded_modules: ["Existing", "NewA", "NewB"]}
    }

    assert %{vm: %{loaded_modules_added: ["NewA", "NewB"], comparable: true}} =
             Resources.delta(current, baseline)

    assert %{vm: %{loaded_modules_added: []}} = Resources.delta(baseline, baseline)
    replaced = %{current | vm: %{current.vm | identity: "replacement"}}
    assert %{vm: nil} = Resources.delta(replaced, baseline)
  end

  test "authority tables retain orphan rows and rule or token contents regardless of row order" do
    rules = [
      {"peer-1", "rule-1", %{member: "Changed"}, "member='Changed'"},
      {"orphan", "rule-2", %{member: "Orphaned"}, "member='Orphaned'"}
    ]

    capabilities = [
      {":1.1", {:send, "org.example.One"}},
      {":orphan", {:call, {"org.example.Two", "org.example.API", "Read"}}}
    ]

    baseline = Resources.authority_tables(%{}, %{}, rules, capabilities)

    assert baseline ==
             Resources.authority_tables(%{}, %{}, Enum.reverse(rules), Enum.reverse(capabilities))

    without_orphans =
      Resources.authority_tables(%{}, %{}, Enum.take(rules, 1), Enum.take(capabilities, 1))

    refute baseline.match_rules_table == without_orphans.match_rules_table
    refute baseline.capabilities_table == without_orphans.capabilities_table

    changed =
      Resources.authority_tables(
        %{},
        %{},
        [hd(rules), {"orphan", "rule-2", %{member: "Other"}, "member='Other'"}],
        [hd(capabilities), {":orphan", {:call, {"org.example.Two", "org.example.API", "Write"}}}]
      )

    refute baseline.match_rules_table == changed.match_rules_table
    refute baseline.capabilities_table == changed.capabilities_table
  end

  test "authority state projections retain complete state beyond per-peer summaries" do
    rules_state = %{peers: %{}, uid_counts: %{}, max_match_entries: 8192}
    capability_state = %{tokens: %{"orphan" => {:send, "org.example.One"}}}
    baseline = Resources.authority_tables(rules_state, capability_state, [], [])

    changed =
      Resources.authority_tables(
        %{rules_state | uid_counts: %{1000 => 1}},
        %{capability_state | tokens: %{"orphan" => {:send, "org.example.Two"}}},
        [],
        []
      )

    refute baseline.match_rules_state == changed.match_rules_state
    refute baseline.capability_state == changed.capability_state
    assert baseline.match_rules_table == changed.match_rules_table
    assert baseline.capabilities_table == changed.capabilities_table
  end

  defp live(pid, metrics), do: %{status: "live", pid: pid, metrics: metrics, complete: true}
  defp absent(pid), do: %{status: "absent", pid: pid, metrics: nil, complete: true}

  defp vm(identity, reductions, total) do
    %{
      identity: identity,
      reductions: reductions,
      memory: %{total: total, processes_used: 100, binary: 20, ets: 30, atom_used: 40},
      atom_count: 1000,
      process_count: 20,
      port_count: 2,
      loaded_modules: []
    }
  end
end
