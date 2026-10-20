ExUnit.start()

defmodule GaoBusTest.FoundationEvidenceIndexTest do
  use ExUnit.Case, async: false
  alias GaoBusTest.E2E.FoundationEvidenceIndex, as: Index

  setup do
    root = Path.join(System.tmp_dir!(), "foundation-index-#{System.unique_integer([:positive])}")
    File.mkdir_p!(Path.join(root, "docs/codex/os-bus-foundation"))
    File.cp!("docs/codex/os-bus-foundation/TEST_PLAN.md", Path.join(root, Index.test_plan_path()))
    on_exit(fn -> File.rm_rf!(root) end)
    %{root: root, map: Index.empty_map()}
  end

  test "catalogue matches all89 IDs and category counts", %{root: root, map: map} do
    assert length(Index.catalogue()) == 89

    assert Enum.frequencies_by(Index.catalogue(), &hd(String.split(&1["required_id"], "-"))) ==
             %{
               "H" => 4,
               "SEC" => 17,
               "PRO" => 7,
               "SEM" => 12,
               "FD" => 10,
               "RES" => 6,
               "FAIL" => 4,
               "POL" => 7,
               "API" => 4,
               "ACT" => 7,
               "SYS" => 5,
               "VM" => 6
             }

    assert {:ok, core} = Index.build(root, map, "core")
    assert core.id_counts.selected == 88
    assert core.id_counts.out_of_scope == 1
    assert core.index_integrity == :passed
    refute core.product_qualified
    assert core.runtime_execution == %{broker: 0, vm: 0}
    assert {:ok, network} = Index.build(root, map, "network")
    assert network.id_counts.selected == 89
    assert Enum.find(core.rows, &(&1.required_id == "VM-04")).status == :out_of_scope
  end

  test "rejects malformed catalogue selections", %{root: root, map: map} do
    for {_name, edit, reason} <- [
          {"missing ID", fn m -> Map.update!(m, "rows", &tl/1) end, "combination catalogue"},
          {"missing subcase",
           fn m ->
             Map.update!(m, "rows", fn rs ->
               Enum.reject(rs, &(&1["subcase_id"] == "control-truncation"))
             end)
           end, "combination catalogue"},
          {"missing backend",
           fn m ->
             Map.update!(m, "rows", fn rs ->
               Enum.reject(rs, &(&1["required_id"] == "FD-01" and &1["backend"] == "reference"))
             end)
           end, "combination catalogue"},
          {"duplicate selection",
           fn m -> Map.update!(m, "rows", fn [r | _] = rs -> [r | rs] end) end,
           "duplicate combination"},
          {"fake totals", fn m -> Map.put(m, "counts", %{"passed" => 89}) end, "supplied counts"},
          {"plan hash", fn m -> Map.put(m, "test_plan_sha256", String.duplicate("0", 64)) end,
           "test plan binding"}
        ] do
      assert {:error, error} = Index.build(root, edit.(map), "core")
      assert error =~ reason
    end
  end

  test "unknown profile rejects", %{root: root, map: map} do
    assert {:error, error} = Index.build(root, map, "session")
    assert error =~ "profile"
  end

  test "rejects malformed authentic receipt claims", %{root: root, map: map} do
    for {_name, mutate, reason} <- [
          {"missing actor",
           fn r -> put_in(r, ["observations", Access.at(0), "actors_executed"], []) end, "actor"},
          {"wrong backend identity", fn r -> put_in(r, ["identity", "backend"], "reference") end,
           "identity"},
          {"conflicting counts", fn r -> put_in(r, ["counts", "passed"], 2) end, "counts"},
          {"conflicting observations",
           fn r ->
             Map.update!(r, "observations", fn [o] -> [o, Map.put(o, "status", "failed")] end)
           end, "unique observation"},
          {"wrong source current binding",
           fn r -> put_in(r, ["bindings", Access.at(0), "sha256"], String.duplicate("0", 64)) end,
           "binding"},
          {"before after drift",
           fn r ->
             put_in(r, ["bindings", Access.at(0), "after_sha256"], String.duplicate("0", 64))
           end, "binding"},
          {"zero observations", fn r -> Map.put(r, "observations", []) end, "unique observation"},
          {"wrong coverage",
           fn r -> put_in(r, ["observations", Access.at(0), "coverage_scope"], "lease-only") end,
           "coverage"}
        ] do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      map = save(root, map, mutate.(receipt))
      assert {:error, error} = Index.build(root, map, "core")
      assert error =~ reason
    end
  end

  test "byte drift rejects the saved artifact", %{root: root, map: map} do
    {map, _} = chosen(root, map, "FD-04", "control-truncation")
    File.write!(Path.join(root, "receipt.json"), "changed")
    assert {:error, error} = Index.build(root, map, "core")
    assert error =~ "artifact hash"
  end

  test "source byte drift rejects current but preserves historical", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    File.write!(Path.join(root, "source.ex"), "changed")
    assert {:error, _} = Index.build(root, map, "core")
    receipt = Map.put(receipt, "currency", "historical")
    map = save(root, map, receipt)
    assert {:ok, result} = Index.build(root, map, "core")
    assert result.combination_counts.passed == 0
    assert result.evidence_counts.historical == 1
  end

  for {id, subcase, scope} <- [
        {"FD-04", "control-truncation", "same-runner"},
        {"FD-07", "failed-activation", "lease-only"},
        {"FD-10", "repeated-batches", "partial"}
      ] do
    test "#{id} partial branch cannot qualify the full row", %{root: root, map: map} do
      {map, receipt} = chosen(root, map, unquote(id), unquote(subcase))

      map =
        save(
          root,
          map,
          receipt |> Map.put("currency", "partial") |> Map.put("scope", unquote(scope))
        )

      assert {:ok, result} = Index.build(root, map, "core")
      row = Enum.find(result.rows, &(&1.required_id == unquote(id)))
      assert row.status == :blocked
      assert result.evidence_counts.partial == 1
      assert hd(result.observations).observation["status"] == "passed"
      refute result.product_qualified
    end
  end

  for field <- ["exit", "teardown_exit"] do
    test "failed command #{field} dominates passed subcase and retains blockers", %{
      root: root,
      map: map
    } do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      map = save(root, map, put_in(receipt, ["command", unquote(field)], 1))
      assert {:ok, result} = Index.build(root, map, "core")
      assert result.id_counts.failed == 1
      assert result.combination_counts.failed == 1
      assert result.combination_counts.blocked > 0
      assert hd(result.observations).observation["status"] == "passed"
    end
  end

  test "current independent pass is scoped, runs deduplicate, reference failure remains", %{
    root: root,
    map: map
  } do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    assert {:ok, result} = Index.build(root, map, "core")
    assert result.combination_counts.passed == 1
    assert result.id_counts.passed == 0
    receipt = put_in(receipt, ["observations", Access.at(0), "status"], "failed")

    receipt =
      Map.put(receipt, "counts", %{
        "selected" => 1,
        "executed" => 1,
        "passed" => 0,
        "failed" => 1,
        "blocked" => 0,
        "skipped" => 0
      })

    assert {:ok, result} = Index.build(root, save(root, map, receipt), "core")
    assert result.id_counts.failed == 1
    assert result.evidence_counts.unique_runs == 1
    assert result.combination_counts.blocked > 1
  end

  test "omitted strict flag permits blocked accounting while explicit strict fails", %{
    root: root,
    map: map
  } do
    map_path = Path.join(root, "cli-map.json")
    File.write!(map_path, Jason.encode!(map))

    args = [
      "-pa",
      "_build/test/lib/jason/ebin",
      "scripts/foundation/required_evidence_index.exs",
      "--root",
      File.cwd!(),
      "--map",
      map_path,
      "--profile",
      "core",
      "--output",
      Path.join(root, "cli-default")
    ]

    executable = "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3/bin/elixir"
    {output, exit} = System.cmd(executable, args, stderr_to_stdout: true)
    assert exit == 0, output
    assert Jason.decode!(output)["product_qualified"] == false

    {output, exit} =
      System.cmd(executable, args ++ ["--require-qualified"], stderr_to_stdout: true)

    assert exit == 1, output
    assert_json_unique!(File.read!(Path.join(root, "cli-default/qualification.json")))
  end

  test "retained failed references serialize with unique keys and original selector intact", %{
    root: root,
    map: map
  } do
    File.write!(Path.join(root, "retained.json"), Jason.encode!(%{"result" => "failed"}))

    reference = %{
      "path" => "retained.json",
      "sha256" => Index.sha256(Path.join(root, "retained.json")),
      "run_id" => "retained-run",
      "currency" => "partial",
      "disposition" => "failed",
      "reason" => "Saved named failure; full required branch remains blocked.",
      "selector" => ["result"],
      "value" => "failed"
    }

    map =
      Map.update!(map, "rows", fn [row | rows] ->
        [Map.put(row, "retained_evidence", [reference]) | rows]
      end)

    assert {:ok, result} = Index.build(root, map, "core")
    assert result.id_counts.failed == 1

    assert {:ok, path} =
             GaoBusTest.E2E.Qualification.write_report(Path.join(root, "serialized"), result)

    json = File.read!(path)
    assert_json_unique!(json)
    decoded = Jason.decode!(json)
    assert hd(decoded["observations"])["selector"] == ["result"]
    assert hd(decoded["observations"])["sha256"] == reference["sha256"]
  end

  test "reviewer receipt with undeclared failed extra is rejected before chosen pass" do
    root =
      "test/reports/foundation/continuation-20261011-full-goal/environment/required-evidence-index-spec-review1/synthetic-root"

    map = root |> Path.join("map.json") |> File.read!() |> Jason.decode!()
    assert {:error, reason} = Index.build(root, map, "core")
    assert reason =~ "undeclared receipt observation"
  end

  for {field, value} <- [
        {"required_id", "FD-99"},
        {"backend", "unexpected-backend"},
        {"profile", "unexpected-profile"},
        {"subcase_id", "unexpected-subcase"}
      ] do
    test "rejects extra observation with unexpected #{field}", %{root: root, map: map} do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      [observation] = receipt["observations"]

      extra =
        observation |> Map.put(unquote(field), unquote(value)) |> Map.put("status", "failed")

      receipt =
        receipt
        |> Map.put("observations", [observation, extra])
        |> Map.put(
          "counts",
          %{
            "selected" => 2,
            "executed" => 2,
            "passed" => 1,
            "failed" => 1,
            "blocked" => 0,
            "skipped" => 0
          }
        )

      assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
      assert reason =~ "undeclared receipt observation"
    end
  end

  test "known but unreferenced extra failed observation cannot disappear", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    [observation] = receipt["observations"]
    extra = observation |> Map.put("subcase_id", "invalid-index") |> Map.put("status", "failed")

    receipt =
      receipt
      |> Map.put("observations", [observation, extra])
      |> Map.put(
        "counts",
        %{
          "selected" => 2,
          "executed" => 2,
          "passed" => 1,
          "failed" => 1,
          "blocked" => 0,
          "skipped" => 0
        }
      )

    assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
    assert reason =~ "unreferenced receipt observation"
  end

  test "missing or wrong source scenario cannot be a qualifying label", %{root: root, map: map} do
    for scenario <- [nil, "different-test"] do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      receipt = put_in(receipt, ["observations", Access.at(0), "source_scenario_id"], scenario)
      assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
      assert reason =~ "source scenario"
    end
  end

  test "missing or mismatched declared invariant references reject", %{root: root, map: map} do
    for assertions <- [[], [%{"invariant" => "wrong invariant", "record_ref" => %{}}]] do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      receipt = put_in(receipt, ["observations", Access.at(0), "assertions"], assertions)
      assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
      assert reason =~ "invariant assertion"
    end
  end

  test "label-only witness without measured values rejects", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")

    witness =
      root
      |> Path.join("assertion.json")
      |> File.read!()
      |> Jason.decode!()
      |> Map.drop(["expected", "actual"])

    {map, receipt} = save_witness(root, map, receipt, witness)
    assert {:error, reason} = Index.build(root, map, "core")
    assert reason =~ "assertion measurements"
    assert receipt["observations"] != []
  end

  test "wrong assertion scenario or source bytes rejects", %{root: root, map: map} do
    for {field, value} <- [
          {"source_scenario_id", "other-case"},
          {"source_sha256", String.duplicate("0", 64)},
          {"invariant", "wrong invariant"},
          {"assertion_source", "assert absent == invented"},
          {"run_id", "other-run"}
        ] do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")

      witness =
        root
        |> Path.join("assertion.json")
        |> File.read!()
        |> Jason.decode!()
        |> Map.put(field, value)

      {map, _receipt} = save_witness(root, map, receipt, witness)
      assert {:error, reason} = Index.build(root, map, "core")
      assert reason =~ "assertion"
    end
  end

  test "contradictory measured pass rejects", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")

    witness =
      root
      |> Path.join("assertion.json")
      |> File.read!()
      |> Jason.decode!()
      |> put_in(["actual", "fd_after"], 25)

    {map, _receipt} = save_witness(root, map, receipt, witness)
    assert {:error, reason} = Index.build(root, map, "core")
    assert reason =~ "assertion outcome"
  end

  test "failed measured invariant remains failed even with a passed observation label", %{
    root: root,
    map: map
  } do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")

    witness =
      root
      |> Path.join("assertion.json")
      |> File.read!()
      |> Jason.decode!()
      |> put_in(["actual", "fd_after"], 25)
      |> Map.put("status", "failed")

    {map, _receipt} = save_witness(root, map, receipt, witness)
    assert {:ok, result} = Index.build(root, map, "core")
    assert result.combination_counts.passed == 0
    assert result.combination_counts.failed == 1
    assert hd(result.observations).observation["status"] == "passed"
    assert hd(result.observations).assertion_evidence |> hd() |> Map.fetch!("status") == "failed"
    refute result.product_qualified
  end

  test "quality reviewer negative log failure receipt rejects" do
    root =
      "test/reports/foundation/continuation-20261011-full-goal/environment/required-evidence-index-quality-review1/negative-log-failures"

    map = root |> Path.join("map.json") |> File.read!() |> Jason.decode!()
    assert {:error, reason} = Index.build(root, map, "core")
    assert reason =~ "command/teardown receipt"
  end

  test "negative log failure count cannot qualify", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    receipt = put_in(receipt, ["command", "log_failures"], -1)
    assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
    assert reason =~ "command/teardown receipt"
  end

  for pid <- [0, -1] do
    test "backend PID #{pid} is invalid", %{root: root, map: map} do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      receipt = put_in(receipt, ["backend_receipt", "pid"], unquote(pid))
      assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
      assert reason =~ "backend identity/config receipt"
    end

    test "executed actor PID #{pid} is invalid", %{root: root, map: map} do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      receipt = put_in(receipt, ["actor_receipts", Access.at(0), "pid"], unquote(pid))
      assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
      assert reason =~ "actor identity/config receipt"
    end
  end

  test "executed actor UID cannot be negative", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    receipt = put_in(receipt, ["actor_receipts", Access.at(0), "uid"], -1)
    assert {:error, reason} = Index.build(root, save(root, map, receipt), "core")
    assert reason =~ "actor identity/config receipt"
  end

  test "UID zero positive PIDs and zero log failures remain valid", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    receipt = put_in(receipt, ["backend_receipt", "pid"], 1)

    receipt =
      Map.update!(receipt, "actor_receipts", fn actors ->
        Enum.map(actors, &Map.merge(&1, %{"pid" => 1, "uid" => 0}))
      end)

    assert {:ok, result} = Index.build(root, save(root, map, receipt), "core")
    assert result.combination_counts.passed == 1
    assert result.combination_counts.failed == 0
  end

  test "negative command or teardown exit remains a failed saved branch", %{root: root, map: map} do
    for field <- ["exit", "teardown_exit"] do
      {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
      receipt = put_in(receipt, ["command", field], -1)
      assert {:ok, result} = Index.build(root, save(root, map, receipt), "core")
      assert result.combination_counts.failed == 1
      assert result.combination_counts.passed == 0
      assert hd(result.observations).observation["status"] == "passed"
    end
  end

  test "positive log failure count retains failed branch", %{root: root, map: map} do
    {map, receipt} = chosen(root, map, "FD-04", "control-truncation")
    receipt = put_in(receipt, ["command", "log_failures"], 1)
    assert {:ok, result} = Index.build(root, save(root, map, receipt), "core")
    assert result.combination_counts.failed == 1
    assert result.combination_counts.passed == 0
  end

  defp save_witness(root, map, receipt, witness) do
    File.write!(Path.join(root, "assertion.json"), Jason.encode!(witness))

    receipt =
      put_in(
        receipt,
        ["observations", Access.at(0), "assertions", Access.at(0), "record_ref", "sha256"],
        Index.sha256(Path.join(root, "assertion.json"))
      )

    {save(root, map, receipt), receipt}
  end

  defp assert_json_unique!(json),
    do: unique_objects!(Jason.decode!(json, objects: :ordered_objects))

  defp unique_objects!(%Jason.OrderedObject{values: pairs}) do
    keys = Enum.map(pairs, &elem(&1, 0))

    assert length(keys) == length(Enum.uniq(keys)),
           "duplicate serialized JSON keys: #{inspect(keys)}"

    Enum.each(pairs, fn {_key, value} -> unique_objects!(value) end)
  end

  defp unique_objects!(values) when is_list(values), do: Enum.each(values, &unique_objects!/1)
  defp unique_objects!(_value), do: :ok

  defp chosen(root, map, id, subcase) do
    row =
      Enum.find(
        map["rows"],
        &(&1["required_id"] == id and &1["subcase_id"] == subcase and &1["backend"] == "gao_bus" and
            &1["profile"] == "core")
      )

    File.write!(Path.join(root, "source.ex"), "source")

    File.write!(
      Path.join(root, "test.exs"),
      "synthetic-case\nassert observed == expected # synthetic-equal\n"
    )

    File.write!(Path.join(root, "fixture.c"), "fixture")
    File.write!(Path.join(root, "config.json"), "config")
    File.write!(Path.join(root, "package.json"), "package")

    source_ref = %{
      "path" => "test.exs",
      "sha256" => Index.sha256(Path.join(root, "test.exs")),
      "binding_path" => "test.exs",
      "excerpt" => "synthetic-case"
    }

    witness = Map.take(row, ["required_id", "subcase_id", "backend", "profile", "coverage_scope"])

    witness =
      Map.merge(witness, %{
        "run_id" => "synthetic-run",
        "source_scenario_id" => "synthetic-case",
        "source_sha256" => source_ref["sha256"],
        "assertion_source" => "assert observed == expected # synthetic-equal",
        "actor" => hd(row["requirements"]["actors"]),
        "invariant" => hd(row["requirements"]["invariants"]),
        "executed" => true,
        "status" => "passed",
        "expected" => %{"terminal" => "closed", "fd_before" => 24, "fd_after" => 24},
        "actual" => %{"terminal" => "closed", "fd_before" => 24, "fd_after" => 24}
      })

    File.write!(Path.join(root, "assertion.json"), Jason.encode!(witness))

    observation =
      Map.take(row, ["required_id", "subcase_id", "backend", "profile", "coverage_scope"])

    observation =
      Map.merge(observation, %{
        "status" => "passed",
        "actors_executed" => row["requirements"]["actors"],
        "source_scenario_id" => "synthetic-case",
        "source_ref" => source_ref,
        "assertions" => [
          %{
            "invariant" => hd(row["requirements"]["invariants"]),
            "record_ref" => %{
              "path" => "assertion.json",
              "sha256" => Index.sha256(Path.join(root, "assertion.json")),
              "selector" => []
            }
          }
        ]
      })

    receipt = %{
      "run_id" => "synthetic-run",
      "currency" => "current",
      "scope" => row["requirements"]["layer"],
      "identity" => %{
        "backend" => "gao_bus",
        "profile" => "core",
        "actors" => row["requirements"]["actors"]
      },
      "actor_receipts" =>
        Enum.map(row["requirements"]["actors"], fn actor ->
          %{
            "actor" => actor,
            "backend" => "gao_bus",
            "profile" => "core",
            "pid" => 123,
            "uid" => 1000,
            "executed" => true,
            "config_sha256" => Index.sha256(Path.join(root, "config.json"))
          }
        end),
      "backend_receipt" => %{
        "backend" => "gao_bus",
        "profile" => "core",
        "pid" => 456,
        "version" => "synthetic-test",
        "independent" => true,
        "config_sha256" => Index.sha256(Path.join(root, "config.json"))
      },
      "command" => %{
        "argv" => ["synthetic-offline-test"],
        "cwd" => root,
        "exit" => 0,
        "teardown_exit" => 0,
        "log_failures" => 0
      },
      "counts" => %{
        "selected" => 1,
        "executed" => 1,
        "passed" => 1,
        "failed" => 0,
        "blocked" => 0,
        "skipped" => 0
      },
      "observations" => [observation],
      "bindings" =>
        for {path, kind} <- [
              {"source.ex", "source"},
              {"test.exs", "test"},
              {"fixture.c", "fixture"},
              {"config.json", "config"},
              {"package.json", "package"}
            ] do
          hash = Index.sha256(Path.join(root, path))

          %{
            "path" => path,
            "kind" => kind,
            "sha256" => hash,
            "before_sha256" => hash,
            "after_sha256" => hash
          }
        end
    }

    map =
      Map.update!(map, "rows", fn rows ->
        Enum.map(rows, fn r ->
          if r == row,
            do:
              Map.put(r, "source_scenario_id", "synthetic-case")
              |> Map.put("record_ref", %{
                "path" => "receipt.json",
                "sha256" => "pending",
                "selector" => 0
              }),
            else: r
        end)
      end)

    {save(root, map, receipt), receipt}
  end

  defp save(root, map, receipt) do
    File.write!(Path.join(root, "receipt.json"), Jason.encode!(receipt))

    Map.update!(map, "rows", fn rows ->
      Enum.map(rows, fn r ->
        if r["record_ref"],
          do: put_in(r, ["record_ref", "sha256"], Index.sha256(Path.join(root, "receipt.json"))),
          else: r
      end)
    end)
  end
end
