defmodule GaoBusTest.E2E.QualificationTest do
  use ExUnit.Case, async: false

  alias GaoBusTest.E2E.{Qualification, ScenarioCase, Selection}
  alias GaoBusTest.E2E.Backend.ReferenceDBusDaemon

  @moduletag :tmp_dir

  setup do
    previous = System.get_env("E2E_STRICT")
    System.put_env("E2E_STRICT", "1")

    on_exit(fn ->
      if previous,
        do: System.put_env("E2E_STRICT", previous),
        else: System.delete_env("E2E_STRICT")
    end)

    :ok
  end

  test "H-02 a missing required actor fails instead of becoming a skip" do
    tags = %{e2e_id: "H-missing", gate: :smoke, backends: [:reference], actors: [:missing_actor]}
    assert is_nil(ScenarioCase.skip_reason(tags))

    assert {:error, {:missing_actor, :missing_actor}} =
             ScenarioCase.requirements(tags, :reference)
  end

  test "H-02 selected known gaps fail even when another backend can run" do
    tags = %{
      e2e_id: "H-gap",
      gate: :release,
      backends: [:reference, :gao_bus],
      actors: [],
      known_gap: [:gao_bus]
    }

    assert {:error, {:known_gap, :gao_bus}} = ScenarioCase.requirements(tags, :gao_bus)
  end

  test "H-02 a failed backend probe is required failure evidence" do
    assert {:error, {:backend_unavailable, "intentional probe failure"}} =
             ScenarioCase.requirements(%{actors: []}, :reference,
               availability: %{reference: "intentional probe failure"}
             )
  end

  test "H-02 empty selection and absent execution cannot qualify" do
    assert {:error, [:zero_selection]} = Qualification.evaluate([], [])
    row = row()

    assert {:error, [{:not_executed, "H-accounting", :reference}]} =
             Qualification.evaluate([row], [])
  end

  test "H-02 an absent required executable blocks the selected scenario", %{tmp_dir: dir} do
    isolate_runtime!()
    System.put_env("PATH", "")
    tags = start_qualification!("E2E-006", dir)

    assert is_nil(System.find_executable("busctl"))
    assert is_nil(ScenarioCase.skip_reason(tags))

    assert_raise RuntimeError, ~r/\{:missing_actor, :busctl\}/, fn ->
      ScenarioCase.run_scenario(tags, fn _ -> send(self(), :scenario_ran) end)
    end

    refute_received :scenario_ran
    assert_blocked!("E2E-006", "{:missing_actor, :busctl}")
  end

  test "H-02 missing dbus-daemon propagates from lookup into strict qualification", %{
    tmp_dir: dir
  } do
    isolate_runtime!()
    System.put_env("PATH", "")
    tags = start_qualification!("E2E-001", dir)

    assert {:error, {:missing_executable, "dbus-daemon"}} =
             ReferenceDBusDaemon.start(tmp_base: dir)

    assert :ok = ScenarioCase.prepare_backend_availability!()
    assert is_nil(ScenarioCase.skip_reason(tags))

    assert_raise RuntimeError, ~r/dbus-daemon not found on PATH/, fn ->
      ScenarioCase.run_scenario(tags, fn _ -> send(self(), :scenario_ran) end)
    end

    refute_received :scenario_ran
    report = assert_blocked!("E2E-001", "dbus-daemon not found on PATH")
    assert %{reference: %{probe: "dbus-daemon not found on PATH"}} = report.metadata

    assert %{dbus_daemon: %{exit_status: 127}, busctl: %{exit_status: 127}} =
             report.metadata.tools
  end

  test "H-02 a controlled backend startup failure cannot qualify", %{tmp_dir: dir} do
    isolate_runtime!()
    pid_path = Path.join(dir, "startup.pid")

    # Synthetic negative executable: it never opens or implements a bus.
    install_daemon!(dir, """
    printf '%s\\n' "$$" > '#{pid_path}'
    printf 'intentional H-02 startup failure\\n'
    exit 23
    """)

    tags = start_qualification!("E2E-001", dir)

    assert {:error, {:exited, %{exit_status: 23, output: output, pid: pid}}} =
             ReferenceDBusDaemon.start(tmp_base: dir)

    assert output =~ "intentional H-02 startup failure"
    refute File.exists?("/proc/#{pid}")
    assert [] = Path.wildcard(Path.join(dir, "e2e_dbus_*"))

    assert_raise RuntimeError, ~r/intentional H-02 startup failure/, fn ->
      ScenarioCase.run_scenario(tags, fn _ -> send(self(), :scenario_ran) end)
    end

    refute_received :scenario_ran
    assert_blocked!("E2E-001", "exit_status: 23")
    assert_reaped!(pid_path)
  end

  @tag capture_log: true
  test "H-02 an executed backend probe failure blocks strict qualification", %{tmp_dir: dir} do
    isolate_runtime!()
    pid_path = Path.join(dir, "probe.pid")
    socket_dir = Path.join(System.tmp_dir!(), "h02_probe_#{System.unique_integer([:positive])}")
    File.mkdir!(socket_dir)
    File.chmod!(socket_dir, 0o700)
    on_exit(fn -> File.rm_rf!(socket_dir) end)
    socket_path = Path.join(socket_dir, "absent.sock")
    refute File.exists?(socket_path)

    # Advertising an absent private socket deliberately fails the real probe.
    # This executable is a negative fixture, never successful broker evidence.
    install_daemon!(dir, """
    printf '%s\\n' "$$" > '#{pid_path}'
    printf 'unix:path=#{socket_path}\\n'
    exit 0
    """)

    tags = start_qualification!("E2E-001", dir)
    assert :ok = ScenarioCase.prepare_backend_availability!()
    assert_received {:ex_d_bus, {:connection_error, {:connect_failed, :enoent, ^socket_path}}}
    assert_reaped!(pid_path)
    refute File.exists?(socket_path)
    assert is_nil(ScenarioCase.skip_reason(tags))

    assert_raise RuntimeError, ~r/reference backend unavailable: :connection_timeout/, fn ->
      ScenarioCase.run_scenario(tags, fn _ -> send(self(), :scenario_ran) end)
    end

    refute_received :scenario_ran
    report = assert_blocked!("E2E-001", "connection_timeout")

    assert %{reference: %{probe: "reference backend unavailable: :connection_timeout"}} =
             report.metadata
  end

  test "H-02 finalizing an empty selected gate raises instead of passing", %{tmp_dir: dir} do
    isolate_runtime!()
    expected = Selection.select([], ScenarioCase.selected_gate())
    assert [] = expected
    start_supervised!({Qualification, expected: expected, dir: dir})
    assert {:error, [:zero_selection]} = Qualification.snapshot_report().result

    assert_raise RuntimeError, ~r/E2E qualification failed: \[:zero_selection\]/, fn ->
      Qualification.finish!(%{failures: 0})
    end

    assert %{"result" => ["error", ["zero_selection"]]} =
             dir |> Path.join("qualification.json") |> File.read!() |> Jason.decode!()
  end

  test "qualifying evidence includes each required actor for each backend" do
    expected = [row()]
    incomplete = [%{row() | status: :passed, actors_executed: []}]

    assert {:error, [{:missing_actor_execution, "H-accounting", :reference, :raw}]} =
             Qualification.evaluate(expected, incomplete)

    assert :ok =
             Qualification.evaluate(expected, [
               %{row() | status: :passed, actors_executed: [:raw]}
             ])
  end

  test "a skip or failed backend outcome cannot qualify" do
    for status <- [:skipped, :blocked, :failed] do
      result = %{row() | status: status, actors_executed: [:raw]}

      assert {:error, [{:required_result, "H-accounting", :reference, ^status}]} =
               Qualification.evaluate([row()], [result])
    end
  end

  test "the versioned selection preserves all original IDs and cumulative gates" do
    assert Enum.map(1..20, &("E2E-" <> String.pad_leading(to_string(&1), 3, "0"))) ==
             Enum.map(Selection.scenarios(), & &1.e2e_id)

    for {gate, count} <- [smoke: 4, release: 16, compat: 19, stress: 20, all: 20] do
      assert length(Selection.select([:reference], gate)) == count
      assert length(Selection.select([:reference, :gao_bus], gate)) == count * 2
    end
  end

  test "H-04 successful qualification retains selected and executed evidence", %{tmp_dir: dir} do
    report =
      Qualification.report([row()], [%{row() | status: :passed, actors_executed: [:raw]}],
        seed: 123,
        backend_probes: %{reference: :ok}
      )

    assert :ok = report.result
    assert %{selected: 1, executed: 1, passed: 1, failed: 0, blocked: 0} = report.counts
    assert {:ok, path} = Qualification.write_report(dir, report)
    content = File.read!(path)
    assert content =~ "H-accounting"
    assert content =~ "123"
    assert content =~ "actors_executed"
  end

  test "unexecuted backend combinations are reported as blocked rather than passed" do
    report = Qualification.report([row()], [])
    assert %{selected: 1, executed: 0, passed: 0, failed: 0, blocked: 1} = report.counts
    assert [%{status: :blocked, reason: :not_executed}] = report.outcomes
  end

  test "a test teardown failure cannot produce a passing qualification report" do
    result = %{row() | status: :passed, actors_executed: [:raw]}

    assert {:error, [{:exunit_failures, 1}]} =
             Qualification.report([row()], [result], stats: %{failures: 1}).result
  end

  test "missing actors cannot inflate passed counts and backend totals stay explicit" do
    expected = [row(), %{row() | backend: :gao_bus}]
    observed = [%{row() | status: :passed}, %{row() | backend: :gao_bus, status: :skipped}]
    report = Qualification.report(expected, observed)
    assert %{passed: 0, blocked: 2, skipped: 1} = report.counts

    assert %{
             reference: %{selected: 1, passed: 0, blocked: 1},
             gao_bus: %{selected: 1, passed: 0, blocked: 1, skipped: 1}
           } = report.per_backend
  end

  test "selected ExUnit skips are retained as blocked backend evidence", %{tmp_dir: dir} do
    start_supervised!({Qualification, expected: [row()], dir: dir})
    formatter = start_supervised!({GaoBusTest.E2E.QualificationFormatter, []})

    test = %ExUnit.Test{
      name: :deliberate_skip,
      module: __MODULE__,
      tags: %{e2e_id: "H-accounting", actors: [:raw], backends: [:reference]},
      state: {:skipped, "intentional required skip"}
    }

    GenServer.cast(formatter, {:test_finished, test})
    _ = :sys.get_state(formatter)
    report = Qualification.snapshot_report()
    assert %{blocked: 1, skipped: 1, passed: 0} = report.counts
    assert [%{skipped: true, outcome: %{reason: "intentional required skip"}}] = report.outcomes
  end

  defp row do
    %{
      e2e_id: "H-accounting",
      backend: :reference,
      profile: :session,
      actors: [:raw],
      actors_executed: [],
      status: :selected
    }
  end

  defp isolate_runtime! do
    previous_env = Map.new(["PATH", "E2E_BACKEND", "E2E_GATE"], &{&1, System.get_env(&1)})
    key = {ScenarioCase, :backend_unavailable_reason, :reference}
    absent = make_ref()
    previous_probe = :persistent_term.get(key, absent)

    on_exit(fn ->
      Enum.each(previous_env, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)

      if previous_probe == absent,
        do: :persistent_term.erase(key),
        else: :persistent_term.put(key, previous_probe)
    end)

    System.put_env("E2E_BACKEND", "reference")
    System.put_env("E2E_GATE", "all")
    :persistent_term.erase(key)
  end

  defp start_qualification!(id, dir) do
    tags = Enum.find(Selection.scenarios(), &(&1.e2e_id == id))
    expected = Enum.filter(Selection.select([:reference], tags.gate), &(&1.e2e_id == id))
    start_supervised!({Qualification, expected: expected, dir: dir})
    tags
  end

  defp assert_blocked!(id, reason) do
    report = Qualification.snapshot_report()
    assert {:error, [{:required_result, ^id, :reference, :blocked}]} = report.result

    assert %{selected: 1, executed: 0, passed: 0, failed: 0, blocked: 1, skipped: 0} =
             report.counts

    assert [%{status: :blocked, actors_executed: [], outcome: %{reason: actual}}] =
             report.outcomes

    assert actual =~ reason
    report
  end

  defp install_daemon!(dir, program) do
    bin = Path.join(dir, "bin")
    File.mkdir_p!(bin)
    path = Path.join(bin, "dbus-daemon")

    File.write!(path, """
    #!/bin/sh
    if [ "$1" = "--version" ]; then
      printf 'H-02 synthetic negative executable\\n'
      exit 0
    fi
    #{program}
    """)

    File.chmod!(path, 0o700)
    System.put_env("PATH", bin)
  end

  defp assert_reaped!(pid_path) do
    pid = pid_path |> File.read!() |> String.trim() |> String.to_integer()
    refute File.exists?("/proc/#{pid}")
  end
end

