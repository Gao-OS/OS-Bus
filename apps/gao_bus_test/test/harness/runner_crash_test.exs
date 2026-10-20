defmodule GaoBusTest.E2E.RunnerCrashTest do
  use ExUnit.Case, async: false

  alias GaoBusTest.E2E.Command

  @moduletag :tmp_dir

  for backend <- ["reference", "gao_bus"] do
    @tag timeout: 40_000
    test "H-04 abrupt runner failure reaps #{backend} daemon and independent actor", %{
      tmp_dir: dir
    } do
      fixtures = Path.expand("../support/e2e/fixtures", __DIR__)
      paths = Path.wildcard(Path.join([Mix.Project.build_path(), "lib", "*", "ebin"]))

      result =
        Command.run(
          "python3",
          [
            Path.join(fixtures, "crash_observer.py"),
            unquote(backend),
            Path.expand(dir),
            Path.join(fixtures, "runner_crash.exs")
          ] ++ paths,
          timeout: 30_000
        )

      assert result.exit_status == 0, result.stdout <> result.stderr
      evidence = Jason.decode!(String.trim(result.stdout))
      assert map_size(evidence["reaped_guards"]) == 2
      refute File.exists?(evidence["tmpdir"])
      report = Jason.decode!(File.read!(Path.join(dir, "qualification.json")))
      assert [%{"e2e_id" => "H-runner-crash", "status" => "running"}] = report["executed"]
      assert %{"blocked" => 1, "passed" => 0} = report["counts"]
      assert File.exists?(Path.join(dir, "context.json"))
    end
  end
end
