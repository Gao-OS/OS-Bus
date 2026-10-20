defmodule GaoBusTest.E2E.SystemLifecycleTest do
  use ExUnit.Case, async: false

  alias GaoBusTest.E2E.Command

  @moduletag :e2e
  @moduletag :tmp_dir

  for backend <- ["reference", "gao_bus"] do
    @tag timeout: 40_000
    test "H-04 core system fixture retains timeout and runner-crash cleanup for #{backend}", %{
      tmp_dir: dir
    } do
      bindings = System.fetch_env!("H04_BINDINGS")
      fixtures = Path.expand("../support/e2e/fixtures", __DIR__)

      result =
        Command.run(
          "python3",
          [Path.join(fixtures, "h04_system_observer.py"), unquote(backend), bindings],
          timeout: 30_000
        )

      File.write!(Path.join(dir, "observer.stdout"), result.stdout)
      File.write!(Path.join(dir, "observer.stderr"), result.stderr)
      assert result.exit_status == 0, result.stdout <> result.stderr
      evidence = Jason.decode!(String.trim(result.stdout))
      assert evidence["backend"] == unquote(backend)
      assert evidence["profile"] == "core"
      assert evidence["status"] == "passed"
      assert evidence["timeout_fixture_reaped"]
      assert evidence["runner_exit"] == -9
      assert evidence["all_observed_incarnations_reaped"]
      assert evidence["private_directory_removed"]
      assert evidence["inner_qualification"] == "blocked"
      refute evidence["installed_policy_qualified"]
      refute evidence["daemon_graceful_unlink_claim"]

      assert evidence["observer_json"] ==
               "/run/osbus-security/h04-current-lifecycle1/#{unquote(backend)}/observer.json"

      observer = File.read!(evidence["observer_json"])
      assert byte_size(observer) == evidence["observer_bytes"]

      assert Base.encode16(:crypto.hash(:sha256, observer), case: :lower) ==
               evidence["observer_sha256"]
    end
  end
end
