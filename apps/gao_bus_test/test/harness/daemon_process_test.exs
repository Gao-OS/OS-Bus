defmodule GaoBusTest.E2E.DaemonProcessTest do
  use ExUnit.Case, async: false

  alias GaoBusTest.E2E.Backend.GaoBusProcess

  test "H-04 isolated Gao daemon has its own OS process and is reaped" do
    assert {:ok, state} = GaoBusProcess.start(scenario_id: "H-daemon")

    try do
      assert is_integer(state.daemon_pid)
      refute state.daemon_pid == String.to_integer(System.pid())
      assert File.exists?("/proc/#{state.daemon_pid}")
      assert :ok = GaoBusProcess.probe(state)
      assert "unix:path=" <> _path = GaoBusProcess.address(state)
      assert %{config_sha256: hash, daemon_pid: pid} = GaoBusProcess.diagnostics(state)
      assert byte_size(hash) == 64
      assert pid == state.daemon_pid
      assert state.config =~ "profile=session"
      assert state.config =~ "policy_rules=#{state.policy_config}"
      assert byte_size(state.policy_sha256) == 64
      assert GaoBusProcess.diagnostics(state).log =~ state.policy_sha256
    after
      assert :ok = GaoBusProcess.stop(state)
    end

    refute File.exists?("/proc/#{state.daemon_pid}")
    refute File.exists?(state.tmpdir)
  end
end
