ExUnit.start()

defmodule GaoBus.HelperWorkerProtocolFixtureTest do
  use ExUnit.Case, async: false
  alias GaoBus.Activation.HelperWorker

  setup_all do
    assert List.to_string(:code.priv_dir(:gao_bus)) ==
             System.fetch_env!("GAO_HELPER_FIXTURE_PRIV")

    :ok
  end

  defp result(name) do
    epoch = make_ref()
    attempt = make_ref()
    token = make_ref()

    pid =
      start_supervised!(
        {HelperWorker,
         [
           owner: self(),
           epoch: epoch,
           attempt: attempt,
           token: token,
           name: "org.fixture.#{name}"
         ]},
        id: make_ref()
      )

    monitor = Process.monitor(pid)
    assert :ok = HelperWorker.launch(pid, token)
    assert_receive {:helper_result, ^pid, ^epoch, ^attempt, ^token, result}, 5000
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5000
    refute_receive {:helper_result, ^pid, _, _, _, _}
    result
  end

  test "fragmented valid status waits for normal Port completion" do
    epoch = make_ref()
    attempt = make_ref()
    token = make_ref()

    pid =
      start_supervised!(
        {HelperWorker,
         [
           owner: self(),
           epoch: epoch,
           attempt: attempt,
           token: token,
           name: "org.fixture.Fragmented"
         ]},
        id: make_ref()
      )

    monitor = Process.monitor(pid)
    assert 1 = :erlang.trace(pid, true, [:receive])
    assert :ok = HelperWorker.launch(pid, token)

    bytes =
      for _ <- 1..16 do
        assert_receive {:trace, ^pid, :receive, {port, {:data, <<byte>>}}}, 5000
        assert Port.command(port, <<1>>)
        <<byte>>
      end

    assert IO.iodata_to_binary(bytes) == <<"GHB", 1, 3, 0, 0::16, 0::32, 0::32>>
    assert_receive {:helper_result, ^pid, ^epoch, ^attempt, ^token, {:exited, 0}}, 5000
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5000
  end

  test "missing/truncated/extra/version/reserved/unknown records lose observation" do
    for name <-
          ~w(Missing Truncated Extra Version Reserved Stage UnknownKind ExitRange SignalRange ZeroErrno) do
      assert {:error, {:observation_lost, reason}} = result(name)
      assert reason in [:extra_record_bytes, :invalid_record]
    end
  end

  test "valid record plus abnormal bridge completion cannot prove child termination" do
    for name <- ~w(Abnormal Signal) do
      assert {:error, {:observation_lost, :bridge_exit}} = result(name)
    end
  end

  test "closed native stages become bounded result variants" do
    assert {:error, {:not_started, :fork, 11}} = result("NotStarted")
    assert {:error, {:exec_failed, :exec, 2}} = result("ExecFailed")
    assert {:error, {:observation_lost, :bridge_observation_failed}} = result("ObservationFailed")
  end
end
