ExUnit.start()

defmodule GaoBus.HelperWorkerFixtureTest do
  use ExUnit.Case, async: false
  alias GaoBus.Activation.HelperWorker

  setup_all do
    assert List.to_string(:code.priv_dir(:gao_bus)) ==
             System.fetch_env!("GAO_HELPER_FIXTURE_PRIV")

    :ok
  end

  test "malformed options fail before an observer or Port exists" do
    valid = [
      owner: self(),
      epoch: make_ref(),
      attempt: make_ref(),
      token: make_ref(),
      name: "org.fixture.Exit0"
    ]

    invalid = [
      nil,
      %{},
      [:not_a_keyword],
      [],
      Keyword.delete(valid, :epoch),
      Keyword.put(valid, :name, ":1.1"),
      Keyword.put(valid, :owner, :invalid),
      Keyword.put(valid, :token, nil),
      Keyword.put(valid, :bridge, "/tmp/override")
    ]

    for options <- invalid do
      assert {:error, :invalid_worker_options} = HelperWorker.start_link(options)
    end
  end

  defp worker(name, options \\ []) do
    epoch = make_ref()
    attempt = {epoch, name}
    token = make_ref()

    pid =
      start_supervised!(
        {HelperWorker,
         Keyword.merge(
           [owner: self(), epoch: epoch, attempt: attempt, token: token, name: name],
           options
         )},
        id: make_ref()
      )

    {pid, epoch, attempt, token}
  end

  defp result(name) do
    {pid, epoch, attempt, token} = worker(name)
    monitor = Process.monitor(pid)
    assert :ok = HelperWorker.launch(pid, token)
    assert_receive {:helper_result, ^pid, ^epoch, ^attempt, ^token, result}, 5000
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5000
    refute_receive {:helper_result, ^pid, _, _, _, _}
    result
  end

  test "reserved worker has no Port and only owner/token can launch" do
    {pid, epoch, attempt, token} = worker("org.fixture.Exit0")
    assert :sys.get_state(pid).phase == :reserved
    assert :sys.get_state(pid).port == nil

    assert {:reply, :ok, %{phase: :launching, port: nil}, {:continue, :open_bridge}} =
             HelperWorker.handle_call({:launch, token}, {self(), make_ref()}, :sys.get_state(pid))

    assert {:error, :invalid_token} = HelperWorker.launch(pid, make_ref())
    parent = self()

    start_supervised!(
      {Task, fn -> send(parent, {:untrusted_launch, HelperWorker.launch(pid, token)}) end},
      id: make_ref()
    )

    assert_receive {:untrusted_launch, {:error, :not_owner}}
    assert :sys.get_state(pid).port == nil
    monitor = Process.monitor(pid)
    assert :ok = HelperWorker.launch(pid, token)
    assert_receive {:helper_result, ^pid, ^epoch, ^attempt, ^token, {:exited, 0}}, 5000
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5000
  end

  test "exact direct-child exit codes survive the real Port lifecycle" do
    for code <- [0, 1] ++ Enum.to_list(2..11) ++ [127, 137, 255] do
      assert {:exited, ^code} = result("org.fixture.Exit#{code}")
    end
  end

  test "real signals remain distinct from exit137" do
    assert {:signaled, 9} = result("org.fixture.Kill")
    assert {:signaled, 15} = result("org.fixture.Term")
    assert {:exited, 137} = result("org.fixture.Exit137")
  end

  test "service output cannot reach the worker or owner" do
    assert {:exited, 0} = result("org.fixture.Flood")
    refute_receive {_port, {:data, _bytes}}
  end

  test "helper receives empty environment and no observer FD" do
    assert {:exited, 0} = result("org.fixture.Inspect")
  end

  test "fast exits do not release an unfinished or missing observation" do
    for _ <- 1..50, do: assert({:exited, 0} = result("org.fixture.Exit0"))
  end

  test "owner death before launch terminates the effect-free reservation" do
    owner =
      start_supervised!(
        {Task,
         fn ->
           receive do
             :stop -> :ok
           end
         end},
        id: make_ref()
      )

    {pid, _, _, _} = worker("org.fixture.Exit0", owner: owner)
    monitor = Process.monitor(pid)
    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :normal}, 5000
  end
end
