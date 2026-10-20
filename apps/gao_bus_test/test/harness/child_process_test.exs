defmodule GaoBusTest.E2E.ChildProcessTest do
  use ExUnit.Case, async: true

  alias GaoBusTest.E2E.ChildProcess

  test "H-04 timed out commands are killed and reaped" do
    child =
      start_supervised!(
        {ChildProcess, command: "sh", args: ["-c", "echo READY; exec sleep 60"], owner: self()}
      )

    assert {:ok, %{pid: pid}} =
             ChildProcess.await_ready(child, &String.contains?(&1, "READY"), 2_000)

    assert %{timed_out?: true} = ChildProcess.await_exit(child, 10)
    refute File.exists?("/proc/#{pid}")
  end

  test "H-04 owner failure reaps an owned fixture" do
    owner =
      start_supervised!(
        {Task,
         fn ->
           receive do
             :finish -> :ok
           end
         end}
      )

    child =
      start_supervised!(
        {ChildProcess, command: "sh", args: ["-c", "echo READY; exec sleep 60"], owner: owner}
      )

    assert {:ok, %{pid: pid}} =
             ChildProcess.await_ready(child, &String.contains?(&1, "READY"), 2_000)

    ref = Process.monitor(child)
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^ref, :process, ^child, :normal}, 3_000
    refute File.exists?("/proc/#{pid}")
  end

  test "command output and exit status remain available after exit" do
    child =
      start_supervised!(
        {ChildProcess,
         command: "sh", args: ["-c", "printf 'fixture output'; exit 7"], owner: self()}
      )

    assert %{output: output, exit_status: 7, timed_out?: false} =
             ChildProcess.await_exit(child, 2_000)

    assert output =~ "fixture output"
  end
end
