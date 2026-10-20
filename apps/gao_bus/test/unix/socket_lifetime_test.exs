Code.require_file("../fixtures/socket_lifetime_probe.ex", __DIR__)

defmodule GaoBus.Unix.SocketLifetimeTest do
  use ExUnit.Case, async: false
  alias GaoBus.Unix.NativeProbe, as: Probe

  setup_all do
    directory =
      Path.join(System.tmp_dir!(), "osbus-nif-probe-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    source = Path.expand("../fixtures/socket_lifetime_probe.c", __DIR__)
    library = Path.join(directory, "socket_lifetime_probe")

    includes =
      Path.join([
        List.to_string(:code.root_dir()),
        "erts-#{:erlang.system_info(:version)}",
        "include"
      ])

    assert {output, 0} =
             System.cmd(
               System.find_executable("cc"),
               [
                 "-std=c11",
                 "-Wall",
                 "-Wextra",
                 "-Werror",
                 "-fPIC",
                 "-shared",
                 "-I#{includes}",
                 "-o",
                 library <> ".so",
                 source
               ],
               stderr_to_stdout: true
             )

    assert output == ""
    assert :ok = Probe.load(library)
    on_exit(fn -> File.rm_rf!(directory) end)
    :ok
  end

  setup do
    directory =
      Path.join(System.tmp_dir!(), "osbus-lifetime-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "socket")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)
    {:ok, client} = :socket.open(:local, :stream, :default)
    :ok = :socket.connect(client, %{family: :local, path: path}, 5000)
    {:ok, socket} = :socket.accept(listener, 5000)
    {:ok, fd} = :socket.getopt(socket, {:otp, :fd})

    on_exit(fn ->
      Probe.release()
      :socket.close(client)
      :socket.close(socket)
      :socket.close(listener)
      File.rm_rf!(directory)
    end)

    %{socket: socket, client: client, fd: fd, listener: listener, path: path}
  end

  test "killed dirty sender cannot divert bytes or rights onto a reused socket FD", context do
    before_count = external_fd_count()
    parent = self()
    handle = Probe.resource()
    on_exit(fn -> Probe.close(handle) end)
    :ok = Probe.arm(2, parent)

    owner =
      start_supervised!(
        {Task,
         fn ->
           receive do
             {:socket, socket} ->
               {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
               {:ok, captured} = Probe.capture(fd)
               Probe.send(captured, "sensitive", [handle])
           end
         end}
      )

    :ok = :socket.setopt(context.socket, {:otp, :controlling_process}, owner)
    monitor = Process.monitor(owner)
    send(owner, {:socket, context.socket})
    assert_receive {:native_barrier, 2}, 5000
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 5000
    peer_fd = wait_reuse(context.fd)
    on_exit(fn -> Probe.raw_close(context.fd, peer_fd) end)
    :ok = Probe.release()
    wait_finished()
    assert {:error, :eagain} = Probe.raw_read(peer_fd)
    assert :ok = Probe.close(handle)
    # The killed OTP socket disappears; the forced replacement has two FDs.
    wait_fd_count(before_count + 1)
  end

  test "killed dirty receiver cannot consume input from a reused socket FD", context do
    before_count = external_fd_count()
    parent = self()
    :ok = :socket.send(context.client, "original")
    :ok = Probe.arm(1, parent)

    owner =
      start_supervised!(
        {Task,
         fn ->
           receive do
             {:socket, socket} ->
               {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
               {:ok, captured} = Probe.capture(fd)
               Probe.recv(captured, 1024, 16)
           end
         end}
      )

    :ok = :socket.setopt(context.socket, {:otp, :controlling_process}, owner)
    monitor = Process.monitor(owner)
    send(owner, {:socket, context.socket})
    assert_receive {:native_barrier, 1}, 5000
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 5000
    peer_fd = wait_reuse(context.fd)
    on_exit(fn -> Probe.raw_close(context.fd, peer_fd) end)
    :ok = Probe.raw_write(peer_fd, "unrelated")
    :ok = Probe.release()
    wait_finished()
    assert {:ok, "unrelated", 0} = Probe.raw_read(context.fd)
    wait_fd_count(before_count + 1)
  end

  for operation <- [:recv, :send] do
    @tag operation: operation
    test "explicit close serializes with an in-flight #{operation} and cannot close a reused FD",
         context do
      before_count = external_fd_count()
      parent = self()
      assert {:ok, captured} = Probe.capture(context.fd)
      captured_fd = Probe.resource_fd(captured)
      on_exit(fn -> Probe.close(captured) end)

      phase = if context.operation == :recv, do: 1, else: 2
      if context.operation == :recv, do: :socket.send(context.client, "original")
      assert :ok = Probe.arm(phase, parent)
      operation = context.operation

      operator =
        start_supervised!(
          Supervisor.child_spec(
            {Task,
             fn ->
               result =
                 case operation do
                   :recv -> Probe.recv(captured, 1024, 0)
                   :send -> Probe.send(captured, "original", [])
                 end

               send(parent, {:operation_result, self(), result})
             end},
            id: :native_operator
          )
        )

      operator_monitor = Process.monitor(operator)
      assert_receive {:native_barrier, ^phase}, 5000

      closer =
        start_supervised!(
          Supervisor.child_spec(
            {Task, fn -> send(parent, {:close_result, self(), Probe.close(captured)}) end},
            id: :native_closer
          )
        )

      closer_monitor = Process.monitor(closer)
      assert_receive :native_close_entered, 5000
      refute_receive {:close_result, ^closer, _}, 0
      assert :ok = Probe.release()
      wait_finished()

      expected = if operation == :recv, do: {:ok, "original", []}, else: {:ok, 8}
      assert_receive {:operation_result, ^operator, ^expected}, 5000
      assert_receive {:DOWN, ^operator_monitor, :process, ^operator, :normal}, 5000
      assert_receive {:close_result, ^closer, :ok}, 5000
      assert_receive {:DOWN, ^closer_monitor, :process, ^closer, :normal}, 5000
      wait_fd_count(before_count)

      peer_fd = wait_reuse(captured_fd)
      on_exit(fn -> Probe.raw_close(captured_fd, peer_fd) end)
      assert {:error, :closed} = Probe.recv(captured, 1024, 0)
      assert {:error, :closed} = Probe.send(captured, "sensitive", [])
      assert :ok = Probe.close(captured)
      assert :ok = Probe.raw_write(peer_fd, "unrelated")
      assert {:ok, "unrelated", 0} = Probe.raw_read(captured_fd)
      assert {:error, :eagain} = Probe.raw_read(peer_fd)
      wait_fd_count(before_count + 2)
    end
  end

  for budget <- [0, 1, 16] do
    @tag budget: budget
    test "receiving excess rights never installs more than #{budget} charged FDs", context do
      source = Path.expand("../fixtures/resource_actor.py", __DIR__)

      actor =
        Port.open({:spawn_executable, System.find_executable("python3")}, [
          :binary,
          :exit_status,
          args: [source, context.path, "control_budget"]
        ])

      on_exit(fn -> if Port.info(actor), do: Port.close(actor) end)
      {:ok, socket} = :socket.accept(context.listener, 5000)
      assert {:ok, _} = :socket.recv(socket, 1, [:peek], 5000)
      parent = self()
      budget = context.budget
      :ok = Probe.arm(3, parent)

      owner =
        start_supervised!(
          {Task,
           fn ->
             receive do
               {:socket, socket} ->
                 {:ok, fd} = :socket.getopt(socket, {:otp, :fd})
                 {:ok, captured} = Probe.capture(fd)
                 send(parent, {:captured, self()})

                 receive do
                   :go ->
                     result = Probe.recv(captured, 1024, budget)
                     :ok = :socket.setopt(socket, {:otp, :controlling_process}, parent)
                     send(parent, {:received, result})
                 end
             end
           end}
        )

      :ok = :socket.setopt(socket, {:otp, :controlling_process}, owner)
      send(owner, {:socket, socket})
      assert_receive {:captured, ^owner}, 5000
      before_count = external_fd_count()
      send(owner, :go)
      assert_receive {:native_barrier, 3}, 5000

      try do
        assert external_fd_count() - before_count <= budget
      after
        Probe.release()
      end

      assert_receive {:received, {:error, :control_truncated}}, 5000
      wait_finished()
      # capture added one native duplicate before this baseline was sampled.
      wait_fd_count(before_count - 1)
      :ok = :socket.send(socket, "!")
      Port.command(actor, "q")
      assert_receive {^actor, {:data, "RESOURCE_ACTOR_OK\n"}}, 5000
      assert_receive {^actor, {:exit_status, 0}}, 5000
      :socket.close(socket)
    end
  end

  defp external_fd_count do
    script = "import os,sys; print(len(os.listdir('/proc/' + sys.argv[1] + '/fd')))"

    assert {count, 0} =
             System.cmd(System.find_executable("python3"), ["-c", script, System.pid()])

    count |> String.trim() |> String.to_integer()
  end

  defp wait_reuse(fd), do: wait_until(fn -> Probe.reuse(fd) end, &match?({:ok, _}, &1)) |> elem(1)

  defp wait_finished do
    assert_receive {:native_complete, _phase}, 5000
  end

  defp wait_fd_count(expected), do: wait_until(&external_fd_count/0, &(&1 == expected))

  defp wait_until(function, complete?) do
    deadline = System.monotonic_time(:millisecond) + 5000
    wait_until(function, complete?, deadline)
  end

  defp wait_until(function, complete?, deadline) do
    value = function.()

    cond do
      complete?.(value) ->
        value

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("native operation did not reach required state: #{inspect(value)}")

      true ->
        wait_until(function, complete?, deadline)
    end
  end
end
