defmodule GaoBus.Unix.ResourcesTest do
  use ExUnit.Case, async: false

  alias GaoBus.Unix.Resources

  @moduletag :tmp_dir

  setup %{tmp_dir: dir} do
    # Keep sockaddr_un under its platform length limit regardless of checkout path.
    path =
      Path.join(
        System.tmp_dir!(),
        "osbus-fd-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(path)
    File.chmod!(path, 0o700)
    socket_path = Path.join(path, "bus")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: socket_path})
    :ok = :socket.listen(listener)

    on_exit(fn ->
      :socket.close(listener)
      File.rm_rf!(path)
    end)

    %{listener: listener, socket_path: socket_path, tmp_dir: dir}
  end

  test "FD-01 arbitrary resources survive forwarding and close exactly once", context do
    {socket, actor} = actor(context, "roundtrip")
    before_count = fd_count()
    assert {:ok, "resources", handles} = Resources.recv(socket, 1024, 16)
    assert [_, _, _] = handles
    assert Enum.all?(handles, &(Resources.info(&1) == {:ok, %{cloexec: true}}))
    assert fd_count() == before_count + 3
    assert {:ok, 8} = Resources.send(socket, "returned", handles)
    assert :ok = Resources.close(handles)
    assert :ok = Resources.close(handles)
    assert fd_count() == before_count
    assert {:error, :closed} = Resources.send(socket, "again", handles)
    assert_actor(actor)
    :socket.close(socket)
  end

  test "FD-04 excess rights are rejected with all received descriptors closed", context do
    {socket, actor} = actor(context, "excess")
    before_count = fd_count()
    assert {:error, :control_truncated} = Resources.recv(socket, 1024, 16)
    assert fd_count() == before_count
    assert :ok = :socket.send(socket, "!")
    assert_actor(actor)
    :socket.close(socket)
  end

  test "FD-04 real credential-plus-rights control truncation reclaims installed FDs", context do
    {socket, actor} = actor(context, "control_truncated")
    before_count = external_fd_count()
    assert {:error, :control_truncated} = Resources.recv(socket, 1024, 253)
    assert external_fd_count() == before_count
    assert :ok = :socket.send(socket, "!")
    assert_actor(actor)
    :socket.close(socket)
  end

  test "FD-09 delivery copies close independently and retain CLOEXEC", context do
    {socket, actor} = actor(context, "roundtrip")
    assert {:ok, _, originals} = Resources.recv(socket, 1024, 16)
    assert {:ok, first} = Resources.duplicate(originals)
    assert {:ok, second} = Resources.duplicate(originals)
    assert :ok = Resources.close(originals)
    assert :ok = Resources.close(first)
    assert Enum.all?(second, &(Resources.info(&1) == {:ok, %{cloexec: true}}))
    assert {:ok, 8} = Resources.send(socket, "returned", second)
    assert :ok = Resources.close(second)
    assert_actor(actor)
    :socket.close(socket)
  end

  test "duplicate rolls back earlier copies when a later source is closed", context do
    {socket, actor} = actor(context, "discard")
    assert {:ok, _, [first, second, third] = originals} = Resources.recv(socket, 1024, 16)
    assert :ok = Resources.close([third])
    before_count = fd_count()
    assert {:error, :closed} = Resources.duplicate([first, second, third])
    assert fd_count() == before_count
    assert_raise ArgumentError, fn -> Resources.duplicate([first, :invalid_handle]) end
    assert fd_count() == before_count
    assert {:ok, []} = Resources.duplicate([])
    assert :ok = Resources.close(originals)
    assert :ok = :socket.send(socket, "!")
    assert_actor(actor)
    :socket.close(socket)
  end

  test "FD-08 independent delivery survives death of original resource owner", context do
    {socket, actor} = actor(context, "roundtrip")
    parent = self()

    owner =
      start_supervised!(
        {Task,
         fn ->
           receive do
             {:socket, socket} ->
               {:ok, _, originals} = Resources.recv(socket, 1024, 16)
               {:ok, copies} = Resources.duplicate(originals)
               :ok = :socket.setopt(socket, {:otp, :controlling_process}, parent)
               send(parent, {:copies, copies})

               receive do
                 :close -> Resources.close(originals)
               end
           end
         end}
      )

    :ok = :socket.setopt(socket, {:otp, :controlling_process}, owner)
    monitor = Process.monitor(owner)
    send(owner, {:socket, socket})
    assert_receive {:copies, copies}, 5000
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 5000
    assert {:ok, 8} = Resources.send(socket, "returned", copies)
    assert :ok = Resources.close(copies)
    assert_actor(actor)
    :socket.close(socket)
  end

  test "resource-bearing authentication bytes can be rejected without leaking", context do
    {socket, actor} = actor(context, "discard")
    before_count = fd_count()
    assert {:ok, _, handles} = Resources.recv(socket, 1024, 16)
    assert :ok = Resources.close(handles)
    assert fd_count() == before_count
    assert :ok = :socket.send(socket, "!")
    assert_actor(actor)
    :socket.close(socket)
  end

  test "FD-06 short send transfers rights once and reports the unsent byte tail", context do
    {socket, actor} = actor(context, "short_write")
    assert {:ok, _, handles} = Resources.recv(socket, 1024, 16)
    :ok = :socket.setopt(socket, {:socket, :sndbuf}, 1024)
    payload = :binary.copy("x", 65_536)
    assert {:ok, sent} = Resources.send(socket, payload, handles)
    assert sent > 0 and sent < byte_size(payload)
    remaining = binary_part(payload, sent, byte_size(payload) - sent)
    assert {:error, :eagain} = Resources.send(socket, remaining, [])
    Port.command(actor, "!")
    assert :ok = :socket.send(socket, remaining, [], 5_000)
    assert_actor(actor)
    assert :ok = Resources.close(handles)
    :socket.close(socket)
  end

  test "FD-08 process death releases resources without terminate callbacks", context do
    {socket, actor} = actor(context, "owner_exit")
    before_count = fd_count()
    parent = self()

    owner =
      start_supervised!(
        {Task,
         fn ->
           receive do
             {:socket, socket} ->
               {:ok, _, handles} = Resources.recv(socket, 1024, 16)
               send(parent, {:owned, self(), length(handles)})

               receive do
                 :close -> Resources.close(handles)
               end
           end
         end}
      )

    :ok = :socket.setopt(socket, {:otp, :controlling_process}, owner)
    ref = Process.monitor(owner)
    send(owner, {:socket, socket})
    assert_receive {:owned, ^owner, 3}, 5_000
    assert fd_count() == before_count + 3
    Process.exit(owner, :kill)
    assert_receive {:DOWN, ^ref, :process, ^owner, :killed}, 5_000
    # Socket owner death closes its accepted socket as well as its rights.
    assert fd_count() == before_count - 1
    assert_actor(actor)
  end

  defp actor(context, mode) do
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")
    source = Path.expand("../fixtures/resource_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        args: [source, context.socket_path, mode]
      ])

    {:ok, socket} = :socket.accept(context.listener, 5_000)

    if mode == "control_truncated" do
      # Linux SO_PASSCRED=16 uses the supported public native-option API.
      :ok = :socket.setopt_native(socket, {:socket, 16}, <<1::native-32>>)
      Port.command(port, "s")
    end

    # Readiness only: peek leaves ancillary rights with the actual receive operation.
    assert {:ok, _} = :socket.recv(socket, 1, [:peek], 5_000)
    {socket, port}
  end

  defp assert_actor(port) do
    Port.command(port, "q")
    assert_receive {^port, {:data, "RESOURCE_ACTOR_OK\n"}}, 5_000
    assert_receive {^port, {:exit_status, 0}}, 5_000
  end

  defp fd_count, do: length(File.ls!("/proc/self/fd"))

  defp external_fd_count do
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")
    script = "import os,sys; print(len(os.listdir('/proc/' + sys.argv[1] + '/fd')))"
    assert {count, 0} = System.cmd(executable, ["-c", script, System.pid()])
    count |> String.trim() |> String.to_integer()
  end
end
