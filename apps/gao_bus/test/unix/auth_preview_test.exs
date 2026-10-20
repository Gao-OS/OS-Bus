defmodule GaoBus.Unix.AuthPreviewTest do
  use ExUnit.Case, async: false

  alias GaoBus.Unix.Resources

  setup do
    assert {:unix, :linux} = :os.type()

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-preview-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    socket_path = Path.join(directory, "bus")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: socket_path})
    :ok = :socket.listen(listener)

    on_exit(fn ->
      :socket.close(listener)
      File.rm_rf!(directory)
    end)

    %{
      listener: listener,
      socket_path: socket_path,
      directory: directory,
      fd_count_before_actor: external_fd_count()
    }
  end

  test "positive-length timeout-zero peek preserves empty, partial and full prefixes", context do
    {socket, owned, actor} = actor(context)

    try do
      assert_peeks(socket, actor, 8, {:error, :timeout})

      command(actor, "partial", "PARTIAL")
      assert_peeks(socket, actor, 8, {:error, {:timeout, "BEG"}})
      assert {:ok, "BE", []} = Resources.recv(owned, 2, 1)
      assert_peeks(socket, actor, 8, {:error, {:timeout, "G"}})
      assert {:ok, "G", []} = Resources.recv(owned, 1, 1)
      assert {:error, :eagain} = Resources.recv(owned, 8, 1)

      command(actor, "full", "FULL")
      assert_peeks(socket, actor, 8, {:ok, "BEGIN\r\nl"})
      assert {:ok, "BEGI", []} = Resources.recv(owned, 4, 1)
      assert_peeks(socket, actor, 8, {:error, {:timeout, "N\r\nl"}})
      assert {:ok, "N\r\nl", []} = Resources.recv(owned, 4, 1)
      assert {:error, :eagain} = Resources.recv(owned, 8, 1)

      command(actor, "eof", "EOF")
      assert_peeks(socket, actor, 8, {:error, :closed})
      assert {:error, :closed} = Resources.recv(owned, 8, 1)
    after
      assert :ok = Resources.close([owned])
      assert :ok = :socket.close(socket)
    end

    finish_actor(actor, context)
  end

  test "wide data-only peeks retain rights after BEGIN until the next native receive", context do
    {socket, owned, actor} = actor(context)

    try do
      command(actor, "begin_rights", "BEGIN_RIGHTS")
      baseline = fd_snapshot(actor)
      prefix = "BEGIN\r\nl"

      # Both writes completed before the acknowledgement. The preview must span
      # the clean auth line and the separately rights-bearing first binary byte.
      assert_peeks(socket, actor, 64, {:error, {:timeout, prefix}})
      assert fd_snapshot(actor) == baseline
      assert {lf, 1} = :binary.match(prefix, "\n")
      assert lf + 1 == byte_size("BEGIN\r\n")
      assert {:ok, "BEGIN\r\n", []} = Resources.recv(owned, lf + 1, 1)
      assert fd_snapshot(actor) == baseline

      assert_peeks(socket, actor, 64, {:error, {:timeout, "l"}})
      assert {:ok, "l", [handle] = handles} = Resources.recv(owned, 1, 1)

      try do
        assert {:ok, %{cloexec: true}} = Resources.info(handle)
        {before_count, _} = baseline
        {after_count, _} = fd_snapshot(actor)
        assert after_count == before_count + 1
        assert {:error, :eagain} = Resources.recv(owned, 1, 1)

        # An independent process must receive precisely one usable descriptor.
        assert {:ok, 8} = Resources.send(owned, "returned", handles)
        command(actor, "return", "PIPE_OK")
      after
        assert :ok = Resources.close(handles)
      end

      assert :ok = Resources.close(handles)
      assert fd_snapshot(actor) == baseline
      assert {:error, :eagain} = Resources.recv(owned, 1, 1)
      command(actor, "tail", "TAIL")
      assert {:ok, "tail", []} = Resources.recv(owned, 4, 1)
      assert {:error, :eagain} = Resources.recv(owned, 1, 1)
      assert_peeks(socket, actor, 64, {:error, :timeout})
      assert fd_snapshot(actor) == baseline
    after
      assert :ok = Resources.close([owned])
      assert :ok = :socket.close(socket)
    end

    finish_actor(actor, context)
  end

  defp actor(context) do
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")
    source = Path.expand("../fixtures/auth_preview_actor.py", __DIR__)

    port =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        {:line, 65_536},
        args: ["-I", "-B", source, context.socket_path, System.pid()]
      ])

    on_exit(fn ->
      if Port.info(port), do: Port.close(port)
    end)

    assert {:ok, socket} = :socket.accept(context.listener, 5_000)
    assert_line(port, "READY")
    assert {:ok, owned} = Resources.capture(socket)
    {socket, owned, port}
  end

  defp assert_peeks(socket, actor, bound, expected) when bound > 0 do
    before = fd_snapshot(actor)

    for _ <- 1..16 do
      assert :socket.recv(socket, bound, [:peek], 0) == expected
      assert_no_async_read(socket)
      assert fd_snapshot(actor) == before
      assert_no_async_read(socket)
    end
  end

  defp assert_no_async_read(socket) do
    assert %{num_readers: 0, rstates: states} = :socket.info(socket)
    refute :selected in states
    refute :busy in states
    refute_received {:"$socket", ^socket, :select, _}
    refute_received {:"$socket", ^socket, :abort, _}
    refute_received {:"$socket", ^socket, :completion, _}
  end

  defp fd_snapshot(actor) do
    true = Port.command(actor, "snapshot\n")
    assert_receive {^actor, {:data, {:eol, line}}}, 5_000
    assert ["FD_MAP", count, inventory] = String.split(line, "\t", parts: 3)
    {String.to_integer(count), inventory}
  end

  defp command(actor, request, response) do
    true = Port.command(actor, request <> "\n")
    assert_line(actor, response)
  end

  defp assert_line(actor, expected) do
    assert_receive {^actor, {:data, {:eol, ^expected}}}, 5_000
  end

  defp finish_actor(actor, context) do
    command(actor, "quit", "AUTH_PREVIEW_ACTOR_OK")
    assert_receive {^actor, {:exit_status, 0}}, 5_000
    assert external_fd_count() == context.fd_count_before_actor
    assert :ok = :socket.close(context.listener)
    assert external_fd_count() == context.fd_count_before_actor - 1
    File.rm!(context.socket_path)
    File.rmdir!(context.directory)
    refute File.exists?(context.directory)
  end

  defp external_fd_count do
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")
    script = "import os,sys; print(len(os.listdir('/proc/' + sys.argv[1] + '/fd')))"
    assert {count, 0} = System.cmd(executable, ["-I", "-B", "-c", script, System.pid()])
    count |> String.trim() |> String.to_integer()
  end
end
