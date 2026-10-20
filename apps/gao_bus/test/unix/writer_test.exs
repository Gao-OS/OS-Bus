defmodule GaoBus.Unix.WriterTest do
  use ExUnit.Case, async: false

  alias GaoBus.Unix.{Resources, Writer}

  @actor ~S"""
  import array,os,socket,sys
  s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
  s.settimeout(5)
  s.connect(sys.argv[1])
  fd=os.memfd_create('osbus-writer',os.MFD_CLOEXEC)
  os.write(fd,b'intended-resource')
  s.sendmsg([b'R'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
  command=sys.stdin.buffer.readline().split()
  if command==[b'CLOSE']:
      os.close(fd);s.close();sys.exit(0)
  assert command[0]==b'DRAIN'
  prefix=int(command[1]) if len(command)>1 else 0
  payload=b''; rights=[]
  while len(payload)<131072+prefix:
      data,control,flags,_=s.recvmsg(1024,socket.CMSG_SPACE(253*4),socket.MSG_CMSG_CLOEXEC)
      assert data and not flags & socket.MSG_CTRUNC
      payload+=data
      for level,kind,raw in control:
          assert (level,kind)==(socket.SOL_SOCKET,socket.SCM_RIGHTS)
          received=array.array('i');received.frombytes(raw);rights.extend(received)
      print('PROGRESS',flush=True)
  assert payload==b'p'*prefix+bytes(range(256))*512
  assert len(rights)==1
  assert os.pread(rights[0],64,0)==b'intended-resource'
  for received in rights:os.close(received)
  os.close(fd)
  print('WRITER_ACTOR_OK',flush=True)
  s.close()
  """

  @moduletag :tmp_dir

  defp actor(%{tmp_dir: directory}) do
    private = Path.join(System.tmp_dir!(), "osbus-writer-#{System.unique_integer([:positive])}")
    File.mkdir!(private)
    File.chmod!(private, 0o700)
    path = Path.join(private, "socket")
    source = Path.join(directory, "actor.py")
    File.write!(source, @actor)
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)

    actor =
      Port.open(
        {:spawn_executable, System.find_executable("python3")},
        [:binary, :exit_status, args: [source, path]]
      )

    {:ok, socket} = :socket.accept(listener, 5000)
    assert {:ok, _} = :socket.recv(socket, 1, [:peek], 5000)
    assert {:ok, "R", handles} = Resources.recv(socket, 1024)

    on_exit(fn ->
      Resources.close(handles)
      :socket.close(socket)
      :socket.close(listener)
      if Port.info(actor), do: Port.close(actor)
      File.rm_rf!(private)
    end)

    %{socket: socket, handles: handles, actor: actor}
  end

  test "FD-06 short writes deliver exact bytes and rights only once", ctx do
    ctx = actor(ctx)
    :ok = :socket.setopt(ctx.socket, {:socket, :sndbuf}, 1024)
    bytes = :binary.list_to_bin(Enum.to_list(0..255)) |> :binary.copy(512)
    assert {:ok, writer} = Writer.new(bytes, ctx.handles, now())
    assert {:wait, writer} = Writer.step(ctx.socket, writer, now())
    assert writer.offset > 0 and writer.offset < 65536
    assert writer.rights_sent
    assert {:wait, blocked} = Writer.step(ctx.socket, writer, now())
    assert blocked.offset == writer.offset
    assert {:ok, false} = Resources.writable?(ctx.socket)
    assert {:wait, again} = Writer.step(ctx.socket, blocked, now())
    assert again.offset == blocked.offset
    Port.command(ctx.actor, "DRAIN\n")
    assert {:done, final} = drive(ctx, again)
    assert final.offset == byte_size(bytes)
    assert_receive {actor, {:exit_status, 0}}, 5000
    assert actor == ctx.actor
  end

  test "absolute deadline expires a queued writer without another send" do
    assert {:ok, writer} = Writer.new("waiting", [], 100, timeout_ms: 10)
    assert {:error, :send_timeout, expired} = Writer.step(nil, writer, 110)
    assert expired.offset == 0
    refute expired.rights_sent
  end

  test "writer rejects unbounded or malformed configuration" do
    assert {:error, :invalid_writer} = Writer.new("", [], 0)
    assert {:error, :invalid_writer} = Writer.new(:binary.copy("x", 1_048_577), [], 0)

    for options <- [[timeout_ms: 0], [timeout_ms: :infinity], [timeout_ms: 60001], [other: 1]] do
      assert {:error, :invalid_writer} = Writer.new("x", [], 0, options)
    end
  end

  test "FD-06 initial EAGAIN retains rights until the first positive send", context do
    ctx = actor(context)
    :ok = :socket.setopt(ctx.socket, {:socket, :sndbuf}, 1024)
    assert {:ok, prefix} = Resources.send(ctx.socket, :binary.copy("p", 65536))
    assert prefix > 0 and prefix < 65536
    bytes = :binary.list_to_bin(Enum.to_list(0..255)) |> :binary.copy(512)
    assert {:ok, writer} = Writer.new(bytes, ctx.handles, now())
    assert {:wait, blocked} = Writer.step(ctx.socket, writer, now())
    assert blocked.offset == 0
    refute blocked.rights_sent
    assert blocked.blocked
    Port.command(ctx.actor, "DRAIN #{prefix}\n")
    assert {:done, final} = drive(ctx, blocked)
    assert final.rights_sent
    assert_receive {actor, {:exit_status, 0}}, 5000
    assert actor == ctx.actor
  end

  test "FD-07 closed blocked recipient produces a terminal error", context do
    ctx = actor(context)
    :ok = :socket.setopt(ctx.socket, {:socket, :sndbuf}, 1024)
    assert {:ok, _} = Resources.send(ctx.socket, :binary.copy("p", 65536))
    assert {:ok, writer} = Writer.new("pending", ctx.handles, now())
    assert {:wait, blocked} = Writer.step(ctx.socket, writer, now())
    Port.command(ctx.actor, "CLOSE\n")
    assert_receive {actor, {:exit_status, 0}}, 5000
    assert actor == ctx.actor
    assert {:error, :closed, failed} = Writer.step(ctx.socket, blocked, now())
    assert failed.offset == 0
    refute failed.rights_sent
  end

  defp drive(ctx, writer) do
    case Writer.step(ctx.socket, writer, now()) do
      {:done, _} = done ->
        done

      {:wait, next} ->
        receive do
          {actor, {:data, _progress}} when actor == ctx.actor -> drive(ctx, next)
        after
          5000 -> flunk("independent slow reader made no progress")
        end

      {:error, reason, _} ->
        flunk("writer failed: #{inspect(reason)}")
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
end
