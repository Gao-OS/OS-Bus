defmodule GaoBus.ListenerOwnershipTest do
  use ExUnit.Case, async: false
  import Bitwise
  alias ExDBus.Message

  setup do
    Application.stop(:gao_bus)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-listen-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    %{directory: directory, path: Path.join(directory, "bus")}
  end

  test "SYS-02 a second daemon cannot replace an existing socket", %{path: path} do
    {:ok, original} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(original, %{family: :local, path: path})
    :ok = :socket.listen(original)
    before = File.lstat!(path)
    assert {:error, _reason} = start_listener(path)
    assert File.lstat!(path).inode == before.inode
    {:ok, client} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    assert {:ok, accepted} = :socket.accept(original, 1000)
    :gen_tcp.close(client)
    :socket.close(accepted)
    :socket.close(original)
  end

  test "SYS-02 a regular file is never removed", %{path: path} do
    File.write!(path, "existing data")
    assert {:error, _reason} = start_listener(path)
    assert File.read!(path) == "existing data"
  end

  test "SYS-02 a symlink endpoint is never followed or removed", %{
    path: path,
    directory: directory
  } do
    target = Path.join(directory, "target")
    File.write!(target, "existing data")
    File.ln_s!(target, path)
    assert {:error, _reason} = start_listener(path)
    assert File.read_link!(path) == target
    assert File.read!(target) == "existing data"
  end

  test "shutdown preserves a replacement at the former listener path", %{path: path} do
    assert {:ok, pid} = start_listener(path)
    File.rm!(path)
    File.write!(path, "replacement")
    GenServer.stop(pid)
    assert File.read!(path) == "replacement"
  end

  test "SYS-02 writable parent directories are refused", %{path: path, directory: directory} do
    File.chmod!(directory, 0o777)
    assert {:error, _reason} = start_listener(path)
    refute File.exists?(path)
  end

  test "SYS-02 symlink parents are refused", %{path: path, directory: directory} do
    linked = directory <> "-alias"
    File.ln_s!(directory, linked)
    on_exit(fn -> File.rm(linked) end)
    assert {:error, _reason} = start_listener(Path.join(linked, "bus"))
    refute File.exists?(path)
  end

  test "owned session sockets have explicit permissions and are removed on clean stop", %{
    path: path
  } do
    assert {:ok, pid} = start_listener(path)
    assert (File.lstat!(path).mode &&& 0o777) == 0o600
    GenServer.stop(pid)
    assert {:error, :enoent} = File.lstat(path)
  end

  test "FAIL-02 real non-owner transfer closes the accepted socket and removes the waiting peer",
       context do
    healthy = transfer_bus(context.path)
    before = DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active
    inode = File.lstat!(context.path).inode
    {accepted, client, holder} = accepted_socket(context.directory)
    assert {:ok, ^holder} = :socket.getopt(accepted, {:otp, :controlling_process})
    assert {:ok, peer} = GaoBus.PeerSupervisor.start_peer(accepted)
    assert nil == GaoBus.Peer.get_credentials(peer)
    assert DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active == before + 1
    monitor = Process.monitor(peer)

    assert {:error, {:invalid, :not_owner}} = GaoBus.Listener.transfer_ownership(accepted, peer)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :shutdown}
    assert {:error, :closed} = :socket.getopt(accepted, {:otp, :controlling_process})
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1000)
    assert DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active == before
    assert File.lstat!(context.path).inode == inode
    assert query(healthy.socket, "GetId", 3).body == healthy.id
    assert {:ok, _new_observer} = connect_and_register(context.path)
  end

  test "FAIL-02 OTP ownership monitoring closes a socket transferred to a real dead target",
       context do
    healthy = transfer_bus(context.path)
    before = DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active
    {accepted, client, holder} = accepted_socket(context.directory)
    send(holder, {:transfer_to, self()})
    assert_receive {:ownership_transferred, ^accepted}
    assert {:ok, peer} = GaoBus.PeerSupervisor.start_peer(accepted)
    monitor = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
    _ = :sys.get_state(GaoBus.PeerSupervisor)

    # OTP accepts the PID even after DOWN; its native ownership monitor closes
    # the socket. A dead PID does not exercise the setopt error branch.
    assert :ok = GaoBus.Listener.transfer_ownership(accepted, peer)
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1000)
    assert {:error, :closed} = :socket.getopt(accepted, {:otp, :controlling_process})
    assert DynamicSupervisor.count_children(GaoBus.PeerSupervisor).active == before
    assert query(healthy.socket, "GetId", 3).body == healthy.id
  end

  defp transfer_bus(path) do
    {:ok, _} = Application.ensure_all_started(:crypto)
    {uid, 0} = System.cmd("id", ["-u"])
    uid = String.to_integer(String.trim(uid))

    settings = [
      socket_path: path,
      profile: :session,
      cluster: false,
      policy_rules: [
        %{action: :connect, effect: :allow, match: %{uid: uid}},
        %{action: :send, effect: :allow, match: %{uid: uid}},
        %{action: :receive, effect: :allow, match: %{uid: uid}}
      ]
    ]

    previous =
      for {key, value} <- settings do
        old = Application.fetch_env(:gao_bus, key)
        Application.put_env(:gao_bus, key, value)
        {key, old}
      end

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, old} -> Application.put_env(:gao_bus, key, old)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end
    end)

    start_supervised!(%{id: :transfer_bus, start: {GaoBus.Application, :start, [:normal, []]}})
    assert {:ok, socket} = connect_and_register(path)
    %{socket: socket, id: query(socket, "GetId", 2).body}
  end

  defp accepted_socket(directory) do
    path = Path.join(directory, "transfer-fault")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)
    on_exit(fn -> :socket.close(listener) end)
    parent = self()

    holder =
      start_supervised!(
        {Task,
         fn ->
           {:ok, accepted} = :socket.accept(listener, 1000)
           send(parent, {:accepted, accepted})

           receive do
             {:transfer_to, target} ->
               :ok = :socket.setopt(accepted, {:otp, :controlling_process}, target)
               send(parent, {:ownership_transferred, accepted})
               receive do: (:stop -> :ok)

             :stop ->
               :ok
           end
         end},
        id: :accepted_socket_holder
      )

    assert {:ok, client} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    on_exit(fn -> :gen_tcp.close(client) end)
    assert_receive {:accepted, accepted}
    {accepted, client, holder}
  end

  defp connect_and_register(path) do
    with {:ok, socket} <-
           :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line], 1000) do
      on_exit(fn -> :gen_tcp.close(socket) end)
      {uid, 0} = System.cmd("id", ["-u"])
      encoded = uid |> String.trim() |> Base.encode16(case: :lower)
      :ok = :gen_tcp.send(socket, "\0AUTH EXTERNAL #{encoded}\r\n")
      assert {:ok, "OK " <> _guid} = :gen_tcp.recv(socket, 0, 1000)
      :ok = :inet.setopts(socket, packet: :raw)
      :ok = :gen_tcp.send(socket, "BEGIN\r\n")
      assert %Message{type: :method_return} = query(socket, "Hello", 1)
      {:ok, socket}
    end
  end

  defp query(socket, member, serial) do
    request =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus",
        serial: serial
      )

    :ok = :gen_tcp.send(socket, Message.encode_message(request))
    reply(socket, serial, System.monotonic_time(:millisecond) + 1000)
  end

  defp reply(socket, serial, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)
    assert remaining > 0
    assert {:ok, header} = :gen_tcp.recv(socket, 16, remaining)
    <<?l, _::binary-size(3), bytes::little-32, _::little-32, fields::little-32>> = header

    assert {:ok, rest} =
             :gen_tcp.recv(socket, fields + rem(8 - rem(fields, 8), 8) + bytes, remaining)

    assert {:ok, message, <<>>} = Message.decode_message(header <> rest)
    if message.reply_serial == serial, do: message, else: reply(socket, serial, deadline)
  end

  defp start_listener(path) do
    start_supervised(%{
      id: :listener_under_test,
      restart: :temporary,
      start: {GenServer, :start_link, [GaoBus.Listener, [socket_path: path], []]}
    })
  end
end
