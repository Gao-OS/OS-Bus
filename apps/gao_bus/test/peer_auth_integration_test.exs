defmodule GaoBus.PeerAuthIntegrationTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{NameRegistry, PeerSupervisor}

  setup do
    Application.stop(:gao_bus)
    {:ok, _apps} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "gb-peer-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    old_path = Application.get_env(:gao_bus, :socket_path)
    old_limits = Application.get_env(:gao_bus, :auth_limits)
    Application.put_env(:gao_bus, :socket_path, path)

    Application.put_env(:gao_bus, :auth_limits,
      idle_timeout_ms: 500,
      timeout_ms: 1000,
      max_lines_per_turn: 1
    )

    start_supervised!(%{id: :peer_test_bus, start: {GaoBus.Application, :start, [:normal, []]}})

    on_exit(fn ->
      restore(:socket_path, old_path)
      restore(:auth_limits, old_limits)
      File.rm_rf!(directory)
    end)

    %{path: path}
  end

  test "coalesced auth and calls wait for the explicit Hello reply", %{path: path} do
    socket = connect(path)

    :ok =
      :gen_tcp.send(
        socket,
        auth_line() <> "BEGIN\r\n" <> call("Hello", 1) <> call("ListNames", 2)
      )

    assert "OK " <> _guid = auth_response(socket)
    assert %Message{type: :method_return, reply_serial: 1, body: [name]} = reply(socket)
    assert %Message{type: :method_return, reply_serial: 2, body: [names]} = reply(socket, 2)
    assert name in names
    assert {:ok, _peer} = NameRegistry.resolve(name)
  end

  test "Hello with NO_REPLY_EXPECTED still returns the registration identity", %{path: path} do
    socket = connect(path)
    <<prefix::binary-size(2), _flags, tail::binary>> = call("Hello", 1)
    :ok = :gen_tcp.send(socket, auth_line() <> "BEGIN\r\n" <> prefix <> <<1>> <> tail)
    assert "OK " <> _guid = auth_response(socket)
    assert %Message{type: :method_return, reply_serial: 1, body: [name]} = reply(socket, 1)
    :ok = :gen_tcp.send(socket, call("ListNames", 2))
    assert %Message{type: :method_return, body: [names]} = reply(socket, 2)
    assert name in names
  end

  test "real idle timer closes a successful handshake missing BEGIN and preserves a healthy peer",
       %{path: path} do
    healthy = connect(path)
    :ok = :gen_tcp.send(healthy, auth_line() <> "BEGIN\r\n" <> call("Hello", 1))
    assert "OK " <> _guid = auth_response(healthy)
    assert %Message{type: :method_return, body: [name]} = reply(healthy, 1)
    {:ok, healthy_peer} = NameRegistry.resolve(name)

    unfinished = connect(path)
    :ok = :gen_tcp.send(unfinished, auth_line())
    assert "OK " <> _guid = auth_response(unfinished)
    assert {:error, :closed} = :gen_tcp.recv(unfinished, 0, 1500)

    assert {:ok, ^healthy_peer} = NameRegistry.resolve(name)
    :ok = :gen_tcp.send(healthy, call("ListNames", 2))
    assert %Message{type: :method_return, body: [names]} = reply(healthy, 2)
    assert name in names
  end

  test "a normal socket close retires the peer instead of restarting a zombie", %{path: path} do
    socket = connect(path)
    :ok = :gen_tcp.send(socket, auth_line() <> "BEGIN\r\n" <> call("Hello", 1))
    assert "OK " <> _guid = auth_response(socket)
    assert %Message{type: :method_return, body: [name]} = reply(socket, 1)
    {:ok, peer} = NameRegistry.resolve(name)
    ref = Process.monitor(peer)
    :gen_tcp.close(socket)
    assert_receive {:DOWN, ^ref, :process, ^peer, :normal}, 1500
    assert [] = DynamicSupervisor.which_children(PeerSupervisor)
    # Router observes DOWN separately, then casts the name retirement.
    await_name_retired(name, System.monotonic_time(:millisecond) + 1500)
    assert {:error, :name_not_found} = NameRegistry.resolve(name)
  end

  test "resource-bearing auth closes the connection and every daemon-owned pipe descriptor", %{
    path: path
  } do
    # Warm the real transport and leave a healthy registered peer throughout.
    healthy = connect(path)
    :ok = :gen_tcp.send(healthy, auth_line() <> "BEGIN\r\n" <> call("Hello", 1))
    assert "OK " <> _guid = auth_response(healthy)
    assert %Message{type: :method_return, body: [name]} = reply(healthy, 1)
    before_count = external_fd_count()

    actor = """
    import array, os, socket, sys
    reader, writer = os.pipe()
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(sys.argv[1])
            identity = str(os.getuid()).encode().hex().encode()
            client.sendmsg([b'\\x00AUTH EXTERNAL ' + identity + b'\\r\\n'],
                           [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [reader]))])
            # Closing with unread authentication bytes may produce a reset;
            # both kernel outcomes must be terminal, with no accepted reply.
            try:
                assert client.recv(1) == b''
            except ConnectionResetError:
                pass
        print('PEER_RESOURCES_REJECTED')
    finally:
        os.close(reader)
        os.close(writer)
    """

    assert {"PEER_RESOURCES_REJECTED\n", 0} = System.cmd(python!(), ["-c", actor, path])
    assert external_fd_count() == before_count
    :ok = :gen_tcp.send(healthy, call("ListNames", 2))
    assert %Message{type: :method_return, body: [names]} = reply(healthy, 2)
    assert name in names
  end

  defp await_name_retired(name, deadline) do
    case NameRegistry.resolve(name) do
      {:error, :name_not_found} ->
        :ok

      result ->
        assert System.monotonic_time(:millisecond) < deadline,
               "name was not retired: #{inspect(result)}"

        await_name_retired(name, deadline)
    end
  end

  defp connect(path) do
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    on_exit(fn -> :gen_tcp.close(socket) end)
    socket
  end

  defp auth_line do
    {uid, 0} = System.cmd("id", ["-u"])
    <<0>> <> "AUTH EXTERNAL " <> Base.encode16(String.trim(uid)) <> "\r\n"
  end

  defp auth_response(socket, bytes \\ <<>>) do
    assert {:ok, byte} = :gen_tcp.recv(socket, 1, 1500)
    bytes = bytes <> byte
    if String.ends_with?(bytes, "\r\n"), do: bytes, else: auth_response(socket, bytes)
  end

  # Independent ingress follows the specification's fixed header and variants.
  defp call(member, serial) do
    fields = [
      {1, "o", "/org/freedesktop/DBus"},
      {2, "s", "org.freedesktop.DBus"},
      {3, "s", member},
      {6, "s", "org.freedesktop.DBus"}
    ]

    header =
      Enum.reduce(fields, <<>>, fn {code, type, value}, acc ->
        acc <>
          padding(byte_size(acc)) <>
          <<code, 1>> <> type <> <<0, byte_size(value)::little-32>> <> value <> <<0>>
      end)

    <<?l, 1, 0, 1, 0::little-32, serial::little-32, byte_size(header)::little-32>> <>
      header <> padding(byte_size(header))
  end

  defp padding(size), do: :binary.copy(<<0>>, rem(8 - rem(size, 8), 8))

  defp external_fd_count do
    script = "import os,sys; print(len(os.listdir('/proc/' + sys.argv[1] + '/fd')))"
    {count, 0} = System.cmd(python!(), ["-c", script, System.pid()])
    String.to_integer(String.trim(count))
  end

  defp python!,
    do: System.find_executable("python3") || flunk("required Python actor unavailable")

  defp reply(socket, wanted_serial \\ nil) do
    assert {:ok,
            <<?l, _type, _flags, _version, body::little-32, _serial::little-32,
              header::little-32>> = prefix} = :gen_tcp.recv(socket, 16, 1500)

    remaining = header + rem(8 - rem(header, 8), 8) + body
    assert {:ok, tail} = :gen_tcp.recv(socket, remaining, 1500)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)

    if wanted_serial == nil or message.reply_serial == wanted_serial,
      do: message,
      else: reply(socket, wanted_serial)
  end

  defp restore(key, nil), do: Application.delete_env(:gao_bus, key)
  defp restore(key, value), do: Application.put_env(:gao_bus, key, value)
end
