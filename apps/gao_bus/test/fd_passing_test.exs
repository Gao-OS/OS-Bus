defmodule GaoBus.FdPassingTest do
  @moduledoc """
  Unix FD negotiation and actual resource delivery through an isolated bus.
  Independent clients use transferred pipes, files and sockets and close every
  received descriptor; no raw descriptor is imported into the test BEAM.
  """

  use ExUnit.Case, async: false

  alias ExDBus.Message

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(System.tmp_dir!(), "gb-fd-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    {uid, 0} = System.cmd("id", ["-u"])
    uid = String.to_integer(String.trim(uid))

    options = [
      socket_path: path,
      profile: :system,
      cluster: false,
      policy_rules:
        Enum.map(
          [:connect, :own, :send, :receive],
          &%{action: &1, effect: :allow, match: %{uid: uid}}
        )
    ]

    previous = Enum.map(options, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    for {key, value} <- options, do: Application.put_env(:gao_bus, key, value)
    start_supervised!(%{id: :fd_test_bus, start: {GaoBus.Application, :start, [:normal, []]}})

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, setting} -> Application.put_env(:gao_bus, key, setting)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end

      File.rm_rf!(directory)
    end)

    %{path: path, uid: uid}
  end

  describe "NEGOTIATE_UNIX_FD auth" do
    test "kernel-bound EXTERNAL authentication agrees to FD passing", context do
      socket = authenticate(context)
      :ok = :gen_tcp.send(socket, "NEGOTIATE_UNIX_FD\r\n")
      assert line(socket) == "AGREE_UNIX_FD\r\n"
      assert_hello(socket)
    end

    test "regular EXTERNAL authentication works without FD negotiation", context do
      context |> authenticate() |> assert_hello()
    end
  end

  describe "FD passing through bus" do
    test "SCM_RIGHTS transfers usable pipe, file and socket resources", %{path: path} do
      assert_actor(path, "resources")
    end

    test "coalesced frames retain their own FD counts and resource indices", %{path: path} do
      assert_actor(path, "coalesced")
    end

    test "resource delivery is rejected when the recipient did not negotiate FDs", %{path: path} do
      assert_actor(path, "unnegotiated")
    end
  end

  defp authenticate(%{path: path, uid: uid}) do
    assert {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1500)
    on_exit(fn -> :gen_tcp.close(socket) end)
    identity = uid |> Integer.to_string() |> Base.encode16()
    :ok = :gen_tcp.send(socket, <<0>> <> "AUTH EXTERNAL " <> identity <> "\r\n")
    assert "OK " <> _guid = line(socket)
    socket
  end

  defp assert_hello(socket) do
    :ok = :gen_tcp.send(socket, "BEGIN\r\n" <> call("Hello", 1))
    assert %Message{type: :method_return, reply_serial: 1, body: [name]} = reply(socket, 1)
    assert String.starts_with?(name, ":1.")
    :ok = :gen_tcp.send(socket, call("ListNames", 2))
    assert %Message{type: :method_return, reply_serial: 2, body: [names]} = reply(socket, 2)
    assert name in names
  end

  defp call(member, serial) do
    Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
      serial: serial,
      destination: "org.freedesktop.DBus"
    )
    |> Message.encode_message()
  end

  defp line(socket, bytes \\ <<>>) do
    assert {:ok, byte} = :gen_tcp.recv(socket, 1, 1500)
    bytes = bytes <> byte
    if String.ends_with?(bytes, "\r\n"), do: bytes, else: line(socket, bytes)
  end

  defp reply(socket, serial) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, 1500)

    assert {:ok, tail} = :gen_tcp.recv(socket, header + rem(8 - rem(header, 8), 8) + body, 1500)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    if message.reply_serial == serial, do: message, else: reply(socket, serial)
  end

  defp assert_actor(path, mode) do
    executable = System.find_executable("python3") || flunk("required Python actor unavailable")
    source = Path.expand("fixtures/transport_actor.py", __DIR__)
    {output, result} = System.cmd(executable, [source, path, mode], stderr_to_stdout: true)
    assert result == 0, output
    assert %{"result" => "PASS", "scenario" => ^mode} = Jason.decode!(output)
  end
end
