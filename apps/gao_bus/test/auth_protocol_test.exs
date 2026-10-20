defmodule GaoBus.AuthProtocolTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message

  @rejected "REJECTED EXTERNAL\r\n"

  setup do
    Application.stop(:gao_bus)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-auth-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    socket_path = Path.join(directory, "bus")
    previous_path = Application.get_env(:gao_bus, :socket_path)
    Application.put_env(:gao_bus, :socket_path, socket_path)
    sup = start_supervised!(%{id: :test_bus, start: {GaoBus.Application, :start, [:normal, []]}})

    on_exit(fn ->
      if previous_path,
        do: Application.put_env(:gao_bus, :socket_path, previous_path),
        else: Application.delete_env(:gao_bus, :socket_path)

      File.rm_rf!(directory)
    end)

    %{socket_path: socket_path, sup: sup}
  end

  describe "SASL auth discovery" do
    test "bare AUTH returns supported mechanisms", %{socket_path: path} do
      sock = connect(path)

      assert send_auth_line(sock, "AUTH") == @rejected

      :socket.close(sock)
    end

    test "unsupported AUTH mechanism returns supported mechanisms", %{socket_path: path} do
      sock = connect(path)

      assert send_auth_line(sock, "AUTH BOGUS") == @rejected

      :socket.close(sock)
    end

    test "CANCEL rejects a pending EXTERNAL exchange", %{socket_path: path} do
      sock = connect(path)

      assert send_auth_line(sock, "AUTH EXTERNAL") == "DATA\r\n"
      assert send_line(sock, "CANCEL") == @rejected

      :socket.close(sock)
    end

    test "AUTH EXTERNAL with inline initial response succeeds", %{socket_path: path} do
      sock = connect(path)
      uid_hex = current_uid_hex()

      response = send_auth_line(sock, "AUTH EXTERNAL #{uid_hex}")

      assert String.starts_with?(response, "OK ")
      assert String.ends_with?(response, "\r\n")

      :socket.close(sock)
    end

    test "AUTH EXTERNAL accepts two-step DATA response", %{socket_path: path} do
      sock = connect(path)
      uid_hex = current_uid_hex()

      assert send_auth_line(sock, "AUTH EXTERNAL") == "DATA\r\n"
      assert send_line(sock, "DATA #{uid_hex}") |> String.starts_with?("OK ")

      :socket.close(sock)
    end

    test "AUTH EXTERNAL accepts bare DATA response and enters message protocol", %{
      socket_path: path
    } do
      sock = connect(path)

      assert send_auth_line(sock, "AUTH") == @rejected
      assert send_line(sock, "AUTH EXTERNAL") == "DATA\r\n"
      assert send_line(sock, "DATA") |> String.starts_with?("OK ")

      :ok = :socket.sendmsg(sock, %{iov: ["BEGIN\r\n"]})

      assert <<":1.", _rest::binary>> = do_hello(sock)

      :socket.close(sock)
    end

    test "unknown auth command returns ERROR", %{socket_path: path} do
      sock = connect(path)

      assert send_auth_line(sock, "FROB") |> String.starts_with?("ERROR")

      :socket.close(sock)
    end
  end

  defp connect(path) do
    {:ok, sock} = :socket.open(:local, :stream, :default)
    :ok = :socket.connect(sock, %{family: :local, path: path})
    sock
  end

  defp send_auth_line(sock, line) do
    :ok = :socket.sendmsg(sock, %{iov: [<<0>>, line, "\r\n"]})
    recv(sock)
  end

  defp send_line(sock, line) do
    :ok = :socket.sendmsg(sock, %{iov: [line, "\r\n"]})
    recv(sock)
  end

  defp recv(sock) do
    {:ok, msg} = :socket.recvmsg(sock, 0, 0, [], 5_000)
    IO.iodata_to_binary(msg.iov)
  end

  defp do_hello(sock) do
    hello =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello",
        serial: 1,
        destination: "org.freedesktop.DBus"
      )

    :ok = :socket.sendmsg(sock, %{iov: [Message.encode_message(hello)]})

    {:ok, reply_msg} = :socket.recvmsg(sock, 0, 0, [], 5_000)
    reply_data = IO.iodata_to_binary(reply_msg.iov)
    {:ok, reply, _rest} = Message.decode_message(reply_data)

    assert %{type: :method_return, body: [name]} = reply
    name
  end

  defp current_uid_hex do
    {uid, 0} = System.cmd("id", ["-u"])
    uid |> String.trim() |> Base.encode16(case: :lower)
  end
end
