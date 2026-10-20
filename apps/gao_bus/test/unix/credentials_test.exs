defmodule GaoBus.Unix.CredentialsTest do
  use ExUnit.Case, async: true

  alias GaoBus.Unix.Credentials

  test "reads the connected process identity from a private Unix socket" do
    # ExUnit's checkout-derived tmp_dir exceeds Linux's sockaddr_un limit here.
    directory = Path.join(System.tmp_dir!(), "gb-cred-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    path = Path.join(directory, "credentials.sock")

    on_exit(fn ->
      File.rm(path)
      File.rmdir(directory)
    end)

    {:ok, listener} = :socket.open(:local, :stream, :default)
    on_exit(fn -> :socket.close(listener) end)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)

    {:ok, client} = :socket.open(:local, :stream, :default)
    on_exit(fn -> :socket.close(client) end)
    :ok = :socket.connect(client, %{family: :local, path: path})
    {:ok, accepted} = :socket.accept(listener, 1_000)
    on_exit(fn -> :socket.close(accepted) end)

    # ps runs independently and inspects the BEAM actor's real credentials.
    {identity, 0} = System.cmd("ps", ["-o", "ruid=,rgid=,pid=", "-p", System.pid()])
    [uid, gid, pid] = identity |> String.split() |> Enum.map(&String.to_integer/1)

    assert {:ok, %{uid: ^uid, gid: ^gid, pid: ^pid}} = Credentials.read(accepted)
  end

  test "decodes the exact Linux ucred record including a legitimate root identity" do
    assert {:ok, %{pid: 42, uid: 0, gid: 0}} =
             Credentials.decode(
               <<42::native-signed-32, 0::native-unsigned-32, 0::native-unsigned-32>>
             )
  end

  test "UID and GID are unsigned fields" do
    assert {:ok, %{pid: 42, uid: 4_294_967_294, gid: 4_294_967_294}} =
             Credentials.decode(
               <<42::native-signed-32, 4_294_967_294::native-unsigned-32,
                 4_294_967_294::native-unsigned-32>>
             )
  end

  test "rejects truncated or oversized credential records without a fallback identity" do
    for record <- [<<>>, <<0::88>>, <<0::104>>] do
      assert {:error, :invalid_peer_credentials} = Credentials.decode(record)
    end
  end

  test "rejects invalid process identifiers and the unset UID or GID sentinel" do
    for {pid, uid, gid} <- [{0, 1, 1}, {-1, 1, 1}, {1, 4_294_967_295, 1}, {1, 1, 4_294_967_295}] do
      assert {:error, :invalid_peer_credentials} =
               Credentials.decode(
                 <<pid::native-signed-32, uid::native-unsigned-32, gid::native-unsigned-32>>
               )
    end
  end

  test "a failed socket query never supplies asserted or zero credentials" do
    assert {:error, _reason} = Credentials.read(:not_a_socket)
  end
end
