defmodule GaoBusTest.E2E.UnixActorTest do
  use ExUnit.Case, async: true

  alias GaoBusTest.E2E.Actor.RawUnix
  alias GaoBusTest.E2E.Context

  @moduletag :tmp_dir

  test "H-03 independent actor transmits caller-supplied protocol bytes" do
    dir = Path.join(System.tmp_dir!(), "hr#{System.unique_integer([:positive])}")
    File.mkdir!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)
    path = Path.join(dir, "raw.sock")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)
    on_exit(fn -> :socket.close(listener) end)
    owner = self()

    start_supervised!(
      {Task,
       fn ->
         {:ok, socket} = :socket.accept(listener, 2_000)
         {:ok, bytes} = :socket.recv(socket, 5, 2_000)
         send(owner, {:independent_bytes, bytes})
         :ok = :socket.send(socket, "OK\r\n")
         :socket.close(socket)
       end}
    )

    context = %Context{tmpdir: Path.expand(dir), bus_address: "unix:path=#{path}"}
    assert {:ok, context} = RawUnix.start(context)
    assert :ok = RawUnix.send(context, <<0, 255, 1, 0, 7>>)
    assert_receive {:independent_bytes, <<0, 255, 1, 0, 7>>}
    assert {:ok, "OK\r\n"} = RawUnix.recv(context, 4, 2_000)
    assert {:ok, _context} = RawUnix.stop(context)
  end

  test "raw actor refuses implicit and out-of-fixture bus addresses", %{tmp_dir: dir} do
    for address <- [
          nil,
          "system",
          "unix:path=/run/dbus/system_bus_socket",
          "tcp:host=localhost,port=1"
        ] do
      context = %Context{tmpdir: dir, bus_address: address}
      assert {:error, :private_unix_address_required, ^context} = RawUnix.start(context)
    end
  end

  test "raw authentication bytes are independently constructed and may be malformed" do
    assert <<0, "AUTH EXTERNAL 31303030\r\n">> = RawUnix.external_auth(1000)
    assert <<0, "AUTH EXTERNAL 30\r\n">> = RawUnix.external_auth(0)
  end
end
