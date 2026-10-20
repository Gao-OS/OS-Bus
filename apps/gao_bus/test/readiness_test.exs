defmodule GaoBus.ReadinessTest do
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  test "Linux abstract notification sockets receive the fixed bounded readiness message" do
    name = "osbus-notify-#{System.pid()}-#{System.unique_integer([:positive])}"
    {:ok, socket} = :socket.open(:local, :dgram, :default)
    :ok = :socket.bind(socket, %{family: :local, path: <<0>> <> name})
    on_exit(fn -> :socket.close(socket) end)
    assert :ok = GaoBus.Readiness.notify("@" <> name)
    assert {:ok, "READY=1"} = :socket.recv(socket, 0, 1000)
  end

  test "standalone mode permits no manager but inherited mode requires notification" do
    assert :ok = GaoBus.Readiness.notify(nil)
    assert {:error, :missing_notify_socket} = GaoBus.Readiness.notify(nil, true)
  end

  test "malformed manager addresses never start a datagram operation" do
    for address <- ["", "relative", "@", "/tmp/a" <> <<0>>, String.duplicate("/", 108), 1] do
      assert {:error, :invalid_notify_socket} = GaoBus.Readiness.notify(address)
    end
  end
end
