defmodule GaoBus.IntegrationTest do
  use ExUnit.Case

  alias ExDBus.{Connection, Message}

  @moduletag :integration

  setup do
    Application.stop(:gao_bus)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-integration-#{System.pid()}-#{System.unique_integer([:positive])}"
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

  defp connect_client(socket_path) do
    {:ok, conn} =
      Connection.start_link(
        address: "unix:path=#{socket_path}",
        auth_mod: ExDBus.Auth.External,
        owner: self()
      )

    assert_receive {:ex_d_bus, {:connected, _guid}}, 5_000
    conn
  end

  defp call_hello(conn) do
    msg =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello",
        destination: "org.freedesktop.DBus"
      )

    {:ok, reply} = Connection.call(conn, msg, 5_000)
    assert reply.type == :method_return
    [unique_name] = reply.body
    assert String.starts_with?(unique_name, ":1.")
    unique_name
  end

  describe "bus lifecycle" do
    test "start and stop bus", %{socket_path: path} do
      assert File.exists?(path)
    end

    test "client connects and authenticates", %{socket_path: path} do
      conn = connect_client(path)
      assert Connection.get_state(conn) == :connected
      Connection.disconnect(conn)
    end
  end

  describe "org.freedesktop.DBus.Hello" do
    test "assigns unique name", %{socket_path: path} do
      conn = connect_client(path)
      name = call_hello(conn)
      assert name =~ ~r/^:1\.\d+$/
      Connection.disconnect(conn)
    end

    test "two clients get different names", %{socket_path: path} do
      conn_a = connect_client(path)
      conn_b = connect_client(path)
      name_a = call_hello(conn_a)
      name_b = call_hello(conn_b)

      assert name_a != name_b

      Connection.disconnect(conn_a)
      Connection.disconnect(conn_b)
    end
  end

  describe "org.freedesktop.DBus.ListNames" do
    test "lists registered names", %{socket_path: path} do
      conn = connect_client(path)
      name = call_hello(conn)

      msg =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames",
          destination: "org.freedesktop.DBus"
        )

      {:ok, reply} = Connection.call(conn, msg, 5_000)
      [names] = reply.body

      assert "org.freedesktop.DBus" in names
      assert name in names

      Connection.disconnect(conn)
    end
  end

  describe "org.freedesktop.DBus.RequestName / ReleaseName" do
    test "request and release a well-known name", %{socket_path: path} do
      conn = connect_client(path)
      _name = call_hello(conn)

      # RequestName
      req =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
          destination: "org.freedesktop.DBus",
          signature: "su",
          body: ["com.example.Test", 0]
        )

      {:ok, reply} = Connection.call(conn, req, 5_000)
      # DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER
      assert reply.body == [1]

      # GetNameOwner
      get =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner",
          destination: "org.freedesktop.DBus",
          signature: "s",
          body: ["com.example.Test"]
        )

      {:ok, reply} = Connection.call(conn, get, 5_000)
      assert reply.type == :method_return

      # ReleaseName
      rel =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "ReleaseName",
          destination: "org.freedesktop.DBus",
          signature: "s",
          body: ["com.example.Test"]
        )

      {:ok, reply} = Connection.call(conn, rel, 5_000)
      # DBUS_RELEASE_NAME_REPLY_RELEASED
      assert reply.body == [1]

      Connection.disconnect(conn)
    end
  end

  describe "peer-to-peer method call" do
    test "client A calls client B, gets response", %{socket_path: path} do
      conn_a = connect_client(path)
      conn_b = connect_client(path)
      _name_a = call_hello(conn_a)
      _name_b = call_hello(conn_b)

      # B registers a well-known name
      req =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName",
          destination: "org.freedesktop.DBus",
          signature: "su",
          body: ["com.example.Service", 0]
        )

      {:ok, _} = Connection.call(conn_b, req, 5_000)

      # A sends a method_call to B's well-known name (async so we can handle B's response)
      call_msg =
        Message.method_call("/com/example/Object", "com.example.Interface", "DoStuff",
          destination: "com.example.Service",
          signature: "s",
          body: ["ping"]
        )

      # Use Task.async for A's call so test process can receive B's incoming message
      task =
        Task.async(fn ->
          Connection.call(conn_a, call_msg, 10_000)
        end)

      # B's connection dispatches the method_call to us (the owner)
      # Drain any signals (NameOwnerChanged etc.) until we get the method_call
      incoming = receive_method_call(5_000)
      assert incoming.member == "DoStuff"
      assert incoming.body == ["ping"]

      # Send reply from B
      reply =
        Message.method_return(incoming.serial,
          destination: incoming.sender,
          signature: "s",
          body: ["pong"]
        )

      Connection.cast(conn_b, reply)

      # A should receive the reply
      {:ok, a_reply} = Task.await(task, 10_000)
      assert a_reply.type == :method_return
      assert a_reply.body == ["pong"]

      Connection.disconnect(conn_a)
      Connection.disconnect(conn_b)
    end
  end

  describe "org.freedesktop.DBus.NameHasOwner" do
    test "returns true for existing name", %{socket_path: path} do
      conn = connect_client(path)
      _name = call_hello(conn)

      msg =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner",
          destination: "org.freedesktop.DBus",
          signature: "s",
          body: ["org.freedesktop.DBus"]
        )

      {:ok, reply} = Connection.call(conn, msg, 5_000)
      assert reply.body == [true]

      Connection.disconnect(conn)
    end

    test "returns false for non-existent name", %{socket_path: path} do
      conn = connect_client(path)
      _name = call_hello(conn)

      msg =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner",
          destination: "org.freedesktop.DBus",
          signature: "s",
          body: ["com.does.not.exist"]
        )

      {:ok, reply} = Connection.call(conn, msg, 5_000)
      assert reply.body == [false]

      Connection.disconnect(conn)
    end
  end

  describe "org.freedesktop.DBus.AddMatch / RemoveMatch" do
    test "AddMatch and RemoveMatch succeed", %{socket_path: path} do
      conn = connect_client(path)
      _name = call_hello(conn)

      # AddMatch
      add =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "AddMatch",
          destination: "org.freedesktop.DBus",
          signature: "s",
          body: ["type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'"]
        )

      {:ok, reply} = Connection.call(conn, add, 5_000)
      assert reply.type == :method_return

      # RemoveMatch
      rem_msg =
        Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", "RemoveMatch",
          destination: "org.freedesktop.DBus",
          signature: "s",
          body: ["type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'"]
        )

      {:ok, reply} = Connection.call(conn, rem_msg, 5_000)
      assert reply.type == :method_return

      Connection.disconnect(conn)
    end
  end

  describe "org.freedesktop.DBus.Introspectable.Introspect" do
    test "returns valid XML", %{socket_path: path} do
      conn = connect_client(path)
      _name = call_hello(conn)

      msg =
        Message.method_call(
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus.Introspectable",
          "Introspect",
          destination: "org.freedesktop.DBus"
        )

      {:ok, reply} = Connection.call(conn, msg, 5_000)
      assert reply.type == :method_return
      [xml] = reply.body

      assert String.contains?(xml, "org.freedesktop.DBus")
      assert String.contains?(xml, "org.freedesktop.DBus.Introspectable")
      assert String.contains?(xml, "<method name=\"Hello\">")
      assert String.contains?(xml, "<method name=\"AddMatch\">")
      assert String.contains?(xml, "<signal name=\"NameOwnerChanged\">")

      # Parse it back
      assert {:ok, _path, interfaces, _children} = ExDBus.Introspection.from_xml(xml)
      iface_names = Enum.map(interfaces, & &1.name)
      assert "org.freedesktop.DBus" in iface_names
      assert "org.freedesktop.DBus.Introspectable" in iface_names

      Connection.disconnect(conn)
    end
  end

  describe "org.freedesktop.DBus.ListActivatableNames" do
    test "returns empty list", %{socket_path: path} do
      conn = connect_client(path)
      _name = call_hello(conn)

      msg =
        Message.method_call(
          "/org/freedesktop/DBus",
          "org.freedesktop.DBus",
          "ListActivatableNames",
          destination: "org.freedesktop.DBus"
        )

      {:ok, reply} = Connection.call(conn, msg, 5_000)
      assert reply.type == :method_return
      assert reply.body == [[]]

      Connection.disconnect(conn)
    end
  end

  # Drain signals from the mailbox until we get a method_call
  defp receive_method_call(timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout

    receive do
      {:ex_d_bus, {:message, %Message{type: :method_call} = msg}} ->
        msg

      {:ex_d_bus, {:message, %Message{type: :signal}}} ->
        remaining = max(0, deadline - System.monotonic_time(:millisecond))
        receive_method_call(remaining)
    after
      timeout ->
        flunk("Timed out waiting for method_call")
    end
  end
end
