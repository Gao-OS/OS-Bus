defmodule GaoBus.ConfigConnectionRuntimeTest do
  use ExUnit.Case, async: false
  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, Peer, PeerSupervisor}

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(System.tmp_dir!(), "gb-p09-#{System.pid()}-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    %{path: Path.join(directory, "bus")}
  end

  defp bus(path, xml) do
    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!({Limits, xml_limits: xml})

    rules =
      Enum.map([:connect, :own, :send, :receive], &%{action: &1, effect: :allow, match: %{}})

    start_supervised!({GaoBus.Policy, rules: rules})
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Router)
    start_supervised!({PeerSupervisor, max_children: 32})

    start_supervised!(
      {GaoBus.Listener,
       socket_path: path,
       socket_mode: 0o600,
       peer_options: [xml_limits: xml, auth_limits: [timeout_ms: 2000, idle_timeout_ms: 2000]]}
    )
  end

  test "BEGIN retains XML incomplete credit while native authentication retires", %{path: path} do
    bus(path, %{"max_incomplete_connections" => 2, "auth_timeout" => 2000})
    socket = handshake(path)
    assert %{incomplete: 1, completed: 0} = stats().xml.global
    assert stats().global.authenticating == 0
    [waiting_peer] = Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))
    {_ref, old_token} = :sys.get_state(waiting_peer).registration_timer
    :ok = :gen_tcp.send(socket, call("Hello", 1))
    assert %Message{type: :method_return, body: [name]} = reply(socket, 1)
    {:ok, peer} = NameRegistry.resolve(name)
    assert %{incomplete: 0, completed: 1} = stats().xml.global
    assert stats().global.authenticating == 0
    assert Peer.get_unique_name(peer) == name
    send(peer, {:registration_expiry, old_token})
    assert Peer.get_unique_name(peer) == name
    :ok = :gen_tcp.send(socket, call("Hello", 2))

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.Failed"} =
             reply(socket, 2)

    assert %{incomplete: 0, completed: 1} = stats().xml.global
  end

  test "completed ceiling rejects Hello before mutation and permits retry after monitored cleanup",
       %{path: path} do
    bus(path, %{
      "max_completed_connections" => 1,
      "max_incomplete_connections" => 2,
      "auth_timeout" => 2000
    })

    first = handshake(path)
    :ok = :gen_tcp.send(first, call("Hello", 1))
    assert %Message{type: :method_return, body: [name]} = reply(first, 1)
    second = handshake(path)
    assert %{incomplete: 1, completed: 1} = stats().xml.global
    :ok = :gen_tcp.send(second, call("Hello", 2))

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.LimitsExceeded"} =
             reply(second, 2)

    assert %{incomplete: 1, completed: 1} = stats().xml.global
    {:ok, peer} = NameRegistry.resolve(name)
    monitor = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
    await(fn -> stats().xml.global.completed == 0 end)
    :ok = :gen_tcp.send(second, call("Hello", 3))
    assert %Message{type: :method_return, body: [other]} = reply(second, 3)
    assert other != name
    assert %{incomplete: 0, completed: 1} = stats().xml.global
  end

  test "incomplete ceiling pauses acceptance until Hello frees a credit", %{path: path} do
    bus(path, %{"max_incomplete_connections" => 1, "auth_timeout" => 2000})
    first = handshake(path)
    assert %{incomplete: 1, completed: 0} = stats().xml.global
    second = connect(path)
    :ok = :gen_tcp.send(second, auth_line() <> "BEGIN\r\n")
    assert {:error, :timeout} = :gen_tcp.recv(second, 1, 80)
    assert length(DynamicSupervisor.which_children(PeerSupervisor)) == 1
    :ok = :gen_tcp.send(first, call("Hello", 1))
    assert %Message{type: :method_return} = reply(first, 1)
    assert "OK " <> _ = auth_response(second)
    assert %{incomplete: 1, completed: 1} = stats().xml.global
  end

  test "XML accept to Hello deadline survives BEGIN and a rejected Hello", %{path: path} do
    bus(path, %{"max_completed_connections" => 0, "auth_timeout" => 280})
    socket = connect(path)
    :ok = :gen_tcp.send(socket, auth_line())
    assert "OK " <> _ = auth_response(socket)
    [peer] = Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))
    before = :sys.get_state(peer)
    # A private receive deadline advances wall time without an arbitrary sleep.
    assert {:error, :timeout} = :gen_tcp.recv(socket, 1, 100)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n" <> call("Hello", 1))

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.LimitsExceeded"} =
             reply(socket, 1)

    after_begin = :sys.get_state(peer)
    assert after_begin.registration_timer == before.registration_timer
    assert {:error, :closed} = :gen_tcp.recv(socket, 1, 230)
  end

  test "zero incomplete pauses acceptance and zero auth timeout closes immediately", %{path: path} do
    bus(path, %{"max_incomplete_connections" => 0})
    socket = connect(path)
    :ok = :gen_tcp.send(socket, auth_line())
    assert {:error, :timeout} = :gen_tcp.recv(socket, 1, 80)
    assert DynamicSupervisor.which_children(PeerSupervisor) == []
    stop_supervised!(GaoBus.Listener)
    stop_supervised!(Limits)
    start_supervised!({Limits, xml_limits: %{"auth_timeout" => 0}})

    start_supervised!(
      {GaoBus.Listener,
       socket_path: path, socket_mode: 0o600, peer_options: [xml_limits: %{"auth_timeout" => 0}]}
    )

    immediate = connect(path)
    assert {:error, :closed} = :gen_tcp.recv(immediate, 1, 500)
    await(fn -> stats().global.connections == 0 end)
    assert %{incomplete: 0, completed: 0} = stats().xml.global
  end

  test "zero completed and per UID ceilings are literal rejection ceilings", %{path: path} do
    bus(path, %{"max_connections_per_user" => 0, "auth_timeout" => 2000})
    socket = handshake(path)
    :ok = :gen_tcp.send(socket, call("Hello", 1))

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.LimitsExceeded"} =
             reply(socket, 1)

    assert %{incomplete: 1, completed: 0} = stats().xml.global
    [peer] = Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))
    assert Peer.get_unique_name(peer) == nil
    assert :sys.get_state(GaoBus.Router).peers[peer].unique_name == nil
  end

  test "killed incomplete owner resumes accept and XML observers are monitored", %{path: path} do
    bus(path, %{"max_incomplete_connections" => 1, "auth_timeout" => 2000})
    _first = handshake(path)
    second = connect(path)
    :ok = :gen_tcp.send(second, auth_line() <> "BEGIN\r\n")
    assert {:error, :timeout} = :gen_tcp.recv(second, 1, 80)
    [peer] = Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))
    monitor = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :killed}
    assert "OK " <> _ = auth_response(second)
    await(fn -> stats().global.authenticating == 0 end)
    assert %{incomplete: 1, completed: 0} = stats().xml.global
    listener = Process.whereis(GaoBus.Listener)
    assert Map.has_key?(:sys.get_state(Limits).accept_observers, listener)
    stop_supervised!(GaoBus.Listener)
    refute Map.has_key?(:sys.get_state(Limits).accept_observers, listener)

    observer =
      start_supervised!(
        {Task,
         fn ->
           receive do
             :stop -> :ok
           end
         end},
        id: make_ref()
      )

    assert {:error, _} = Limits.accept_ready(observer)
    monitor = Process.monitor(observer)
    Process.exit(observer, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^observer, :killed}
    await(fn -> not Map.has_key?(:sys.get_state(Limits).accept_observers, observer) end)
  end

  test "explicit peer options override ambient settings and all XML peers retain defaults", %{
    path: path
  } do
    before = Application.fetch_env(:gao_bus, :auth_limits)
    Application.put_env(:gao_bus, :auth_limits, timeout_ms: 1, idle_timeout_ms: 1)

    on_exit(fn ->
      case before do
        {:ok, value} -> Application.put_env(:gao_bus, :auth_limits, value)
        :error -> Application.delete_env(:gao_bus, :auth_limits)
      end
    end)

    bus(path, %{})
    socket = handshake(path)
    [peer] = Enum.map(DynamicSupervisor.which_children(PeerSupervisor), &elem(&1, 1))
    state = :sys.get_state(peer)
    assert state.auth.limits.timeout_ms > 29_000

    assert state.xml_limits == %{
             "max_completed_connections" => 2048,
             "max_incomplete_connections" => 64,
             "max_connections_per_user" => 256,
             "auth_timeout" => 30_000
           }

    assert {:error, :timeout} = :gen_tcp.recv(socket, 1, 80)
    :ok = :gen_tcp.send(socket, call("Hello", 1))
    assert %Message{type: :method_return} = reply(socket, 1)
  end

  test "per UID ceiling counts completed only and serializes concurrent completion" do
    limits =
      start_supervised!({Limits, name: nil, xml_limits: %{"max_connections_per_user" => 1}})

    peers =
      for _ <- 1..2 do
        start_supervised!(
          {Task,
           fn ->
             receive do
               :stop -> :ok
             end
           end},
          id: make_ref()
        )
      end

    for peer <- peers do
      assert :ok = Limits.acquire(peer, %{uid: 1000, gid: 1000, pid: 1}, limits)
      assert :ok = Limits.auth_completed(peer, limits)
    end

    results =
      peers
      |> Task.async_stream(&Limits.hello_completed(&1, limits))
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &(&1 == :ok)) == 1

    assert Enum.count(
             results,
             &(&1 == {:error, {:xml_limit_exceeded, "max_connections_per_user"}})
           ) == 1

    assert {:ok, %{xml: %{global: %{incomplete: 1, completed: 1}}}} = Limits.snapshot(limits)
  end

  test "accounting refuses an expired Hello transition without moving credit" do
    limits = start_supervised!({Limits, name: nil, xml_limits: %{}})

    peer =
      start_supervised!(
        {Task,
         fn ->
           receive do
             :stop -> :ok
           end
         end},
        id: make_ref()
      )

    assert :ok = Limits.acquire(peer, %{uid: 1000, gid: 1000, pid: 1}, limits)
    assert :ok = Limits.auth_completed(peer, limits)

    assert {:error, :hello_timeout} =
             Limits.hello_completed(peer, limits, System.monotonic_time(:millisecond) - 1)

    assert {:ok, %{xml: %{global: %{incomplete: 1, completed: 0}}}} = Limits.snapshot(limits)
    assert :ok = Limits.hello_completed(peer, limits, System.monotonic_time(:millisecond) + 1000)
    assert {:ok, %{xml: %{global: %{incomplete: 0, completed: 1}}}} = Limits.snapshot(limits)
  end

  defp stats do
    assert {:ok, stats} = Limits.snapshot()
    stats
  end

  defp await(check), do: await(check, System.monotonic_time(:millisecond) + 1000)

  defp await(check, deadline) do
    unless check.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(check, deadline)
    end
  end

  defp handshake(path) do
    socket = connect(path)
    :ok = :gen_tcp.send(socket, auth_line() <> "BEGIN\r\n")
    assert "OK " <> _ = auth_response(socket)
    await(fn -> stats().global.authenticating == 0 end)
    socket
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

  defp reply(socket, serial) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, 1500)

    assert {:ok, tail} = :gen_tcp.recv(socket, header + rem(8 - rem(header, 8), 8) + body, 1500)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    if message.reply_serial == serial, do: message, else: reply(socket, serial)
  end
end
