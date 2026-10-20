defmodule GaoBus.ConfigQueueSocketTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Config, Limits, NameRegistry, Policy}
  alias GaoBus.Config.Runtime

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    directory = Path.join(System.tmp_dir!(), "gb-queues-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    %{directory: directory, path: Path.join(directory, "bus")}
  end

  test "retained output pauses source input while an observer stays usable, then resumes in order",
       ctx do
    bus(ctx, %{"max_incoming_bytes" => 4096})
    source = connect(ctx.path)
    target = connect(ctx.path)
    observer = connect(ctx.path)
    await(fn -> stats().global.ingress_bytes == 0 and stats().global.egress_bytes == 0 end)
    suspend(target.pid)
    notice(source, target, "first" <> String.duplicate("x", 5000))
    notice(source, target, "second")

    await(fn ->
      stats().peers[source.pid].ingress_bytes > 4096 and
        Map.get(:sys.get_state(source.pid), :ingress_paused, false)
    end)

    assert %{body: [id]} = query(observer, "GetId")
    assert byte_size(id) == 32
    assert {:ok, pid} = NameRegistry.resolve(source.name)
    assert pid == source.pid
    :ok = :sys.resume(target.pid)
    assert %Message{body: [first]} = read_message(target.socket)
    assert String.starts_with?(first, "first")
    assert %Message{body: ["second"]} = read_message(target.socket)
    assert %Message{type: :method_return} = query(source, "GetId")
    await(fn -> stats().global.ingress_bytes == 0 and stats().global.egress_bytes == 0 end)
  end

  test "XML outgoing overshoot yields a bounded LimitsExceeded and retires failed call state",
       ctx do
    bus(ctx, %{"max_outgoing_bytes" => 4096})
    source = connect(ctx.path)
    target = connect(ctx.path)
    observer = connect(ctx.path)
    await(fn -> stats().global.egress_bytes == 0 end)
    suspend(target.pid)
    notice(source, target, String.duplicate("x", 5000))
    await(fn -> stats().peers[target.pid].egress_bytes > 4096 end)
    serial = System.unique_integer([:positive])

    call =
      Message.method_call("/org/foundation/Queues", "org.foundation.Queues", "Echo",
        serial: serial,
        destination: target.name
      )

    :ok = :gen_tcp.send(source.socket, Message.encode_message(call))

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.LimitsExceeded"} =
             reply(source.socket, serial)

    assert :sys.get_state(GaoBus.Router).pending.entries == %{}
    assert %Message{type: :method_return} = query(observer, "GetId")
    :ok = :sys.resume(target.pid)
    assert %Message{type: :signal} = read_message(target.socket)
    await(fn -> stats().global.ingress_bytes == 0 and stats().global.egress_bytes == 0 end)
  end

  test "XML forwarding accepts an input larger than the native one-MiB output default", ctx do
    bus(ctx, %{})
    source = connect(ctx.path)
    target = connect(ctx.path)
    payload = String.duplicate("x", 1_049_600)
    notice(source, target, payload)
    assert %Message{type: :signal, body: [received]} = read_message(target.socket)
    assert byte_size(received) == byte_size(payload)
    assert :crypto.hash(:sha256, received) == :crypto.hash(:sha256, payload)
    assert %Message{type: :method_return} = query(source, "GetId")
    await(fn -> stats().global.ingress_bytes == 0 and stats().global.egress_bytes == 0 end)
  end

  test "killing a peer during a self-directed partial output retires retained input and output",
       ctx do
    bus(ctx, %{"max_incoming_bytes" => 4096})
    source = connect(ctx.path)
    observer = connect(ctx.path)
    await(fn -> stats().global.egress_bytes == 0 end)
    socket = :sys.get_state(source.pid).socket
    assert :ok = :socket.setopt(socket, :socket, :sndbuf, 4096)
    notice(source, source, String.duplicate("x", 2_097_152))

    await(fn ->
      stats().peers[source.pid].ingress_bytes > 4096 and
        stats().peers[source.pid].egress_bytes > 4096
    end)

    assert %Message{type: :method_return} = query(observer, "GetId")
    monitor = Process.monitor(source.pid)
    Process.exit(source.pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, _pid, :killed}
    await(fn -> stats().global.ingress_bytes == 0 and stats().global.egress_bytes == 0 end)
    assert stats().reservations == 0
    assert %Message{type: :method_return} = query(observer, "GetId")
  end

  defp bus(ctx, limits) do
    identity = GaoBus.Unix.Native.identity()
    file = Path.join(ctx.directory, "bus.conf")

    declared =
      Enum.map_join(limits, fn {name, value} -> ~s(<limit name="#{name}">#{value}</limit>) end)

    File.write!(file, """
    <busconfig><type>session</type><auth>EXTERNAL</auth>#{declared}
      <policy context="default"><allow user="*"/><allow own="*"/>
        <allow send_type="*"/><allow receive_type="*"/>
      </policy>
    </busconfig>
    """)

    accounts = %{
      users: %{"fixture" => identity.uid},
      groups: %{"fixture" => identity.gid},
      memberships: %{identity.uid => [identity.gid]}
    }

    assert {:ok, config} = Config.load(file, daemon_uid: identity.uid, accounts: accounts)

    assert {:ok, plan} =
             Runtime.compile(config, %{profile: :session, socket_path: ctx.path}, identity)

    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!({Limits, plan.limits_options})
    start_supervised!({Policy, rules: config})
    start_supervised!({NameRegistry, plan.name_options})
    start_supervised!({GaoBus.MatchRules, plan.match_options})
    start_supervised!(GaoBus.Policy.Capability)
    start_supervised!({GaoBus.Router, plan.router_options})
    start_supervised!({GaoBus.PeerSupervisor, plan.peer_supervisor_options})
    start_supervised!({GaoBus.Listener, Keyword.put(plan.listener_options, :socket_mode, 0o600)})
  end

  defp connect(path) do
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    on_exit(fn -> :gen_tcp.close(socket) end)
    uid = GaoBus.Unix.Native.identity().uid

    :ok =
      :gen_tcp.send(
        socket,
        <<0>> <> "AUTH EXTERNAL " <> Base.encode16(Integer.to_string(uid)) <> "\r\n"
      )

    assert "OK " <> _ = auth_response(socket)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
    client = %{socket: socket}
    assert %Message{body: [name]} = query(client, "Hello")
    # The driver queues NameAcquired after Hello; exact framing drains it.
    assert %Message{type: :signal, member: "NameAcquired"} = read_message(socket)
    assert {:ok, pid} = NameRegistry.resolve(name)
    %{socket: socket, name: name, pid: pid}
  end

  defp auth_response(socket, acc \\ <<>>) do
    assert {:ok, byte} = :gen_tcp.recv(socket, 1, 1500)
    acc = acc <> byte
    if String.ends_with?(acc, "\r\n"), do: acc, else: auth_response(socket, acc)
  end

  defp query(client, member) do
    serial = System.unique_integer([:positive])

    call =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        serial: serial,
        destination: "org.freedesktop.DBus"
      )

    :ok = :gen_tcp.send(client.socket, Message.encode_message(call))
    reply(client.socket, serial)
  end

  defp reply(socket, serial) do
    message = read_message(socket)
    if message.reply_serial == serial, do: message, else: reply(socket, serial)
  end

  defp read_message(socket) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, 1500)

    assert {:ok, tail} = :gen_tcp.recv(socket, header + rem(8 - rem(header, 8), 8) + body, 1500)
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    message
  end

  defp notice(source, target, body) do
    message =
      Message.signal("/org/foundation/Queues", "org.foundation.Queues", "Notice",
        serial: System.unique_integer([:positive]),
        destination: target.name,
        signature: "s",
        body: [body]
      )

    assert :ok = :gen_tcp.send(source.socket, Message.encode_message(message))
  end

  defp suspend(pid) do
    :ok = :sys.suspend(pid)

    on_exit(fn ->
      try do
        :sys.resume(pid)
      catch
        :exit, _ -> :ok
      end
    end)
  end

  defp stats do
    assert {:ok, value} = Limits.snapshot()
    value
  end

  defp await(check), do: await(check, System.monotonic_time(:millisecond) + 1500)

  defp await(check, deadline) do
    unless check.() do
      assert System.monotonic_time(:millisecond) < deadline
      await(check, deadline)
    end
  end
end
