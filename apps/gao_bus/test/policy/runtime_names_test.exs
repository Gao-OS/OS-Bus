defmodule GaoBus.Policy.RuntimeNamesTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Config, NameRegistry, Policy}
  @bus "org.freedesktop.DBus"
  @alias "org.foundation.QueuedPolicy"
  @interface "org.foundation.RuntimeNames"

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    identity = GaoBus.Unix.Native.identity()

    directory =
      Path.join(System.tmp_dir!(), "gb-policy-names-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)

    settings = %{
      socket_path: Path.join(directory, "bus"),
      profile: :session,
      cluster: false,
      policy_rules: Policy.session_rules()
    }

    previous = Map.new(settings, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)
    Enum.each(settings, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
        {key, :error} -> Application.delete_env(:gao_bus, key)
      end)

      File.rm_rf!(directory)
    end)

    start_supervised!(%{
      id: :runtime_names_core,
      start: {GaoBus.Application, :start, [:normal, []]}
    })

    [owner, waiter, caller] = for _ <- 1..3, do: connect(settings.socket_path, identity.uid)
    assert %Message{body: [1]} = query(owner, "RequestName", "su", [@alias, 0])
    assert %Message{body: [2]} = query(waiter, "RequestName", "su", [@alias, 0])
    assert %Message{body: [id]} = query(caller, "GetId")

    %{
      owner: owner,
      waiter: waiter,
      caller: caller,
      id: id,
      identity: identity,
      directory: directory
    }
  end

  test "queued destination alias denies a direct unique-name call until queue release", ctx do
    reload(ctx, ~s(<deny send_destination="#{@alias}" send_type="method_call"/>))
    serial = send_probe(ctx.caller, ctx.waiter.name)
    assert %Message{type: :method_return} = query(ctx.waiter, "GetId")

    assert %Message{error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.caller, serial)

    assert %Message{body: [1]} = query(ctx.waiter, "ReleaseName", "s", [@alias])
    send_probe(ctx.caller, ctx.waiter.name, 1)

    assert %Message{type: :method_call, member: "Probe", body: ["marker"]} =
             receive_message(ctx.waiter)

    healthy(ctx)
  end

  test "queued sender alias denies receive by the unique sender until queue release", ctx do
    reload(ctx, ~s(<deny receive_sender="#{@alias}" receive_type="method_call"/>))
    serial = send_probe(ctx.waiter, ctx.caller.name)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")

    assert %Message{error_name: "org.freedesktop.DBus.Error.AccessDenied"} =
             reply(ctx.waiter, serial)

    assert %Message{body: [1]} = query(ctx.waiter, "ReleaseName", "s", [@alias])
    send_probe(ctx.waiter, ctx.caller.name, 1)

    assert %Message{type: :method_call, member: "Probe", body: ["marker"]} =
             receive_message(ctx.caller)

    healthy(ctx)
  end

  test "subscription sender aliases exclude queued owners while primary signals match", ctx do
    reload(ctx, "")
    rule = "type='signal',sender='#{@alias}',interface='#{@interface}',member='Notice'"
    assert %Message{type: :method_return} = query(ctx.caller, "AddMatch", "s", [rule])
    emit(ctx.waiter)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    emit(ctx.owner)
    assert %Message{type: :signal, member: "Notice", sender: sender} = receive_message(ctx.caller)
    assert sender == ctx.owner.name
    assert %Message{body: [1]} = query(ctx.waiter, "ReleaseName", "s", [@alias])
    emit(ctx.waiter)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    healthy(ctx)
  end

  test "one authority snapshot distinguishes policy aliases and current owners", ctx do
    snapshot = NameRegistry.routing_snapshot(ctx.waiter.pid, ctx.waiter.name)
    assert {:peer, pid, names} = snapshot.destination
    assert pid == ctx.waiter.pid
    assert names == snapshot.destination_names
    assert snapshot.sender_names == [ctx.waiter.name]
    assert Enum.sort(snapshot.sender_policy_names) == Enum.sort([ctx.waiter.name, @alias])
    assert snapshot.destination_policy_names == snapshot.sender_policy_names
    assert {:ok, pid, [name]} = NameRegistry.resolve_with_names(ctx.waiter.name)
    assert pid == ctx.waiter.pid and name == ctx.waiter.name
    assert @alias not in NameRegistry.names_for(ctx.waiter.pid)
    assert %Message{body: [1]} = query(ctx.waiter, "ReleaseName", "s", [@alias])
    after_release = NameRegistry.routing_snapshot(ctx.waiter.pid, @alias)
    assert after_release.sender_policy_names == [ctx.waiter.name]
    assert {:peer, owner, owner_names} = after_release.destination
    assert owner == ctx.owner.pid
    assert @alias in owner_names and @alias in after_release.destination_policy_names

    assert %{destination: :bus, destination_policy_names: [@bus]} =
             NameRegistry.routing_snapshot(ctx.waiter.pid, :bus)

    assert %{
             destination: {:missing, "org.foundation.Unknown"},
             destination_policy_names: ["org.foundation.Unknown"]
           } =
             NameRegistry.routing_snapshot(ctx.waiter.pid, "org.foundation.Unknown")

    assert %{destination: :broadcast, destination_policy_names: []} =
             NameRegistry.routing_snapshot(ctx.waiter.pid, :broadcast)

    healthy(ctx)
  end

  defp reload(ctx, deny) do
    path = Path.join(ctx.directory, "policy.conf")

    File.write!(path, """
    <busconfig><policy context="default">
      <allow user="*"/><allow own="*"/>
      <allow send_destination="*"/><allow receive_sender="*"/>
      #{deny}
    </policy></busconfig>
    """)

    accounts = %{
      users: %{"fixture" => ctx.identity.uid},
      groups: %{"fixture" => ctx.identity.gid},
      memberships: %{ctx.identity.uid => [ctx.identity.gid]}
    }

    assert {:ok, candidate} = Config.load(path, daemon_uid: ctx.identity.uid, accounts: accounts)
    assert {:ok, _generation} = Policy.reload(candidate)
  end

  defp connect(path, uid) do
    assert {:ok, socket} =
             :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line], 1000)

    on_exit(fn -> :gen_tcp.close(socket) end)

    :ok =
      :gen_tcp.send(socket, <<0>> <> "AUTH EXTERNAL #{Base.encode16(Integer.to_string(uid))}\r\n")

    assert {:ok, "OK " <> _} = :gen_tcp.recv(socket, 0, 1000)
    :ok = :inet.setopts(socket, packet: :raw)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
    client = %{socket: socket}
    assert %Message{body: [name]} = query(client, "Hello")
    assert {:ok, pid} = NameRegistry.resolve(name)
    %{socket: socket, name: name, pid: pid}
  end

  defp query(client, member, signature \\ "", body \\ []) do
    serial = System.unique_integer([:positive])

    message =
      Message.method_call("/org/freedesktop/DBus", @bus, member,
        destination: @bus,
        serial: serial,
        signature: signature,
        body: body
      )

    :ok = :gen_tcp.send(client.socket, Message.encode_message(message))
    reply(client, serial)
  end

  defp send_probe(client, destination, flags \\ 0) do
    serial = System.unique_integer([:positive])

    message =
      Message.method_call("/probe", @interface, "Probe",
        destination: destination,
        serial: serial,
        flags: flags,
        signature: "s",
        body: ["marker"]
      )

    :ok = :gen_tcp.send(client.socket, Message.encode_message(message))
    serial
  end

  defp emit(client) do
    signal =
      Message.signal("/probe", @interface, "Notice", serial: System.unique_integer([:positive]))

    :ok = :gen_tcp.send(client.socket, Message.encode_message(signal))
    assert %Message{type: :method_return} = query(client, "GetId")
  end

  defp reply(client, serial, deadline \\ System.monotonic_time(:millisecond) + 1000) do
    message = receive_message(client, deadline)

    if message.reply_serial == serial do
      message
    else
      assert message.type == :signal and message.interface == @bus,
             "unexpected routed payload before barrier: #{inspect(message)}"

      reply(client, serial, deadline)
    end
  end

  defp receive_message(client, deadline \\ System.monotonic_time(:millisecond) + 1000) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)
    assert remaining > 0
    assert {:ok, header} = :gen_tcp.recv(client.socket, 16, remaining)
    <<?l, _::binary-size(3), bytes::little-32, _::little-32, fields::little-32>> = header

    assert {:ok, tail} =
             :gen_tcp.recv(client.socket, fields + rem(8 - rem(fields, 8), 8) + bytes, remaining)

    assert {:ok, message, <<>>} = Message.decode_message(header <> tail)
    message
  end

  defp healthy(ctx) do
    for client <- [ctx.owner, ctx.waiter, ctx.caller] do
      assert %Message{body: [id]} = query(client, "GetId")
      assert id == ctx.id
      assert {:ok, pid} = NameRegistry.resolve(client.name)
      assert pid == client.pid
    end
  end
end
