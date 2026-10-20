defmodule GaoBus.CoreRecoveryTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Ids, Limits, MatchRules, NameRegistry, Policy, Router}

  @core [
    Ids,
    GaoBus.PeerRegistry,
    Limits,
    Policy,
    NameRegistry,
    MatchRules,
    Policy.Capability,
    Router,
    GaoBus.PeerSupervisor,
    GaoBus.Listener
  ]

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    {uid, 0} = System.cmd("id", ["-u"])

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-recovery-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")

    configuration = %{
      socket_path: path,
      profile: :session,
      cluster: false,
      policy_rules: Policy.session_rules(),
      resource_limits: %{},
      bus_id: nil
    }

    previous =
      Map.new(configuration, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)

    Enum.each(configuration, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
        {key, :error} -> Application.delete_env(:gao_bus, key)
      end)

      File.rm_rf!(directory)
    end)

    start_supervised!(%{
      id: GaoBus.Supervisor,
      start: {GaoBus.Application, :start, [:normal, []]},
      type: :supervisor,
      restart: :temporary
    })

    assert Bitwise.band(File.stat!(directory).mode, 0o777) == 0o700
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600

    %{path: path, uid: String.trim(uid)}
  end

  for failed <- [Router, NameRegistry, Policy] do
    @failed failed
    test "FAIL-03 #{inspect(failed)} failure disconnects peers and clears all authority", ctx do
      {owner, owner_name, _guid} = registered(ctx)
      {queued, queued_name, _guid} = registered(ctx)
      name = "org.foundation.Recovery"
      assert [1] == call(owner, "RequestName", 2, "su", [name, 0]).body
      assert [2] == call(queued, "RequestName", 2, "su", [name, 0]).body
      {:ok, owner_pid} = NameRegistry.resolve(owner_name)
      {:ok, queued_pid} = NameRegistry.resolve(queued_name)

      assert [%{owner: owner_pid, queued: queued_pid}] ==
               Enum.map(:ets.lookup(:sys.get_state(NameRegistry).names, name), fn
                 {^name, pid, _, _, [{queued, _, _}]} -> %{owner: pid, queued: queued}
               end)

      assert [] == call(owner, "AddMatch", 3, "s", ["type='signal'"]).body
      assert MatchRules.has_rules?(owner_pid)
      :ok = Policy.Capability.grant(owner_name, {:own, name})
      assert [_] = Policy.Capability.capabilities(owner_name)
      assert {:ok, _token} = Limits.reserve_ingress(owner_pid, 128)
      assert {:ok, %{reservations: 1}} = Limits.snapshot()
      assert %{credentials: %{uid: _}} = :sys.get_state(Router).peers[owner_pid]
      assert {:ok, 2} = Policy.reload(Policy.session_rules())
      _ = call(owner, "GetId", 4)
      old = Map.new(@core, &{&1, Process.whereis(&1)})
      monitors = Enum.map([owner_pid, queued_pid], &{&1, Process.monitor(&1)})
      failed = old[@failed]
      reference = Process.monitor(failed)
      Process.exit(failed, :kill)
      assert_receive {:DOWN, ^reference, :process, ^failed, :killed}, 2000

      Enum.each(monitors, fn {pid, ref} ->
        assert_receive {:DOWN, ^ref, :process, ^pid, _}, 2000
      end)

      await_listener(old[GaoBus.Listener])

      assert NameRegistry.list_names() == ["org.freedesktop.DBus"]
      refute MatchRules.has_rules?(owner_pid)
      assert Policy.Capability.capabilities(owner_name) == []
      assert :sys.get_state(Router).peers == %{}

      assert {:ok,
              %{
                global: %{connections: 0, ingress_messages: 0, ingress_bytes: 0},
                peers: %{},
                uids: %{},
                reservations: 0
              }} = Limits.snapshot()

      assert {:ok, 1, _} = Policy.snapshot()
      Enum.each(old, fn {module, pid} -> refute Process.whereis(module) == pid end)
      assert {:error, :closed} = :gen_tcp.recv(owner, 0, 1000)
      assert {:error, :closed} = :gen_tcp.recv(queued, 0, 1000)

      {reconnected, _, _} = registered(ctx)
      assert [1] == call(reconnected, "RequestName", 2, "su", [name, 0]).body
    end
  end

  test "FAIL-03 new core epoch rotates server GUID and bus ID while each epoch stays stable",
       ctx do
    {socket, _, guid} = registered(ctx)
    assert [bus_id] = call(socket, "GetId", 2).body
    assert bus_id == Ids.bus_id()
    assert guid == Ids.auth_guid()
    assert [bus_id] == call(socket, "GetId", 3).body
    old_listener = Process.whereis(GaoBus.Listener)
    router = Process.whereis(Router)
    reference = Process.monitor(router)
    Process.exit(router, :kill)
    assert_receive {:DOWN, ^reference, :process, ^router, :killed}, 2000
    await_listener(old_listener)
    {replacement, _, next_guid} = registered(ctx)
    assert [next_id] = call(replacement, "GetId", 2).body
    refute next_guid == guid
    refute next_id == bus_id
    assert next_guid == Ids.auth_guid()
    assert [next_id] == call(replacement, "GetId", 3).body
    {same_epoch, _, same_guid} = registered(ctx)
    assert same_guid == next_guid
    assert [next_id] == call(same_epoch, "GetId", 2).body
    refute next_id == next_guid

    case File.read("/etc/machine-id") do
      {:ok, machine_id} -> refute next_id == String.trim(machine_id)
      {:error, _} -> :ok
    end
  end

  defp await_listener(old) do
    deadline = System.monotonic_time(:millisecond) + 2000
    await_listener(old, deadline)
  end

  defp await_listener(old, deadline) do
    children = Supervisor.which_children(GaoBus.Supervisor)

    case List.keyfind(children, GaoBus.Listener, 0) do
      {GaoBus.Listener, pid, _, _} when is_pid(pid) and pid != old ->
        _ = :sys.get_state(pid)
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline, "listener did not restart"
        await_listener(old, deadline)
    end
  end

  defp registered(ctx) do
    assert {:ok, socket} = :gen_tcp.connect({:local, ctx.path}, 0, [:binary, active: false], 1000)
    :ok = :gen_tcp.send(socket, <<0>> <> "AUTH EXTERNAL " <> Base.encode16(ctx.uid) <> "\r\n")
    assert {:ok, "OK " <> response} = :gen_tcp.recv(socket, 0, 1000)
    guid = String.trim(response)
    assert guid =~ ~r/^[0-9a-f]{32}$/
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
    assert [name] = call(socket, "Hello", 1).body
    {socket, name, guid}
  end

  defp call(socket, member, serial, signature \\ nil, body \\ []) do
    message =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus",
        serial: serial,
        signature: signature,
        body: body
      )

    :ok = :gen_tcp.send(socket, Message.encode_message(message))
    reply(socket, serial)
  end

  defp reply(socket, serial) do
    assert {:ok, <<?l, _::24, body::little-32, _::32, header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, 1500)

    length = header + rem(8 - rem(header, 8), 8) + body

    tail =
      if length == 0 do
        <<>>
      else
        assert {:ok, tail} = :gen_tcp.recv(socket, length, 1500)
        tail
      end

    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)
    if message.reply_serial == serial, do: message, else: reply(socket, serial)
  end
end
