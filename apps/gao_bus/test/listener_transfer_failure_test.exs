defmodule GaoBus.ListenerTransferFailureTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, NameRegistry, Peer, PeerSupervisor}
  alias GaoBus.Unix.Native

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    uid = Native.identity().uid
    directory = Path.join(System.tmp_dir!(), "gb-transfer-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)

    settings = %{
      socket_path: Path.join(directory, "bus"),
      profile: :session,
      cluster: false,
      policy_rules: [
        %{action: :connect, effect: :allow, match: %{uid: uid}},
        %{action: :own, effect: :allow, match: %{uid: uid}},
        %{action: :send, effect: :allow, match: %{uid: uid}},
        %{action: :receive, effect: :allow, match: %{uid: uid}}
      ]
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

    start_supervised!(%{id: :transfer_core, start: {GaoBus.Application, :start, [:normal, []]}})

    assert {:ok, observer} =
             :gen_tcp.connect(
               {:local, settings.socket_path},
               0,
               [:binary, active: false, packet: :line],
               1000
             )

    on_exit(fn -> :gen_tcp.close(observer) end)
    identity = Base.encode16(Integer.to_string(uid))
    :ok = :gen_tcp.send(observer, <<0>> <> "AUTH EXTERNAL #{identity}\r\n")
    assert {:ok, "OK " <> _} = :gen_tcp.recv(observer, 0, 1000)
    :ok = :inet.setopts(observer, packet: :raw)
    :ok = :gen_tcp.send(observer, "BEGIN\r\n")
    assert %Message{type: :method_return, body: [name]} = query(observer, "Hello", 1)
    assert {:ok, observer_peer} = NameRegistry.resolve(name)
    owned = "org.foundation.TransferObserver"
    assert %Message{body: [1]} = query(observer, "RequestName", 2, "su", [owned, 0])
    :ok = GaoBus.Policy.Capability.grant(name, {:own, owned})
    :ok = GaoBus.MatchRules.add_match(observer_peer, "type='signal'")
    assert %Message{body: [id]} = query(observer, "GetId", 3)
    await(fn -> match?({:ok, %{reservations: 0}}, Limits.snapshot()) end)
    %{directory: directory, observer: observer, name: name, owned: owned, id: id}
  end

  test "failed transfer restores exact resources without changing healthy authority", ctx do
    before = authority(ctx)
    baseline_fds = fd_count()
    {accepted, client, holder, listener} = accepted_socket(ctx.directory)
    assert {:ok, ^holder} = :socket.getopt(accepted, {:otp, :controlling_process})
    assert {:ok, fd} = :socket.getopt(accepted, {:otp, :fd})
    assert {:ok, "socket:" <> _} = File.read_link("/proc/#{System.pid()}/fd/#{fd}")
    assert {:ok, peer} = PeerSupervisor.start_peer(accepted)
    monitor = Process.monitor(peer)
    assert nil == Peer.get_unique_name(peer)
    assert nil == Peer.get_credentials(peer)
    assert %{state: :waiting_socket, native_socket: nil} = :sys.get_state(peer)
    assert Registry.keys(GaoBus.PeerRegistry, peer) == []
    refute Map.has_key?(:sys.get_state(GaoBus.Router).peers, peer)
    assert {:ok, accounting} = Limits.snapshot()
    refute Map.has_key?(accounting.peers, peer)

    assert {:error, {:invalid, :not_owner}} = GaoBus.Listener.transfer_ownership(accepted, peer)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :shutdown}, 1000
    assert {:error, :closed} = :gen_tcp.recv(client, 0, 1000)
    assert {:error, :closed} = :socket.getopt(accepted, {:otp, :controlling_process})
    assert {:error, :enoent} = File.read_link("/proc/#{System.pid()}/fd/#{fd}")
    :gen_tcp.close(client)
    :socket.close(listener)
    holder_monitor = Process.monitor(holder)
    send(holder, :stop)
    assert_receive {:DOWN, ^holder_monitor, :process, ^holder, :normal}, 1000

    await(fn -> fd_count() == baseline_fds end)
    await(fn -> authority(ctx) == before end)
    assert Registry.keys(GaoBus.PeerRegistry, peer) == []
    refute GaoBus.MatchRules.has_rules?(peer)
    assert %Message{type: :method_return, body: [id]} = query(ctx.observer, "GetId", 4)
    assert id == ctx.id
    assert %Message{type: :method_return, body: [names]} = query(ctx.observer, "ListNames", 5)
    assert Enum.sort(names) == before.names
    await(fn -> authority(ctx) == before end)
    await(fn -> fd_count() == baseline_fds end)

    IO.inspect(
      %{
        adapter_error: {:invalid, :not_owner},
        peer_down: :shutdown,
        baseline_fds: baseline_fds,
        terminal_fds: fd_count(),
        authority_preserved: true,
        observer_alive: true
      },
      label: "FAIL-02 transfer resource evidence"
    )
  end

  defp authority(ctx) do
    {:ok, accounting} = Limits.snapshot()

    %{
      core_children: Supervisor.which_children(GaoBus.Supervisor) |> Enum.sort(),
      peers: DynamicSupervisor.which_children(PeerSupervisor) |> Enum.sort(),
      registered: Registry.count(GaoBus.PeerRegistry),
      router_peers: :sys.get_state(GaoBus.Router).peers,
      names: NameRegistry.list_names() |> Enum.sort(),
      queue: NameRegistry.list_queued_owners(ctx.owned),
      capabilities: GaoBus.Policy.Capability.capabilities(ctx.name) |> Enum.sort(),
      observer_match: GaoBus.MatchRules.has_rules?(NameRegistry.resolve(ctx.name) |> elem(1)),
      policy: GaoBus.Policy.snapshot(),
      accounting: accounting
    }
  end

  defp accepted_socket(directory) do
    path = Path.join(directory, "transfer")
    {:ok, listener} = :socket.open(:local, :stream, :default)
    :ok = :socket.bind(listener, %{family: :local, path: path})
    :ok = :socket.listen(listener)
    on_exit(fn -> :socket.close(listener) end)
    parent = self()

    holder =
      start_supervised!({Task,
       fn ->
         {:ok, accepted} = :socket.accept(listener, 1000)
         # Real traffic confirms that this is an open accepted connection before
         # invoking transfer_ownership from the test, which is not its owner.
         {:ok, <<42>>} = :socket.recv(accepted, 1, 1000)
         send(parent, {:accepted, accepted})
         receive do: (:stop -> :ok)
       end})

    assert {:ok, client} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    on_exit(fn -> :gen_tcp.close(client) end)
    :ok = :gen_tcp.send(client, <<42>>)
    assert_receive {:accepted, accepted}, 1000
    {accepted, client, holder, listener}
  end

  defp query(socket, member, serial, signature \\ "", body \\ []) do
    request =
      Message.method_call("/org/freedesktop/DBus", "org.freedesktop.DBus", member,
        destination: "org.freedesktop.DBus",
        serial: serial,
        signature: signature,
        body: body
      )

    :ok = :gen_tcp.send(socket, Message.encode_message(request))
    reply(socket, serial, System.monotonic_time(:millisecond) + 1000)
  end

  defp reply(socket, serial, deadline) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)
    assert remaining > 0
    assert {:ok, header} = :gen_tcp.recv(socket, 16, remaining)
    <<?l, _::binary-size(3), bytes::little-32, _::little-32, fields::little-32>> = header

    assert {:ok, rest} =
             :gen_tcp.recv(socket, fields + rem(8 - rem(fields, 8), 8) + bytes, remaining)

    assert {:ok, message, <<>>} = Message.decode_message(header <> rest)
    if message.reply_serial == serial, do: message, else: reply(socket, serial, deadline)
  end

  defp fd_count do
    script = "import os,sys; print(len(os.listdir('/proc/' + sys.argv[1] + '/fd')))"
    {count, 0} = System.cmd(System.find_executable("python3"), ["-c", script, System.pid()])
    String.to_integer(String.trim(count))
  end

  defp await(predicate, deadline \\ System.monotonic_time(:millisecond) + 1500) do
    unless predicate.() do
      assert System.monotonic_time(:millisecond) < deadline, "transfer cleanup deadline exceeded"
      await(predicate, deadline)
    end
  end
end
