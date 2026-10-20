defmodule GaoBus.FoundationSecurityTest do
  use ExUnit.Case, async: false
  alias ExDBus.Message

  setup tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)

    directory =
      Path.join(
        System.tmp_dir!(),
        "osbus-sec-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    path = Path.join(directory, "bus")
    old_path = Application.get_env(:gao_bus, :socket_path)
    old_limits = Application.get_env(:gao_bus, :auth_limits)
    old_resources = Application.get_env(:gao_bus, :resource_limits)
    old_profile = Application.get_env(:gao_bus, :profile)
    old_policy = Application.get_env(:gao_bus, :policy_rules)
    old_frame_timeout = Application.get_env(:gao_bus, :frame_timeout_ms)
    Application.put_env(:gao_bus, :frame_timeout_ms, Map.get(tags, :frame_timeout_ms, 5000))
    Application.put_env(:gao_bus, :socket_path, path)
    Application.put_env(:gao_bus, :profile, :system)
    {uid_text, 0} = System.cmd("id", ["-u"])
    uid = String.to_integer(String.trim(uid_text))

    Application.put_env(:gao_bus, :policy_rules, [
      %{action: :connect, effect: :allow, match: %{uid: uid}},
      %{action: :own, effect: :allow, match: %{uid: uid, name: {:prefix, "org.foundation"}}},
      %{action: :send, effect: :allow, match: %{uid: uid}},
      %{action: :receive, effect: :allow, match: %{uid: uid}}
    ])

    Application.put_env(:gao_bus, :auth_limits,
      timeout_ms: 1000,
      idle_timeout_ms: 500,
      max_line_bytes: 512
    )

    Application.put_env(:gao_bus, :resource_limits, Map.get(tags, :resource_limits, %{}))

    start_supervised!(%{
      id: :foundation_bus,
      start: {GaoBus.Application, :start, [:normal, []]}
    })

    on_exit(fn ->
      restore(:socket_path, old_path)
      restore(:auth_limits, old_limits)
      restore(:resource_limits, old_resources)
      restore(:profile, old_profile)
      restore(:policy_rules, old_policy)
      restore(:frame_timeout_ms, old_frame_timeout)
      File.rm_rf!(directory)
    end)

    observer = connect(path)
    authenticate(observer)
    :ok = :gen_tcp.send(observer, call("Hello", 1))
    assert %Message{type: :method_return, body: [name]} = reply(observer, 1)
    {:ok, peer} = GaoBus.NameRegistry.resolve(name)
    owned = "org.foundation.Observer"
    :ok = GaoBus.Policy.Capability.grant(name, {:own, owned})

    :ok =
      :gen_tcp.send(
        observer,
        call(
          "RequestName",
          2,
          "su",
          string(owned) <> padding(byte_size(string(owned)), 4) <> <<0::little-32>>
        )
      )

    assert %Message{type: :method_return, body: [1]} = reply(observer, 2)

    %{
      path: path,
      observer: observer,
      observer_name: name,
      observer_peer: peer,
      observer_owned: owned,
      router: Process.whereis(GaoBus.Router)
    }
  end

  test "SEC-01 socket credentials retain actual kernel PID UID and GID", context do
    {uid_text, 0} = System.cmd("id", ["-u"])
    {gid_text, 0} = System.cmd("id", ["-g"])

    expected = %{
      pid: String.to_integer(System.pid()),
      uid: String.to_integer(String.trim(uid_text)),
      gid: String.to_integer(String.trim(gid_text))
    }

    assert Map.take(GaoBus.Peer.get_credentials(context.observer_peer), [:uid, :gid, :pid]) ==
             expected

    healthy(context)
  end

  test "SEC-02 client identity text cannot substitute another kernel UID", context do
    {uid_text, 0} = System.cmd("id", ["-u"])
    uid = String.to_integer(String.trim(uid_text))
    claimed = if uid == 0, do: 1, else: 0
    socket = connect(context.path)

    :ok =
      :gen_tcp.send(
        socket,
        <<0>> <> "AUTH EXTERNAL " <> Base.encode16(Integer.to_string(claimed)) <> "\r\n"
      )

    assert {:ok, response} = :gen_tcp.recv(socket, 0, 1000)
    assert response == "REJECTED EXTERNAL\r\n"
    :gen_tcp.close(socket)
    healthy(context)
  end

  for exchange <- ["BEGIN\r\n", "AUTH BOGUS\r\nBEGIN\r\n", "CANCEL\r\nBEGIN\r\n"] do
    @exchange exchange
    test "SEC-04 unauthenticated transition is contained: #{inspect(exchange)}", context do
      socket = connect(context.path)
      :ok = :gen_tcp.send(socket, <<0>> <> @exchange <> call("Hello", 10))
      bytes = until_closed(socket, <<>>)
      refute bytes =~ "OK "
      refute binary_reply?(bytes)
      healthy(context)
    end
  end

  test "SEC-05 system authentication offers only verified EXTERNAL", context do
    socket = connect(context.path)
    :ok = :gen_tcp.send(socket, <<0, "AUTH ANONYMOUS\r\n">>)
    assert {:ok, "REJECTED EXTERNAL\r\n"} = :gen_tcp.recv(socket, 0, 1000)
    :ok = :gen_tcp.send(socket, "NEGOTIATE_UNIX_FD\r\n")
    assert {:ok, "ERROR" <> _} = :gen_tcp.recv(socket, 0, 1000)
    :gen_tcp.close(socket)
    healthy(context)
  end

  test "SEC-07 oversized authentication is closed with observer intact", context do
    socket = connect(context.path)
    :ok = :gen_tcp.send(socket, <<0>> <> :binary.copy("A", 513))
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1500)
    healthy(context)
  end

  test "SEC-06 a real failed credential query cannot admit a peer", context do
    {:ok, socket} = :socket.open(:local, :stream, :default)
    :ok = :socket.close(socket)
    assert {:error, _} = GaoBus.Unix.Credentials.read(socket)
    peer = start_supervised!({GaoBus.Peer, socket: socket})
    monitor = Process.monitor(peer)
    send(peer, :socket_ready)
    assert_receive {:DOWN, ^monitor, :process, ^peer, :normal}, 1000
    refute Map.has_key?(:sys.get_state(context.router).peers, peer)
    assert {:ok, accounting} = GaoBus.Limits.snapshot()
    refute Map.has_key?(accounting.peers, peer)
    healthy(context)
  end

  @tag :foundation_peer_cleanup
  test "SEC-17 killing a peer clears owned and queued authority while the observer survives",
       context do
    socket = connect(context.path)
    authenticate(socket)
    :ok = :gen_tcp.send(socket, call("Hello", 1))
    assert %Message{body: [name]} = reply(socket, 1)
    {:ok, peer} = GaoBus.NameRegistry.resolve(name)
    owned = "org.foundation.KilledOwner"

    for {requested, serial} <- [{owned, 2}, {context.observer_owned, 3}] do
      body = string(requested) <> padding(byte_size(string(requested)), 4) <> <<0::little-32>>
      :ok = :gen_tcp.send(socket, call("RequestName", serial, "su", body))
      assert %Message{type: :method_return} = reply(socket, serial)
    end

    assert {:ok, peer} == GaoBus.NameRegistry.resolve(owned)
    :ok = GaoBus.MatchRules.add_match(peer, "type='signal'")
    :ok = GaoBus.Policy.Capability.grant(name, {:own, owned})
    observer_name = context.observer_name

    :ok =
      :gen_tcp.send(
        context.observer,
        call("Wait", 60, "", <<>>,
          destination: owned,
          path: "/cleanup",
          interface: "org.foundation.Cleanup"
        )
      )

    # Receiving the real call without replying keeps its causal reservation live.
    assert %Message{type: :method_call, flags: 0, serial: 60, sender: ^observer_name} =
             cleanup_message(socket, System.monotonic_time(:millisecond) + 1000)

    assert_pending_call(context.router, context.observer_peer, peer, 60)
    {:ok, token} = GaoBus.Limits.reserve_ingress(peer, 128)
    await_cleanup_usage(2, 1, 128, System.monotonic_time(:millisecond) + 1000)
    deadline = System.monotonic_time(:millisecond) + 1000
    reference = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^reference, :process, ^peer, :killed}, 1000
    await_cleanup(peer, name, System.monotonic_time(:millisecond) + 1000)
    await_pending_empty(context.router, deadline)

    assert %Message{
             type: :error,
             reply_serial: 60,
             sender: "org.freedesktop.DBus",
             destination: ^observer_name,
             error_name: "org.freedesktop.DBus.Error.NoReply"
           } = cleanup_message(context.observer, deadline)

    assert {:error, :name_not_found} = GaoBus.NameRegistry.resolve(owned)
    refute GaoBus.MatchRules.has_rules?(peer)
    assert [] = GaoBus.Policy.Capability.capabilities(name)
    await_cleanup_usage(1, 1, 128, deadline)
    # Source death cannot forgive work still queued in the authority mailbox.
    # This fixture owns that synthetic work item and retires it explicitly.
    assert :ok = GaoBus.Limits.release(token)
    accounting = await_cleanup_usage(1, 0, 0, deadline)
    assert Map.keys(accounting.peers) == [context.observer_peer]
    :ok = :gen_tcp.close(socket)
    table = :sys.get_state(GaoBus.NameRegistry).names
    [{_, _, _, _, queue}] = :ets.lookup(table, context.observer_owned)
    refute Enum.any?(queue, fn {queued, _, _} -> queued == peer end)
    healthy(context)
  end

  @tag :foundation_peer_cleanup
  test "SEC-17 killing a caller retires its outstanding call without replying to the callee",
       context do
    socket = connect(context.path)
    authenticate(socket)
    :ok = :gen_tcp.send(socket, call("Hello", 1))
    assert %Message{type: :method_return, body: [name]} = reply(socket, 1)
    assert {:ok, peer} = GaoBus.NameRegistry.resolve(name)

    :ok =
      :gen_tcp.send(
        socket,
        call("Wait", 60, "", <<>>,
          destination: context.observer_owned,
          path: "/cleanup",
          interface: "org.foundation.Cleanup"
        )
      )

    assert %Message{type: :method_call, flags: 0, serial: 60, sender: ^name} =
             cleanup_message(context.observer, System.monotonic_time(:millisecond) + 1000)

    assert_pending_call(context.router, peer, context.observer_peer, 60)
    await_cleanup_usage(2, 0, 0, System.monotonic_time(:millisecond) + 1000)
    deadline = System.monotonic_time(:millisecond) + 1000
    reference = Process.monitor(peer)
    Process.exit(peer, :kill)
    assert_receive {:DOWN, ^reference, :process, ^peer, :killed}, 1000
    await_cleanup(peer, name, deadline)
    await_pending_empty(context.router, deadline)
    accounting = await_cleanup_usage(1, 0, 0, deadline)
    assert Map.keys(accounting.peers) == [context.observer_peer]
    :ok = :gen_tcp.close(socket)

    # The next non-signal must be this barrier reply, never a reply for the dead caller.
    :ok = :gen_tcp.send(context.observer, call("ListNames", 61))

    assert %Message{type: :method_return, reply_serial: 61, body: [names]} =
             cleanup_message(context.observer, deadline)

    assert context.observer_owned in names
    healthy(context)
  end

  @tag frame_timeout_ms: 100
  test "PRO-04 a truncated frame expires without closing the healthy observer", context do
    socket = connect(context.path)
    authenticate(socket)
    :ok = :gen_tcp.send(socket, call("Hello", 1))
    assert %Message{body: [name]} = reply(socket, 1)
    {:ok, peer} = GaoBus.NameRegistry.resolve(name)
    reference = Process.monitor(peer)
    :ok = :gen_tcp.send(socket, call("ListNames", 2))
    assert %Message{type: :method_return} = reply(socket, 2)
    <<header::binary-size(16), _tail::binary>> = call("ListNames", 3)
    :ok = :gen_tcp.send(socket, header)
    assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1000)
    assert_receive {:DOWN, ^reference, :process, ^peer, :normal}, 1000
    healthy(context)
  end

  test "PRO-01 every frame split and coalesced successor preserve responses", context do
    size = byte_size(call("ListNames", 100))

    for split <- 1..(size - 1) do
      serial = 100 + split * 2
      <<first::binary-size(split), rest::binary>> = call("ListNames", serial)
      :ok = :gen_tcp.send(context.observer, first)
      await_buffer(context.observer_peer, first, System.monotonic_time(:millisecond) + 1000)
      :ok = :gen_tcp.send(context.observer, rest <> call("ListNames", serial + 1))

      assert %Message{type: :method_return, reply_serial: ^serial, body: [names]} =
               reply(context.observer, serial)

      assert context.observer_owned in names
      assert %Message{type: :method_return, body: [^names]} = reply(context.observer, serial + 1)
    end

    healthy(context)
  end

  @tag :foundation_containment
  test "SEC-14 valid frame with invalid RequestName arguments cannot reset authority", context do
    socket = connect(context.path)
    authenticate(socket)
    :ok = :gen_tcp.send(socket, call("Hello", 1))
    assert %Message{type: :method_return} = reply(socket, 1)
    :ok = :gen_tcp.send(socket, call("RequestName", 2))

    assert %Message{type: :error, error_name: "org.freedesktop.DBus.Error.InvalidArgs"} =
             reply(socket, 2)

    healthy(context)
  end

  @tag :foundation_containment
  test "SEC-16 pre-Hello ownership creates no registry entry", context do
    socket = connect(context.path)
    authenticate(socket)
    name = "org.foundation.Premature"
    body = string(name) <> padding(byte_size(string(name)), 4) <> <<0::little-32>>
    :ok = :gen_tcp.send(socket, call("RequestName", 1, "su", body))
    result = reply(socket, 1)
    assert %Message{type: :error} = result
    assert {:error, :name_not_found} = GaoBus.NameRegistry.resolve(name)
    healthy(context)
  end

  for {member, signature, body, options, expected} <- [
        {"ReleaseName", "", <<>>, [], "InvalidArgs"},
        {"GetNameOwner", "u", <<1::little-32>>, [], "InvalidArgs"},
        {"NameHasOwner", "", <<>>, [], "InvalidArgs"},
        {"AddMatch", "u", <<1::little-32>>, [], "InvalidArgs"},
        {"RemoveMatch", "", <<>>, [], "InvalidArgs"},
        {"Get", "", <<>>, [interface: "org.freedesktop.DBus.Properties"], "InvalidArgs"},
        {"ListNames", "u", <<1::little-32>>, [], "InvalidArgs"},
        {"ListNames", "", <<>>, [interface: "org.foundation.Wrong"], "UnknownInterface"},
        {"Get", "", <<>>, [path: "/wrong", interface: "org.freedesktop.DBus.Properties"],
         "UnknownInterface"}
      ] do
    @case {member, signature, body, options, expected}
    @tag :foundation_containment
    test "SEC-14 core schema contains #{member}/#{expected}/#{inspect(options)}", context do
      {member, signature, body, options, expected} = @case
      :ok = :gen_tcp.send(context.observer, call(member, 20, signature, body, options))
      assert %Message{type: :error, error_name: error} = reply(context.observer, 20)
      assert error == "org.freedesktop.DBus.Error." <> expected
      healthy(context)
    end
  end

  @tag :foundation_containment
  test "SEC-14 legacy ListNames accepts a noncanonical object path", context do
    :ok = :gen_tcp.send(context.observer, call("ListNames", 20, "", <<>>, path: "/wrong"))

    assert %Message{type: :method_return, signature: "as", body: [names]} =
             reply(context.observer, 20)

    assert "org.freedesktop.DBus" in names
    healthy(context)
  end

  @tag :foundation_containment
  test "SEC-15 terminal wire errors close only the malformed sender", context do
    for malformed <- [
          # Fixed header version and serial are independently corrupted.
          fn <<endian, type, flags, _version, rest::binary>> ->
            <<endian, type, flags, 9, rest::binary>>
          end,
          fn <<prefix::binary-size(8), _serial::binary-size(4), rest::binary>> ->
            prefix <> <<0::32>> <> rest
          end
        ] do
      socket = connect(context.path)
      authenticate(socket)
      :ok = :gen_tcp.send(socket, malformed.(call("Hello", 1)))
      assert {:error, :closed} = :gen_tcp.recv(socket, 0, 1500)
      healthy(context)
    end
  end

  @tag :foundation_containment
  test "SEC-15 typed signal arguments cannot crash match evaluation", context do
    rule = "type='signal',arg0path='/probe'"
    :ok = :gen_tcp.send(context.observer, call("AddMatch", 30, "s", string(rule)))
    assert %Message{type: :method_return} = reply(context.observer, 30)
    attacker = connect(context.path)
    authenticate(attacker)
    :ok = :gen_tcp.send(attacker, call("Hello", 1))
    assert %Message{type: :method_return} = reply(attacker, 1)

    signal =
      Message.signal("/probe", "org.foundation.Probe", "Changed",
        serial: 2,
        signature: "u",
        body: [42]
      )

    :ok = :gen_tcp.send(attacker, Message.encode_message(signal))
    :ok = :gen_tcp.send(attacker, call("ListNames", 3))
    assert %Message{type: :method_return} = reply(attacker, 3)
    healthy(context)
  end

  @tag resource_limits: %{uid: %{connections: 2}}
  test "RES-01 a real UID cannot exceed its connection budget", context do
    admitted = connect(context.path)
    authenticate(admitted)
    excess = connect(context.path)
    assert {:error, reason} = :gen_tcp.recv(excess, 0, 1000)
    assert reason in [:closed, :econnreset]
    {:ok, accounting} = GaoBus.Limits.snapshot()
    assert accounting.global.connections == 2
    healthy(context)
  end

  @tag resource_limits: %{uid: %{authenticating: 1}}
  test "RES-02 slow authentication consumes a finite slot while the observer works", context do
    unfinished = connect(context.path)
    :ok = :gen_tcp.send(unfinished, <<0, "AUTH EXTERNAL\r\n">>)
    assert {:ok, "DATA\r\n"} = :gen_tcp.recv(unfinished, 0, 1000)
    excess = connect(context.path)
    assert {:error, reason} = :gen_tcp.recv(excess, 0, 1000)
    assert reason in [:closed, :econnreset]
    {:ok, accounting} = GaoBus.Limits.snapshot()
    assert accounting.global.authenticating == 1
    healthy(context)
    assert {:error, :closed} = :gen_tcp.recv(unfinished, 0, 1000)
  end

  @tag resource_limits: %{global: %{ingress_messages: 2}}
  test "RES-03 shared reservations bound the actual Router mailbox before enqueue", context do
    attackers =
      for _ <- 1..3 do
        attacker = connect(context.path)
        authenticate(attacker)
        :ok = :gen_tcp.send(attacker, call("Hello", 1))
        assert %Message{type: :method_return, body: [name]} = reply(attacker, 1)
        :ok = :gen_tcp.send(attacker, call("ListNames", 2))
        assert %Message{type: :method_return} = reply(attacker, 2)
        assert {:ok, peer} = GaoBus.NameRegistry.resolve(name)
        {attacker, peer}
      end

    _ = :sys.get_state(context.router)

    :ok = :sys.suspend(context.router)

    try do
      # Each Peer now admits one routed frame at a time. Independent sources
      # still exercise a real N+1 reservation against the shared capacity.
      for {{attacker, _peer}, serial} <- Enum.zip(Enum.take(attackers, 2), 10..11) do
        :ok = :gen_tcp.send(attacker, call("ListNames", serial))

        await_routes(
          context.router,
          Enum.to_list(10..serial),
          System.monotonic_time(:millisecond) + 1000
        )
      end

      {excess, excess_peer} = List.last(attackers)
      reference = Process.monitor(excess_peer)
      :ok = :gen_tcp.send(excess, call("ListNames", 12))
      assert {:error, :closed} = :gen_tcp.recv(excess, 0, 1500)
      assert_receive {:DOWN, ^reference, :process, ^excess_peer, :normal}, 1000
      assert queued_routes(context.router) == [10, 11]
    after
      :ok = :sys.resume(context.router)
    end

    for {{attacker, _peer}, serial} <- Enum.zip(Enum.take(attackers, 2), 10..11),
        do: assert(%Message{type: :method_return} = reply(attacker, serial))

    healthy(context)
    _ = :sys.get_state(context.router)
    {:ok, accounting} = GaoBus.Limits.snapshot()
    assert accounting.global.ingress_messages == 0
    assert accounting.global.ingress_bytes == 0
  end

  defp queued_routes(router) do
    assert {:messages, messages} = Process.info(router, :messages)

    for {:"$gen_cast", {kind, %{serial: serial}, _peer, _token, _bytes}} <- messages,
        kind in [:route, :route_frame] and serial in 10..12,
        do: serial
  end

  defp await_routes(router, expected, deadline) do
    unless queued_routes(router) == expected do
      assert System.monotonic_time(:millisecond) < deadline, "ingress was not admitted"
      await_routes(router, expected, deadline)
    end
  end

  defp healthy(context) do
    assert Process.whereis(GaoBus.Router) == context.router
    assert {:ok, context.observer_peer} == GaoBus.NameRegistry.resolve(context.observer_name)

    assert {:ok, context.observer_name} ==
             GaoBus.NameRegistry.get_name_owner(context.observer_owned)

    :ok = :gen_tcp.send(context.observer, call("ListNames", 50))
    assert %Message{type: :method_return, body: [names]} = reply(context.observer, 50)
    assert context.observer_owned in names
  end

  defp await_cleanup(peer, name, deadline) do
    {:ok, accounting} = GaoBus.Limits.snapshot()

    case {GaoBus.NameRegistry.resolve(name), Map.has_key?(accounting.peers, peer)} do
      {{:error, :name_not_found}, false} ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline, "monitored cleanup did not finish"
        await_cleanup(peer, name, deadline)
    end
  end

  defp assert_pending_call(router, caller, callee, serial) do
    assert [{{^caller, ^serial}, %{caller: ^caller, callee: ^callee, serial: ^serial, uid: uid}}] =
             router
             |> :sys.get_state()
             |> Map.fetch!(:pending)
             |> Map.fetch!(:entries)
             |> Map.to_list()

    assert uid == GaoBus.Peer.get_credentials(caller).uid
  end

  defp await_pending_empty(router, deadline) do
    unless :sys.get_state(router, cleanup_timeout(deadline)).pending.entries == %{} do
      await_pending_empty(router, deadline)
    end
  end

  defp await_cleanup_usage(connections, ingress_messages, ingress_bytes, deadline) do
    assert {:ok, accounting} = GenServer.call(GaoBus.Limits, :snapshot, cleanup_timeout(deadline))

    expected =
      accounting.global
      |> Map.new(fn {metric, _count} -> {metric, 0} end)
      |> Map.merge(%{
        connections: connections,
        ingress_messages: ingress_messages,
        ingress_bytes: ingress_bytes
      })

    if accounting.global == expected and accounting.reservations == ingress_messages do
      accounting
    else
      await_cleanup_usage(connections, ingress_messages, ingress_bytes, deadline)
    end
  end

  defp cleanup_message(socket, deadline) do
    assert {:ok,
            <<?l, _type, _flags, _version, body::little-32, _serial::little-32,
              header::little-32>> = prefix} =
             :gen_tcp.recv(socket, 16, cleanup_timeout(deadline))

    size = header + rem(8 - rem(header, 8), 8) + body
    assert {:ok, tail} = :gen_tcp.recv(socket, size, cleanup_timeout(deadline))
    assert {:ok, message, <<>>} = Message.decode_message(prefix <> tail)

    if message.type == :signal,
      do: cleanup_message(socket, deadline),
      else: message
  end

  defp cleanup_timeout(deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)
    assert remaining > 0, "pending-call cleanup exceeded its fixed deadline"
    remaining
  end

  defp await_buffer(peer, expected, deadline) do
    case :sys.get_state(peer).buffer do
      ^expected ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline, "fragment was not consumed"
        await_buffer(peer, expected, deadline)
    end
  end

  defp connect(path) do
    {:ok, socket} = :gen_tcp.connect({:local, path}, 0, [:binary, active: false], 1000)
    socket
  end

  defp authenticate(socket) do
    {uid, 0} = System.cmd("id", ["-u"])

    :ok =
      :gen_tcp.send(
        socket,
        <<0>> <> "AUTH EXTERNAL " <> Base.encode16(String.trim(uid)) <> "\r\n"
      )

    assert {:ok, "OK " <> _} = :gen_tcp.recv(socket, 0, 1000)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
  end

  # Independent wire fixture: no production encoder participates in ingress.
  defp call(member, serial, signature \\ "", body \\ <<>>, options \\ []) do
    fields = [
      {1, "o", Keyword.get(options, :path, "/org/freedesktop/DBus")},
      {2, "s", Keyword.get(options, :interface, "org.freedesktop.DBus")},
      {3, "s", member},
      {6, "s", Keyword.get(options, :destination, "org.freedesktop.DBus")}
    ]

    header =
      Enum.reduce(fields, <<>>, fn {code, type, value}, acc ->
        acc <> padding(byte_size(acc), 8) <> <<code, 1>> <> type <> <<0>> <> string(value)
      end)

    header =
      if signature == "",
        do: header,
        else:
          header <>
            padding(byte_size(header), 8) <>
            <<8, 1, ?g, 0, byte_size(signature)>> <> signature <> <<0>>

    <<?l, 1, 0, 1, byte_size(body)::little-32, serial::little-32, byte_size(header)::little-32>> <>
      header <> padding(byte_size(header), 8) <> body
  end

  defp string(value), do: <<byte_size(value)::little-32>> <> value <> <<0>>

  defp padding(offset, alignment),
    do: :binary.copy(<<0>>, rem(alignment - rem(offset, alignment), alignment))

  defp reply(socket, serial) do
    case :gen_tcp.recv(socket, 16, 1500) do
      {:ok,
       <<?l, _type, _flags, _version, body::little-32, _serial::little-32, header::little-32>> =
           prefix} ->
        size = header + rem(8 - rem(header, 8), 8) + body
        {:ok, tail} = :gen_tcp.recv(socket, size, 1500)
        {:ok, msg, <<>>} = Message.decode_message(prefix <> tail)
        if msg.reply_serial == serial, do: msg, else: reply(socket, serial)

      error ->
        flunk("expected reply #{serial}: #{inspect(error)}")
    end
  end

  defp until_closed(socket, buffer) do
    case :gen_tcp.recv(socket, 0, 1500) do
      {:ok, bytes} -> until_closed(socket, buffer <> bytes)
      {:error, :closed} -> buffer
      error -> flunk("expected bounded peer close, got #{inspect(error)}")
    end
  end

  defp binary_reply?(bytes), do: :binary.match(bytes, <<?l, 2, 0, 1>>) != :nomatch
  defp restore(key, nil), do: Application.delete_env(:gao_bus, key)
  defp restore(key, value), do: Application.put_env(:gao_bus, key, value)
end
