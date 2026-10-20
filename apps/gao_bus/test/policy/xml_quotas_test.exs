defmodule GaoBus.Policy.XMLQuotasTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Config, MatchRules, NameRegistry, PendingCalls, Policy, Router}

  @bus "org.freedesktop.DBus"
  @interface "org.foundation.XMLQuotas"
  @limits "org.freedesktop.DBus.Error.LimitsExceeded"
  @a "org.foundation.QuotaA"
  @b "org.foundation.QuotaB"
  @c "org.foundation.QuotaC"
  @rule "type='signal',interface='org.foundation.XMLQuotas',member='Notice'"

  setup tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    identity = GaoBus.Unix.Native.identity()

    directory =
      Path.join(System.tmp_dir!(), "gb-xml-quotas-#{System.unique_integer([:positive])}")

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    path = Path.join(directory, "bus")
    xml = Map.get(tags, :xml, %{})

    limits =
      Enum.map_join(xml, fn {name, value} -> ~s(<limit name="#{name}">#{value}</limit>) end)

    config_path = Path.join(directory, "quotas.conf")

    File.write!(config_path, """
    <busconfig><auth>EXTERNAL</auth>#{limits}<policy context="default">
      <allow user="*"/><allow own="*"/>
      <allow send_type="method_call"/><allow send_type="signal"/>
      <allow send_requested_reply="true"/>
      <allow receive_type="method_call"/><allow receive_type="signal"/>
      <allow receive_requested_reply="true"/>
      #{Map.get(tags, :deny, "")}
    </policy></busconfig>
    """)

    accounts = %{
      users: %{"fixture" => identity.uid},
      groups: %{"fixture" => identity.gid},
      memberships: %{identity.uid => [identity.gid]}
    }

    assert {:ok, config} = Config.load(config_path, daemon_uid: identity.uid, accounts: accounts)
    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(GaoBus.Limits)
    start_supervised!({Policy, rules: config})
    options = if tags[:native], do: [], else: [xml_limits: config.limits]
    start_supervised!({NameRegistry, options ++ Map.get(tags, :name_options, [])})
    start_supervised!({MatchRules, options ++ Map.get(tags, :match_options, [])})
    # Mirror Runtime XML binding: zero and omitted timeouts disable expiry.
    # Numeric PendingCalls zero remains immediate.
    declared = Map.get(config.limits, "reply_timeout", :infinity)
    timeout = Map.get(tags, :timeout, if(declared == 0, do: :infinity, else: declared))

    pending = %{
      per_peer: Map.get(config.limits, "max_replies_per_connection", 128),
      timeout_ms: timeout,
      per_uid: 512,
      global: 4096
    }

    start_supervised!({Router, pending_limits: pending})
    start_supervised!(GaoBus.PeerSupervisor)
    start_supervised!({GaoBus.Listener, socket_path: path, socket_mode: 0o600})
    [owner, waiter, caller] = for _ <- 1..3, do: connect(path, identity.uid)
    %{owner: owner, waiter: waiter, caller: caller, xml: config.limits}
  end

  @tag xml: %{"max_names_per_connection" => 3}, name_options: [max_names_per_peer: 1]
  test "XML names count the unique identity and deny N+1, duplicate and no-allocation requests",
       ctx do
    acquired(ctx.owner, @a)
    acquired(ctx.owner, @b)
    acquired(ctx.waiter, @c)
    limited(query(ctx.owner, "RequestName", "su", [@c, 4]))
    limited(query(ctx.owner, "RequestName", "su", [@a, 1]))
    limited(query(ctx.owner, "RequestName", "su", ["org.foundation.Extra", 0]))
    assert %Message{body: [[name]]} = query(ctx.caller, "ListQueuedOwners", "s", [@a])
    assert name == ctx.owner.name
    assert %Message{body: [1]} = query(ctx.owner, "ReleaseName", "s", [@b])
    assert %Message{body: [4]} = query(ctx.owner, "RequestName", "su", [@a, 1])
    assert %Message{body: [1]} = query(ctx.waiter, "RequestName", "su", [@a, 2])
    acquired(ctx.owner, @b)
    limited(query(ctx.owner, "RequestName", "su", [@c, 4]))
    healthy(ctx)
  end

  @tag xml: %{"max_names_per_connection" => 3}
  test "queued names consume XML quota and release, update and promotion reclaim it", ctx do
    acquired(ctx.owner, @a)
    acquired(ctx.owner, @b)
    assert %Message{body: [2]} = query(ctx.waiter, "RequestName", "su", [@a, 0])
    assert %Message{body: [2]} = query(ctx.waiter, "RequestName", "su", [@b, 0])
    limited(query(ctx.waiter, "RequestName", "su", [@a, 1]))
    limited(query(ctx.waiter, "RequestName", "su", [@a, 4]))
    limited(query(ctx.waiter, "RequestName", "su", [@c, 0]))
    assert %Message{body: [[owner, waiter]]} = query(ctx.caller, "ListQueuedOwners", "s", [@a])
    assert owner == ctx.owner.name and waiter == ctx.waiter.name
    assert %Message{body: [1]} = query(ctx.waiter, "ReleaseName", "s", [@b])
    assert %Message{body: [2]} = query(ctx.waiter, "RequestName", "su", [@a, 1])
    assert %Message{body: [1]} = query(ctx.owner, "ReleaseName", "s", [@a])
    assert %Message{body: [waiter]} = query(ctx.caller, "GetNameOwner", "s", [@a])
    assert waiter == ctx.waiter.name
    acquired(ctx.waiter, @c)
    limited(query(ctx.waiter, "RequestName", "su", [@b, 0]))
    assert %Message{body: [1]} = query(ctx.waiter, "ReleaseName", "s", [@c])
    assert %Message{body: [2]} = query(ctx.waiter, "RequestName", "su", [@b, 0])
    healthy(ctx)
  end

  for limit <- [0, 1] do
    @tag xml: %{"max_names_per_connection" => limit}
    test "XML names ceiling #{limit} permits Hello but rejects any RequestName", ctx do
      limited(query(ctx.owner, "RequestName", "su", [@a, 0]))
      assert %Message{body: [names]} = query(ctx.caller, "ListNames")
      assert @a not in names and ctx.owner.name in names
      healthy(ctx)
    end
  end

  @tag xml: %{"max_match_rules_per_connection" => 2}, match_options: [max_matches_per_peer: 1]
  test "XML duplicate matches consume N slots and removal returns exactly one", ctx do
    matched(ctx.caller, @rule)
    matched(ctx.caller, @rule)
    limited(query(ctx.caller, "AddMatch", "s", [@rule]))
    limited(query(ctx.caller, "AddMatch", "s", ["not a match rule"]))
    emit(ctx.owner)
    assert %Message{type: :signal, member: "Notice"} = receive_message(ctx.caller)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    assert %Message{type: :method_return} = query(ctx.caller, "RemoveMatch", "s", [@rule])
    matched(ctx.caller, "type='signal',member='Other'")
    limited(query(ctx.caller, "AddMatch", "s", [@rule]))
    assert %Message{type: :method_return} = query(ctx.caller, "RemoveMatch", "s", [@rule])
    emit(ctx.owner)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    healthy(ctx)
  end

  @tag xml: %{"max_match_rules_per_connection" => 0}
  test "XML zero match ceiling rejects valid and malformed AddMatch without subscriptions", ctx do
    limited(query(ctx.caller, "AddMatch", "s", [@rule]))
    limited(query(ctx.caller, "AddMatch", "s", ["invalid"]))
    emit(ctx.owner)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    healthy(ctx)
  end

  test "omitted XML names and matches use 512 defaults rather than native safety ceilings", ctx do
    for index <- 1..511, do: acquired(ctx.owner, "org.foundation.Default#{index}")
    limited(query(ctx.owner, "RequestName", "su", [@a, 0]))
    for _ <- 1..512, do: matched(ctx.caller, @rule)
    limited(query(ctx.caller, "AddMatch", "s", [@rule]))
    healthy(ctx)
  end

  @tag native: true,
       name_options: [max_names_per_peer: 1],
       match_options: [max_matches_per_peer: 1]
  test "absent XML options preserve native names counting and duplicate ownership behavior",
       ctx do
    acquired(ctx.owner, @a)
    assert %Message{body: [4]} = query(ctx.owner, "RequestName", "su", [@a, 1])
    limited(query(ctx.owner, "RequestName", "su", [@b, 0]))
    matched(ctx.caller, @rule)
    limited(query(ctx.caller, "AddMatch", "s", [@rule]))

    assert %Message{error_name: "org.freedesktop.DBus.Error.MatchRuleInvalid"} =
             query(ctx.caller, "AddMatch", "s", ["invalid"])

    healthy(ctx)
  end

  @tag xml: %{"max_replies_per_connection" => 2, "reply_timeout" => 2000}
  test "pending N+1 is rejected before delivery and a causal reply returns one caller slot",
       ctx do
    first = forwarded(ctx.caller, ctx.owner)
    second = forwarded(ctx.caller, ctx.owner)
    limited(reply(ctx.caller, send_probe(ctx.caller, ctx.owner.name)))
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")
    # A different caller has its own quota even on the same trusted UID.
    other = forwarded(ctx.waiter, ctx.owner)
    denied_reply(ctx.waiter, ctx.caller, first)
    assert %Message{type: :method_return} = query(ctx.waiter, "GetId")
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    send_reply(ctx.owner, ctx.caller, first)
    assert %Message{type: :method_return, reply_serial: ^first} = reply(ctx.caller, first)
    third = forwarded(ctx.caller, ctx.owner)
    send_probe(ctx.caller, ctx.owner.name, 1)
    assert %Message{type: :method_call, flags: 1} = receive_message(ctx.owner)

    for serial <- [second, third] do
      send_reply(ctx.owner, ctx.caller, serial)
      assert %Message{type: :method_return, reply_serial: ^serial} = reply(ctx.caller, serial)
    end

    send_reply(ctx.owner, ctx.waiter, other)
    assert %Message{type: :method_return} = reply(ctx.waiter, other)
    healthy(ctx)
  end

  @tag xml: %{"max_replies_per_connection" => 0, "reply_timeout" => 1000}
  test "zero pending ceiling rejects expected replies but permits NO_REPLY_EXPECTED", ctx do
    limited(reply(ctx.caller, send_probe(ctx.caller, ctx.owner.name)))
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")
    serial = send_probe(ctx.caller, ctx.owner.name, 1)
    assert %Message{type: :method_call, serial: ^serial, flags: 1} = receive_message(ctx.owner)
    denied_reply(ctx.owner, ctx.caller, serial)
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    healthy(ctx)
  end

  @tag xml: %{"max_replies_per_connection" => 1, "reply_timeout" => 0}
  test "explicit XML zero timeout preserves late causal replies without a timer", ctx do
    assert ctx.xml["reply_timeout"] == 0
    serial = forwarded(ctx.caller, ctx.owner)
    assert :sys.get_state(Router).pending_timer == nil
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller.socket, 1, 80)
    limited(reply(ctx.caller, send_probe(ctx.caller, ctx.owner.name)))
    send_reply(ctx.owner, ctx.caller, serial)
    assert %Message{type: :method_return} = reply(ctx.caller, serial)
    next = forwarded(ctx.caller, ctx.owner)
    send_reply(ctx.owner, ctx.caller, next)
    assert %Message{type: :method_return} = reply(ctx.caller, next)
    healthy(ctx)
  end

  @tag xml: %{"max_replies_per_connection" => 1},
       deny:
         ~s(<deny receive_type="method_return" receive_interface="org.foundation.Blocked" receive_sender="org.foundation.QuotaA" receive_requested_reply="true"/>)
  test "XML receive denial returns a bounded diagnostic and retires the causal quota",
       ctx do
    acquired(ctx.owner, @a)
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")

    for interface <- [nil, "org.foundation.Blocked", "org.foundation.Accepted"] do
      serial = forwarded(ctx.caller, ctx.owner)
      denied_reply(ctx.owner, ctx.caller, serial, interface)
      assert %Message{type: :method_return} = query(ctx.caller, "GetId")
      assert :sys.get_state(Router).pending.entries == %{}
      denied_reply(ctx.owner, ctx.caller, serial)
      assert %Message{type: :method_return} = query(ctx.caller, "GetId")
      assert :sys.get_state(Router).pending.entries == %{}
      next = forwarded(ctx.caller, ctx.owner)
      denied_reply(ctx.owner, ctx.caller, next)
      assert %Message{type: :method_return} = query(ctx.caller, "GetId")
      assert :sys.get_state(Router).pending.entries == %{}
    end

    healthy(ctx)
  end

  @tag xml: %{"max_replies_per_connection" => 1},
       deny:
         ~s(<deny receive_type="method_return" receive_sender="org.foundation.QuotaA" receive_requested_reply="true"/>)
  test "XML alias release permits new replies after a denied reply retires its quota", ctx do
    acquired(ctx.owner, @a)
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")
    serial = forwarded(ctx.caller, ctx.owner)
    denied_reply(ctx.owner, ctx.caller, serial)
    assert :sys.get_state(Router).pending.entries == %{}
    denied_reply(ctx.owner, ctx.caller, serial)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    assert %Message{body: [1]} = query(ctx.owner, "ReleaseName", "s", [@a])
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")
    next = forwarded(ctx.caller, ctx.owner)
    send_reply(ctx.owner, ctx.caller, next)
    assert %Message{type: :method_return} = reply(ctx.caller, next)
    healthy(ctx)
  end

  @tag xml: %{"max_replies_per_connection" => 1, "reply_timeout" => 40}
  test "finite reply timeout sends one NoReply, denies stale reply and reclaims XML capacity",
       ctx do
    serial = forwarded(ctx.caller, ctx.owner)
    assert %Message{error_name: "org.freedesktop.DBus.Error.NoReply"} = reply(ctx.caller, serial)
    denied_reply(ctx.owner, ctx.caller, serial)
    assert %Message{type: :method_return} = query(ctx.owner, "GetId")
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    next = forwarded(ctx.caller, ctx.owner)
    send_reply(ctx.owner, ctx.caller, next)
    assert %Message{type: :method_return} = reply(ctx.caller, next)
    healthy(ctx)
  end

  @tag timeout: :infinity, xml: %{"max_replies_per_connection" => 1}
  test "omitted XML timeout keeps causal replies indefinitely without a timer but remains bounded",
       ctx do
    serial = forwarded(ctx.caller, ctx.owner)
    state = :sys.get_state(Router)
    assert state.pending_timer == nil
    assert [%{deadline: :infinity}] = Map.values(state.pending.entries)
    assert {:error, :timeout} = :gen_tcp.recv(ctx.caller.socket, 1, 80)
    limited(reply(ctx.caller, send_probe(ctx.caller, ctx.owner.name)))
    denied_reply(ctx.waiter, ctx.caller, serial)
    assert %Message{type: :method_return} = query(ctx.waiter, "GetId")
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
    send_reply(ctx.owner, ctx.caller, serial)
    assert %Message{type: :method_return} = reply(ctx.caller, serial)
    assert :sys.get_state(Router).pending.entries == %{}
    next = forwarded(ctx.caller, ctx.owner)
    monitor = Process.monitor(ctx.owner.pid)
    :ok = :gen_tcp.close(ctx.owner.socket)
    assert_receive {:DOWN, ^monitor, :process, _, _}, 1000
    assert %Message{error_name: "org.freedesktop.DBus.Error.NoReply"} = reply(ctx.caller, next)
    last = forwarded(ctx.caller, ctx.waiter)
    send_reply(ctx.waiter, ctx.caller, last)
    assert %Message{type: :method_return} = reply(ctx.caller, last)
    assert %Message{type: :method_return} = query(ctx.caller, "GetId")
  end

  test "pure pending state distinguishes infinity and zero with native finite defaults" do
    assert {:ok, native} = PendingCalls.new()
    assert native.limits.timeout_ms == 25_000
    assert {:ok, state} = PendingCalls.new(%{timeout_ms: :infinity, per_peer: 1})
    message = %Message{serial: 9, sender: ":1.9"}
    assert {:ok, state} = PendingCalls.add(state, message, self(), :callee, 1000, -10)
    assert PendingCalls.requested?(state, self(), :callee, 9, 9_999_999_999)
    refute PendingCalls.requested?(state, self(), :attacker, 9, 9_999_999_999)
    assert {[], ^state} = PendingCalls.expire(state, 9_999_999_999)
    assert PendingCalls.next_deadline(state) == :infinity

    assert {:error, :limits_exceeded} =
             PendingCalls.add(state, %{message | serial: 10}, self(), :callee, 1000, 0)

    assert {:ok, zero} = PendingCalls.new(%{timeout_ms: 0})
    assert {:ok, zero} = PendingCalls.add(zero, message, self(), :callee, 1000, 12)
    refute PendingCalls.requested?(zero, self(), :callee, 9, 12)
    assert {[%{deadline: 12}], %{entries: entries}} = PendingCalls.expire(zero, 12)
    assert entries == %{}

    for invalid <- [%{per_peer: :infinity}, %{global: :infinity}, %{timeout_ms: -1}] do
      assert {:error, :invalid_pending_limits} = PendingCalls.new(invalid)
    end
  end

  defp acquired(client, name),
    do: assert(%Message{body: [1]} = query(client, "RequestName", "su", [name, 0]))

  defp matched(client, rule),
    do: assert(%Message{type: :method_return} = query(client, "AddMatch", "s", [rule]))

  defp limited(message), do: assert(%Message{type: :error, error_name: @limits} = message)

  defp connect(path, uid) do
    assert {:ok, socket} =
             :gen_tcp.connect({:local, path}, 0, [:binary, active: false, packet: :line], 1000)

    on_exit(fn -> :gen_tcp.close(socket) end)

    :ok =
      :gen_tcp.send(socket, <<0>> <> "AUTH EXTERNAL #{Base.encode16(Integer.to_string(uid))}\r\n")

    assert {:ok, "OK " <> _} = :gen_tcp.recv(socket, 0, 1000)
    :ok = :inet.setopts(socket, packet: :raw)
    :ok = :gen_tcp.send(socket, "BEGIN\r\n")
    assert %Message{body: [name]} = query(%{socket: socket}, "Hello")
    assert {:ok, pid} = NameRegistry.resolve(name)
    assert %Message{type: :method_return} = query(%{socket: socket}, "GetId")
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
        flags: flags
      )

    :ok = :gen_tcp.send(client.socket, Message.encode_message(message))
    serial
  end

  defp forwarded(source, target) do
    serial = send_probe(source, target.name)

    assert %Message{type: :method_call, member: "Probe", serial: ^serial} =
             receive_message(target)

    serial
  end

  defp send_reply(source, target, serial, interface \\ nil) do
    response_serial = System.unique_integer([:positive])

    :ok =
      :gen_tcp.send(
        source.socket,
        Message.encode_message(%{
          Message.method_return(serial, destination: target.name, serial: response_serial)
          | interface: interface
        })
      )

    response_serial
  end

  defp denied_reply(source, target, serial, interface \\ nil) do
    response_serial = send_reply(source, target, serial, interface)

    assert %Message{
             type: :error,
             reply_serial: ^response_serial,
             error_name: "org.freedesktop.DBus.Error.AccessDenied",
             sender: @bus,
             destination: name,
             fds: [],
             body: ["Operation denied by bus policy"]
           } = reply(source, response_serial)

    assert name == source.name
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
      assert %Message{type: :method_return} = query(client, "GetId")
      assert {:ok, pid} = NameRegistry.resolve(client.name)
      assert pid == client.pid
    end
  end
end
