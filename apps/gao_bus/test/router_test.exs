defmodule GaoBus.RouterTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{MatchRules, NameRegistry, Policy, Router}

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    start_supervised!(GaoBus.Limits)
    start_supervised!(NameRegistry)
    start_supervised!(MatchRules)
    start_supervised!({Policy, rules: Policy.session_rules()})
    start_supervised!(Router)
    GaoBus.Peer.ensure_counter()
    register_peer(self(), ":1.99")
    :ok
  end

  # Unit peers model authenticated authority entries; socket identity is proved
  # separately. Unique-name ownership precedes routing:
  # https://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-names
  defp start_fake_peer(opts \\ []) do
    name = Keyword.get(opts, :unique_name)
    test_pid = self()
    peer = start_supervised!({Task, fn -> fake_peer_loop(name, test_pid) end}, id: make_ref())
    register_peer(peer, name)
    peer
  end

  defp fake_peer_loop(name, test_pid) do
    receive do
      {:"$gen_call", from, :get_unique_name} ->
        GenServer.reply(from, name)
        fake_peer_loop(name, test_pid)

      {:"$gen_call", from, :assign_unique_name} ->
        ref = :persistent_term.get(:gao_bus_peer_counter)
        name = name || ":1.#{:atomics.add_get(ref, 1, 1)}"
        GenServer.reply(from, name)
        fake_peer_loop(name, test_pid)

      {:send_message, message, {token, _queued_at}} ->
        :ok = GaoBus.Limits.release(token)
        send(test_pid, {:peer_received, self(), {:send_message, message}})
        fake_peer_loop(name, test_pid)

      message ->
        send(test_pid, {:peer_received, self(), message})
        fake_peer_loop(name, test_pid)
    end
  end

  defp register_peer(peer, name) do
    credentials = %{uid: 1000, gid: 1000, pid: 123, unique_name: name}
    {:ok, accounting} = GaoBus.Limits.snapshot()

    unless Map.has_key?(accounting.peers, peer) do
      assert :ok = GaoBus.Limits.acquire(peer, credentials)
      assert :ok = GaoBus.Limits.auth_completed(peer)
    end

    Router.register_peer(peer, name, credentials)
    if name, do: NameRegistry.register_unique(name, peer)
    _ = :sys.get_state(Router)

    # NameAcquired is a required unicast notification, independent of match
    # rules (D-Bus NameAcquired and Message Bus Message Routing sections).
    if name do
      if peer == self() do
        assert_receive {:send_message,
                        %Message{member: "NameAcquired", destination: ^name, body: [^name]},
                        {token, _queued_at}}

        assert :ok = GaoBus.Limits.release(token)
      else
        assert_receive {:peer_received, ^peer,
                        {:send_message,
                         %Message{member: "NameAcquired", destination: ^name, body: [^name]}}}
      end
    end

    :ok
  end

  # --- Message helpers ---

  defp bus_method_call(member, opts) do
    sender = Keyword.get(opts, :sender, ":1.99")
    serial = Keyword.get(opts, :serial, 1)
    signature = Keyword.get(opts, :signature, nil)
    body = Keyword.get(opts, :body, [])

    %Message{
      type: :method_call,
      serial: serial,
      path: "/org/freedesktop/DBus",
      destination: "org.freedesktop.DBus",
      interface: "org.freedesktop.DBus",
      member: member,
      sender: sender,
      signature: signature,
      body: body
    }
  end

  defp method_call_to(destination, member, opts) do
    sender = Keyword.get(opts, :sender, ":1.1")
    serial = Keyword.get(opts, :serial, 1)
    signature = Keyword.get(opts, :signature, nil)
    body = Keyword.get(opts, :body, [])

    %Message{
      type: :method_call,
      serial: serial,
      path: "/some/path",
      interface: "com.example.Interface",
      member: member,
      destination: destination,
      sender: sender,
      signature: signature,
      body: body
    }
  end

  # --- Tests ---

  describe "register_peer/unregister_peer" do
    test "registered subscribed peer receives signals" do
      peer = start_fake_peer()
      register_peer(peer, ":1.50")

      :ok =
        MatchRules.add_match(peer, "type='signal',interface='com.test.Iface',member='TestSignal'")

      _ = :sys.get_state(Router)

      signal =
        Message.signal("/test", "com.test.Iface", "TestSignal",
          sender: ":1.1",
          serial: 1
        )

      Router.route(signal, self())
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer, {:send_message, msg}}
      assert msg.type == :signal
      assert msg.member == "TestSignal"
    end

    test "unregistered peer stops receiving signals" do
      peer = start_fake_peer()
      register_peer(peer, ":1.50")

      :ok =
        MatchRules.add_match(peer, "type='signal',interface='com.test.Iface',member='TestSignal'")

      _ = :sys.get_state(Router)

      Router.unregister_peer(peer)
      _ = :sys.get_state(Router)
      _ = :sys.get_state(MatchRules)

      signal =
        Message.signal("/test", "com.test.Iface", "TestSignal",
          sender: ":1.1",
          serial: 1
        )

      Router.route(signal, self())
      _ = :sys.get_state(Router)

      refute_receive {:peer_received, _, _}
    end
  end

  describe "emit_signal" do
    test "emitted signal is delivered to subscribed registered peers" do
      peer = start_fake_peer()
      register_peer(peer, ":1.50")
      :ok = MatchRules.add_match(peer, "type='signal',member='NameOwnerChanged'")
      _ = :sys.get_state(Router)

      Router.emit_signal(
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "NameOwnerChanged",
        "sss",
        ["com.test.Svc", "", ":1.10"]
      )

      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer, {:send_message, msg}}
      assert msg.type == :signal
      assert msg.member == "NameOwnerChanged"
      assert msg.sender == "org.freedesktop.DBus"
      assert msg.body == ["com.test.Svc", "", ":1.10"]
    end

    test "emitted signal has auto-incremented serial" do
      peer = start_fake_peer()
      register_peer(peer, ":1.50")
      :ok = MatchRules.add_match(peer, "type='signal',interface='com.test.I'")
      _ = :sys.get_state(Router)

      Router.emit_signal("/test", "com.test.I", "Sig1", nil, [])
      Router.emit_signal("/test", "com.test.I", "Sig2", nil, [])
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer, {:send_message, msg1}}
      assert_receive {:peer_received, ^peer, {:send_message, msg2}}
      assert msg2.serial > msg1.serial
    end
  end

  describe "route method_call to bus (org.freedesktop.DBus)" do
    test "Hello message returns unique name to peer" do
      peer = start_fake_peer()

      msg = bus_method_call("Hello", sender: ":1.99")
      Router.route(msg, peer)
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer, {:send_message, reply}}
      assert reply.type == :method_return
      [name] = reply.body
      assert String.starts_with?(name, ":1.")
    end

    test "ListNames returns at least org.freedesktop.DBus" do
      peer = start_fake_peer(unique_name: ":1.10")

      msg = bus_method_call("ListNames", sender: ":1.10")
      Router.route(msg, peer)
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer, {:send_message, reply}}
      assert reply.type == :method_return
      [names] = reply.body
      assert "org.freedesktop.DBus" in names
    end
  end

  describe "route method_call to named peer" do
    test "message is delivered to the target peer" do
      # Register sender in the NameRegistry so error replies can route back
      sender_peer = start_fake_peer()
      register_peer(sender_peer, ":1.1")

      # Register target peer with a well-known name
      target_peer = start_fake_peer()
      register_peer(target_peer, ":1.10")
      NameRegistry.request_name("com.test.Target", 0, target_peer, ":1.10")

      assert_receive {:peer_received, ^target_peer,
                      {:send_message, %Message{member: "NameAcquired", body: ["com.test.Target"]}}}

      msg = method_call_to("com.test.Target", "DoStuff", sender: ":1.1")
      Router.route(msg, sender_peer)
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^target_peer, {:send_message, delivered}}
      assert delivered.type == :method_call
      assert delivered.member == "DoStuff"
      assert delivered.destination == "com.test.Target"
    end

    test "message to unique name is delivered" do
      sender_peer = start_fake_peer()
      register_peer(sender_peer, ":1.1")

      target_peer = start_fake_peer()
      register_peer(target_peer, ":1.20")

      msg = method_call_to(":1.20", "Ping", sender: ":1.1")
      Router.route(msg, sender_peer)
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^target_peer, {:send_message, delivered}}
      assert delivered.type == :method_call
      assert delivered.member == "Ping"
    end
  end

  describe "route to unknown destination" do
    test "returns ServiceUnknown error to sender" do
      # Register self() directly so the error reply comes to this process
      register_peer(self(), ":1.1")
      _ = :sys.get_state(Router)

      msg = method_call_to("com.nonexistent.Service", "Call", sender: ":1.1")
      Router.route(msg, self())
      _ = :sys.get_state(Router)

      assert_receive {:send_message, error_msg, {token, _queued_at}}, 500
      assert :ok = GaoBus.Limits.release(token)
      assert error_msg.type == :error
      assert error_msg.error_name == "org.freedesktop.DBus.Error.ServiceUnknown"
    end

    test "NO_AUTO_START selects NameHasNoOwner independently of unrelated flags" do
      register_peer(self(), ":1.1")

      for {flags, expected_error} <- [
            {2, "org.freedesktop.DBus.Error.NameHasNoOwner"},
            {4, "org.freedesktop.DBus.Error.ServiceUnknown"},
            {6, "org.freedesktop.DBus.Error.NameHasNoOwner"}
          ] do
        serial = 100 + flags
        msg = method_call_to("com.nonexistent.Service", "Call", sender: ":1.1", serial: serial)
        msg = %{msg | flags: flags}
        assert :ok = Router.route(msg, self())
        _ = :sys.get_state(Router)

        assert_receive {:send_message,
                        %Message{
                          type: :error,
                          error_name: ^expected_error,
                          reply_serial: ^serial,
                          destination: ":1.1",
                          sender: "org.freedesktop.DBus"
                        }, {token, _queued_at}},
                       500

        assert :ok = GaoBus.Limits.release(token)
      end
    end
  end

  describe "route method_return/error" do
    test "method_return is routed back to the sender by destination" do
      caller_peer = start_fake_peer()
      register_peer(caller_peer, ":1.1")

      reply =
        Message.method_return(1,
          serial: 5,
          destination: ":1.1",
          sender: ":1.20",
          signature: "s",
          body: ["hello"]
        )

      Router.route(reply, self())
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^caller_peer, {:send_message, delivered}}
      assert delivered.type == :method_return
      assert delivered.body == ["hello"]
    end

    test "error is routed back to the sender by destination" do
      caller_peer = start_fake_peer()
      register_peer(caller_peer, ":1.1")

      error =
        Message.error("org.freedesktop.DBus.Error.Failed", 1,
          serial: 5,
          destination: ":1.1",
          sender: ":1.20",
          signature: "s",
          body: ["something broke"]
        )

      Router.route(error, self())
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^caller_peer, {:send_message, delivered}}
      assert delivered.type == :error
      assert delivered.error_name == "org.freedesktop.DBus.Error.Failed"
      assert delivered.body == ["something broke"]
    end

    test "method_return to unknown destination is silently dropped" do
      reply =
        Message.method_return(1,
          serial: 5,
          destination: ":1.999",
          sender: ":1.20"
        )

      Router.route(reply, self())
      _ = :sys.get_state(Router)

      refute_receive {:peer_received, _, _}
    end
  end

  describe "auto-unregister on process death" do
    test "dead peer is removed from registered peers" do
      peer = start_fake_peer(unique_name: ":1.50")
      live_peer = start_fake_peer(unique_name: ":1.51")
      :ok = MatchRules.add_match(peer, "type='signal',member='Ping'")
      :ok = MatchRules.add_match(live_peer, "type='signal',member='Ping'")

      :ok =
        MatchRules.add_match(live_peer, "type='signal',member='NameOwnerChanged',arg0=':1.50'")

      reference = Process.monitor(peer)
      Process.exit(peer, :kill)
      assert_receive {:DOWN, ^reference, :process, ^peer, :killed}

      # The authoritative disconnect signal is the synchronization barrier.
      assert_receive {:peer_received, ^live_peer,
                      {:send_message,
                       %Message{member: "NameOwnerChanged", body: [":1.50", ":1.50", ""]}}}

      refute Map.has_key?(:sys.get_state(Router).peers, peer)
      assert {:error, :name_not_found} = NameRegistry.resolve(":1.50")
      _ = :sys.get_state(MatchRules)
      refute MatchRules.has_rules?(peer)

      signal = Message.signal("/test", "com.test.Iface", "Ping", serial: 1)
      Router.route(signal, self())
      _ = :sys.get_state(Router)
      assert_receive {:peer_received, ^live_peer, {:send_message, %Message{member: "Ping"}}}
      refute_receive {:peer_received, _, _}
    end
  end

  # D-Bus broadcasts go only to applications whose match rules match;
  # unicast goes to its recipient independently of subscriptions:
  # https://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-routing
  describe "signal broadcasting" do
    test "signal is delivered only to subscribed registered peers" do
      peer1 = start_fake_peer()
      peer2 = start_fake_peer()
      peer3 = start_fake_peer()

      register_peer(peer1, ":1.10")
      register_peer(peer2, ":1.11")
      register_peer(peer3, ":1.12")
      :ok = MatchRules.add_match(peer1, "type='signal',member='Broadcast'")
      :ok = MatchRules.add_match(peer2, "type='signal',member='Broadcast'")
      _ = :sys.get_state(Router)

      signal =
        Message.signal("/test", "com.test.Iface", "Broadcast",
          sender: ":1.1",
          serial: 1
        )

      Router.route(signal, self())
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer1, {:send_message, m1}}
      assert_receive {:peer_received, ^peer2, {:send_message, m2}}
      # peer3 has no subscription and must not receive the broadcast.
      refute_receive {:peer_received, _, _}

      for msg <- [m1, m2] do
        assert msg.type == :signal
        assert msg.member == "Broadcast"
      end
    end

    test "signal with match rules only goes to matching peers" do
      peer1 = start_fake_peer()
      peer2 = start_fake_peer()

      register_peer(peer1, ":1.10")
      register_peer(peer2, ":1.11")
      _ = :sys.get_state(Router)

      # peer1 subscribes to a specific signal
      MatchRules.add_match(peer1, "type='signal',interface='com.test.Specific',member='Matched'")
      # peer2 subscribes to a different signal
      MatchRules.add_match(peer2, "type='signal',interface='com.test.Other',member='Other'")

      signal =
        Message.signal("/test", "com.test.Specific", "Matched",
          sender: ":1.1",
          serial: 1
        )

      Router.route(signal, self())
      _ = :sys.get_state(Router)

      # peer1 matches, peer2 does not match
      assert_receive {:peer_received, ^peer1, {:send_message, msg}}
      assert msg.member == "Matched"

      # peer2 should not get it (it has rules, but none match)
      refute_receive {:peer_received, _, _}
    end
  end

  describe "route method_call with nil destination" do
    test "treats as bus message" do
      peer = start_fake_peer(unique_name: ":1.10")

      msg = %Message{
        type: :method_call,
        serial: 1,
        path: "/org/freedesktop/DBus",
        interface: "org.freedesktop.DBus",
        member: "GetId",
        destination: nil,
        sender: ":1.10"
      }

      Router.route(msg, peer)
      _ = :sys.get_state(Router)

      assert_receive {:peer_received, ^peer, {:send_message, reply}}
      assert reply.type == :method_return
      [id] = reply.body
      assert is_binary(id)
      assert byte_size(id) > 0
    end
  end
end
