defmodule GaoBus.BusInterfaceTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{BusInterface, Policy}

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    start_supervised!(GaoBus.Limits)
    start_supervised!(GaoBus.NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!({Policy, rules: Policy.session_rules()})
    GaoBus.Peer.ensure_counter()

    %{state: %{peers: %{}, next_serial: 1, policy_snapshot: Policy.snapshot()}}
  end

  # Unit peers model the already-authenticated authority entry; they do not
  # derive identity from message fields. Socket credential proof is separate.
  defp start_fake_peer(state, opts \\ []) do
    name = Keyword.get(opts, :unique_name)
    peer = start_supervised!({Task, fn -> fake_peer_loop(name) end}, id: make_ref())
    credentials = %{uid: 1000, gid: 1000, pid: 123, unique_name: name}
    :ok = GaoBus.Limits.acquire(peer, credentials)
    :ok = GaoBus.Limits.auth_completed(peer)
    if name, do: GaoBus.NameRegistry.register_unique(name, peer)
    info = %{unique_name: name, credentials: credentials}
    {peer, put_in(state.peers[peer], info)}
  end

  defp fake_peer_loop(name) do
    receive do
      {:"$gen_call", from, :get_unique_name} ->
        GenServer.reply(from, name)
        fake_peer_loop(name)

      {:"$gen_call", from, :assign_unique_name} ->
        ref = :persistent_term.get(:gao_bus_peer_counter)
        name = name || ":1.#{:atomics.add_get(ref, 1, 1)}"
        GenServer.reply(from, name)
        fake_peer_loop(name)

      _other ->
        fake_peer_loop(name)
    end
  end

  defp bus_method_call(member, opts \\ []) do
    signature = Keyword.get(opts, :signature, nil)
    body = Keyword.get(opts, :body, [])
    interface = Keyword.get(opts, :interface, "org.freedesktop.DBus")

    %Message{
      type: :method_call,
      serial: 1,
      path: "/org/freedesktop/DBus",
      destination: "org.freedesktop.DBus",
      interface: interface,
      member: member,
      sender: Keyword.get(opts, :sender, ":1.10"),
      signature: signature,
      body: body
    }
  end

  describe "Hello" do
    test "assigns unique name on first call", %{state: state} do
      {peer, state} = start_fake_peer(state)
      msg = bus_method_call("Hello", sender: nil)

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      [name] = reply.body
      assert String.starts_with?(name, ":1.")
    end

    test "returns error on second Hello", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.50")
      msg = bus_method_call("Hello", sender: ":1.50")

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :error
      assert reply.error_name == "org.freedesktop.DBus.Error.Failed"
    end
  end

  describe "RequestName" do
    test "grants ownership", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("RequestName", signature: "su", body: ["com.test.Svc", 0])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      # primary owner
      assert reply.body == [1]
    end
  end

  describe "ReleaseName" do
    test "reserved release is a controlled InvalidArgs error", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      for name <- ["org.freedesktop.DBus", ":1.10", "invalid"] do
        msg = bus_method_call("ReleaseName", signature: "s", body: [name])
        {reply, _state} = BusInterface.handle_message(msg, peer, state)
        assert reply.error_name == "org.freedesktop.DBus.Error.InvalidArgs"
      end
    end

    test "releases owned name", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")
      GaoBus.NameRegistry.request_name("com.test.Svc", 0, peer, ":1.10")

      msg = bus_method_call("ReleaseName", signature: "s", body: ["com.test.Svc"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      # released
      assert reply.body == [1]
    end

    test "releasing non-existent name returns 2", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("ReleaseName", signature: "s", body: ["com.test.NoSuch"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      # non-existent
      assert reply.body == [2]
    end
  end

  describe "ListQueuedOwners" do
    test "returns current owner followed by each unique waiter", %{state: state} do
      {owner, state} = start_fake_peer(state, unique_name: ":1.10")
      {waiter, state} = start_fake_peer(state, unique_name: ":1.11")

      assert {:ok, 1} =
               GaoBus.NameRegistry.request_name("org.foundation.Queue", 0, owner, ":1.10")

      assert {:ok, 2} =
               GaoBus.NameRegistry.request_name("org.foundation.Queue", 0, waiter, ":1.11")

      msg = bus_method_call("ListQueuedOwners", signature: "s", body: ["org.foundation.Queue"])
      {reply, _state} = BusInterface.handle_message(msg, owner, state)
      assert reply.type == :method_return
      assert reply.signature == "as"
      assert reply.body == [[":1.10", ":1.11"]]
    end

    test "missing name returns NameHasNoOwner", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")
      msg = bus_method_call("ListQueuedOwners", signature: "s", body: ["org.foundation.Missing"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)
      assert reply.error_name == "org.freedesktop.DBus.Error.NameHasNoOwner"
    end
  end

  describe "GetNameOwner" do
    test "returns owner of well-known name", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")
      GaoBus.NameRegistry.request_name("com.test.Svc", 0, peer, ":1.10")

      msg = bus_method_call("GetNameOwner", signature: "s", body: ["com.test.Svc"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      assert reply.body == [":1.10"]
    end

    test "returns error for unknown name", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("GetNameOwner", signature: "s", body: ["com.test.Unknown"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :error
      assert reply.error_name == "org.freedesktop.DBus.Error.NameHasNoOwner"
    end
  end

  describe "ListNames" do
    test "includes org.freedesktop.DBus", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("ListNames")
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      [names] = reply.body
      assert "org.freedesktop.DBus" in names
    end

    test "includes registered unique and well-known names", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")
      GaoBus.NameRegistry.request_name("com.test.Svc", 0, peer, ":1.10")

      msg = bus_method_call("ListNames")
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      [names] = reply.body
      assert ":1.10" in names
      assert "com.test.Svc" in names
    end
  end

  describe "ListActivatableNames" do
    test "returns empty list", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("ListActivatableNames")
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      assert reply.body == [[]]
    end
  end

  describe "NameHasOwner" do
    test "true for org.freedesktop.DBus", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("NameHasOwner", signature: "s", body: ["org.freedesktop.DBus"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      assert reply.body == [true]
    end

    test "false for unknown name", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("NameHasOwner", signature: "s", body: ["com.test.Unknown"])
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      assert reply.body == [false]
    end
  end

  describe "GetId" do
    test "returns bus instance ID", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("GetId")
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      [id] = reply.body
      assert is_binary(id)
      assert byte_size(id) > 0
    end
  end

  describe "AddMatch / RemoveMatch" do
    test "AddMatch succeeds for valid rule", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("AddMatch",
          signature: "s",
          body: ["type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'"]
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
    end

    test "RemoveMatch succeeds after AddMatch", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")
      rule = "type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'"

      # Add first
      add_msg = bus_method_call("AddMatch", signature: "s", body: [rule])
      {_, state} = BusInterface.handle_message(add_msg, peer, state)

      # Remove
      rem_msg = bus_method_call("RemoveMatch", signature: "s", body: [rule])
      {reply, _state} = BusInterface.handle_message(rem_msg, peer, state)

      assert reply.type == :method_return
    end

    test "RemoveMatch fails for non-existent rule", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("RemoveMatch",
          signature: "s",
          body: ["type='signal',member='NeverAdded'"]
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :error
    end
  end

  describe "Introspect" do
    test "returns XML with bus interface", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("Introspect",
          interface: "org.freedesktop.DBus.Introspectable"
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      [xml] = reply.body
      assert String.contains?(xml, "org.freedesktop.DBus")
      assert String.contains?(xml, "<method name=\"Hello\">")
      assert String.contains?(xml, "<method name=\"RequestName\">")
      assert String.contains?(xml, "<signal name=\"NameOwnerChanged\">")
    end
  end

  describe "Properties" do
    test "Set rejects each read-only property without changing its value", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      for interface <- ["", "org.freedesktop.DBus"],
          property <- ["Features", "Interfaces"],
          value <- [{"as", ["foundation-property-set-sentinel"]}, {"s", "other type"}] do
        get =
          bus_method_call("Get",
            interface: "org.freedesktop.DBus.Properties",
            signature: "ss",
            body: [interface, property]
          )

        {before, state} = BusInterface.handle_message(get, peer, state)
        assert before.type == :method_return

        set = %{get | member: "Set", signature: "ssv", body: [interface, property, value]}
        {reply, updated} = BusInterface.handle_message(set, peer, state)

        assert %Message{
                 type: :error,
                 error_name: "org.freedesktop.DBus.Error.PropertyReadOnly",
                 reply_serial: 1,
                 sender: "org.freedesktop.DBus",
                 destination: ":1.10",
                 signature: "s",
                 body: [explanation]
               } = reply

        assert is_binary(explanation) and explanation != ""
        assert Map.delete(updated, :next_serial) == Map.delete(state, :next_serial)
        {after_reply, _state} = BusInterface.handle_message(get, peer, updated)
        assert after_reply.type == :method_return
        assert after_reply.body == before.body
      end
    end

    test "Set distinguishes unknown interfaces and properties", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      for {interface, property, error} <- [
            {"org.foundation.Missing", "Features", "UnknownInterface"},
            {"org.freedesktop.DBus", "Missing", "UnknownProperty"},
            {"", "Missing", "UnknownProperty"},
            {"org.freedesktop.DBus.Peer", "Features", "UnknownProperty"}
          ] do
        message =
          bus_method_call("Set",
            interface: "org.freedesktop.DBus.Properties",
            signature: "ssv",
            body: [interface, property, {"as", []}]
          )

        {reply, updated} = BusInterface.handle_message(message, peer, state)
        assert reply.type == :error
        assert reply.error_name == "org.freedesktop.DBus.Error." <> error
        assert Map.delete(updated, :next_serial) == Map.delete(state, :next_serial)
      end
    end

    test "Set validates signature, argument count and decoded variant shape", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      for {signature, body} <- [
            {"ss", ["org.freedesktop.DBus", "Features"]},
            {"ssv", ["org.freedesktop.DBus", "Features"]},
            {"ssv", ["org.freedesktop.DBus", "Features", {"as", []}, "extra"]},
            {"ssv", [42, "Features", {"as", []}]},
            {"ssv", ["org.freedesktop.DBus", 42, {"as", []}]},
            {"ssv", ["org.freedesktop.DBus", "Features", []]},
            {"ssv", ["org.freedesktop.DBus", "Features", {42, []}]},
            {"ssv", ["org.freedesktop.DBus", "Features", {"", []}]},
            {"ssv", ["org.freedesktop.DBus", "Features", {"ss", []}]}
          ] do
        message =
          bus_method_call("Set",
            interface: "org.freedesktop.DBus.Properties",
            signature: signature,
            body: body
          )

        {reply, updated} = BusInterface.handle_message(message, peer, state)
        assert reply.type == :error
        assert reply.error_name == "org.freedesktop.DBus.Error.InvalidArgs"
        assert Map.delete(updated, :next_serial) == Map.delete(state, :next_serial)
      end
    end

    test "Get Features returns empty array", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("Get",
          interface: "org.freedesktop.DBus.Properties",
          signature: "ss",
          body: ["org.freedesktop.DBus", "Features"]
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      assert [{"as", []}] = reply.body
    end

    # The D-Bus Interfaces property lists optional bus interfaces and excludes
    # DBus, Peer, Introspectable and Properties (specification, Interfaces).
    test "Get Interfaces returns only implemented optional bus interfaces", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("Get",
          interface: "org.freedesktop.DBus.Properties",
          signature: "ss",
          body: ["org.freedesktop.DBus", "Interfaces"]
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      assert [{"as", []}] = reply.body
    end

    test "Get unknown property returns error", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("Get",
          interface: "org.freedesktop.DBus.Properties",
          signature: "ss",
          body: ["org.freedesktop.DBus", "NoSuchProp"]
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :error
      assert reply.error_name == "org.freedesktop.DBus.Error.UnknownProperty"
    end

    test "GetAll returns Features and Interfaces", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg =
        bus_method_call("GetAll",
          interface: "org.freedesktop.DBus.Properties",
          signature: "s",
          body: ["org.freedesktop.DBus"]
        )

      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :method_return
      [props] = reply.body
      keys = Enum.map(props, &elem(&1, 0))
      assert "Features" in keys
      assert "Interfaces" in keys
    end

    test "GetAll on implemented propertyless interfaces returns an empty dictionary", %{
      state: state
    } do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      for interface <- [
            "org.freedesktop.DBus.Peer",
            "org.freedesktop.DBus.Introspectable",
            "org.freedesktop.DBus.Properties"
          ] do
        message =
          bus_method_call("GetAll",
            interface: "org.freedesktop.DBus.Properties",
            signature: "s",
            body: [interface]
          )

        {reply, updated} = BusInterface.handle_message(message, peer, state)
        assert reply.type == :method_return
        assert reply.signature == "a{sv}"
        assert [[]] = reply.body
        assert reply.reply_serial == message.serial
        assert reply.destination == ":1.10"
        assert Map.delete(updated, :next_serial) == Map.delete(state, :next_serial)
      end
    end

    test "GetAll distinguishes unknown interfaces without changing authority", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      message =
        bus_method_call("GetAll",
          interface: "org.freedesktop.DBus.Properties",
          signature: "s",
          body: ["org.foundation.UnknownInterface"]
        )

      {reply, updated} = BusInterface.handle_message(message, peer, state)
      assert reply.type == :error
      assert reply.error_name == "org.freedesktop.DBus.Error.UnknownInterface"
      assert reply.signature == "s"
      assert [explanation] = reply.body
      assert is_binary(explanation) and byte_size(explanation) > 0
      assert reply.reply_serial == message.serial
      assert reply.destination == ":1.10"
      assert Map.delete(updated, :next_serial) == Map.delete(state, :next_serial)
    end
  end

  describe "unknown method" do
    test "returns UnknownMethod error", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("NonExistentMethod")
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      assert reply.type == :error
      assert reply.error_name == "org.freedesktop.DBus.Error.UnknownMethod"
    end
  end

  describe "non-method_call messages" do
    test "returns nil for signal messages", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = %Message{
        type: :signal,
        serial: 1,
        path: "/org/freedesktop/DBus",
        interface: "org.freedesktop.DBus",
        member: "NameOwnerChanged",
        sender: ":1.10"
      }

      assert {nil, ^state} = BusInterface.handle_message(msg, peer, state)
    end
  end

  describe "reply serial tracking" do
    test "state.next_serial increments across calls", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg1 = bus_method_call("GetId")
      {_, state} = BusInterface.handle_message(msg1, peer, state)
      assert state.next_serial > 1

      msg2 = bus_method_call("GetId")
      {_, state2} = BusInterface.handle_message(msg2, peer, state)
      assert state2.next_serial > state.next_serial
    end

    test "reply destination matches sender", %{state: state} do
      {peer, state} = start_fake_peer(state, unique_name: ":1.10")

      msg = bus_method_call("GetId")
      {reply, _state} = BusInterface.handle_message(msg, peer, state)

      # matches sender from bus_method_call
      assert reply.destination == ":1.10"
      assert reply.sender == "org.freedesktop.DBus"
    end
  end
end
