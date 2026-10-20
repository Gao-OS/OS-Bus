defmodule GaoBus.MatchRulesTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.MatchRules

  describe "parse/1" do
    test "parses type filter — signal" do
      assert {:ok, rule} = MatchRules.parse("type='signal'")
      assert rule.type == :signal
    end

    test "parses type filter — method_call" do
      assert {:ok, rule} = MatchRules.parse("type='method_call'")
      assert rule.type == :method_call
    end

    test "parses type filter — method_return" do
      assert {:ok, rule} = MatchRules.parse("type='method_return'")
      assert rule.type == :method_return
    end

    test "parses type filter — error" do
      assert {:ok, rule} = MatchRules.parse("type='error'")
      assert rule.type == :error
    end

    test "parses sender filter" do
      assert {:ok, rule} = MatchRules.parse("sender='org.freedesktop.DBus'")
      assert rule.sender == "org.freedesktop.DBus"
    end

    test "parses interface filter" do
      assert {:ok, rule} = MatchRules.parse("interface='com.example.Test'")
      assert rule.interface == "com.example.Test"
    end

    test "parses member filter" do
      assert {:ok, rule} = MatchRules.parse("member='NameOwnerChanged'")
      assert rule.member == "NameOwnerChanged"
    end

    test "parses multiple filters" do
      assert {:ok, rule} =
               MatchRules.parse(
                 "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'"
               )

      assert rule.type == :signal
      assert rule.sender == "org.freedesktop.DBus"
      assert rule.interface == "org.freedesktop.DBus"
      assert rule.member == "NameOwnerChanged"
    end

    test "parses path filter" do
      assert {:ok, rule} = MatchRules.parse("path='/org/freedesktop/DBus'")
      assert rule.path == "/org/freedesktop/DBus"
    end

    test "parses path_namespace filter" do
      assert {:ok, rule} = MatchRules.parse("path_namespace='/org/freedesktop'")
      assert rule.path_namespace == "/org/freedesktop"
    end

    test "parses destination filter" do
      assert {:ok, rule} = MatchRules.parse("destination=':1.42'")
      assert rule.destination == ":1.42"
    end

    test "parses eavesdrop true" do
      assert {:ok, rule} = MatchRules.parse("eavesdrop='true'")
      assert rule.eavesdrop == true
    end

    test "parses eavesdrop false" do
      assert {:ok, rule} = MatchRules.parse("eavesdrop='false'")
      assert rule.eavesdrop == false
    end

    test "parses arg0 filter" do
      assert {:ok, rule} = MatchRules.parse("arg0='hello'")
      assert rule.args == %{{:arg, 0} => "hello"}
    end

    test "parses arg0path filter" do
      assert {:ok, rule} = MatchRules.parse("arg0path='/com/example'")
      assert rule.args == %{{:arg_path, 0} => "/com/example"}
    end

    test "parses multiple arg filters" do
      assert {:ok, rule} = MatchRules.parse("arg0='hello',arg2path='/com'")
      assert rule.args == %{{:arg, 0} => "hello", {:arg_path, 2} => "/com"}
    end

    test "parses high-numbered arg (arg63)" do
      assert {:ok, rule} = MatchRules.parse("arg63='test'")
      assert rule.args == %{{:arg, 63} => "test"}
    end

    test "parses empty string to empty rule" do
      assert {:ok, rule} = MatchRules.parse("")
      assert rule.type == nil
      assert rule.sender == nil
      assert rule.interface == nil
      assert rule.member == nil
      assert rule.path == nil
      assert rule.path_namespace == nil
      assert rule.destination == nil
      assert rule.eavesdrop == nil
      assert rule.args == %{}
    end

    test "rejects invalid type" do
      assert {:error, {:invalid_type, "bogus"}} = MatchRules.parse("type='bogus'")
    end

    test "rejects unknown key" do
      assert {:error, {:unknown_key, "foo"}} = MatchRules.parse("foo='bar'")
    end

    test "rejects invalid arg number" do
      assert {:error, {:invalid_arg, "arg-1"}} = MatchRules.parse("arg-1='test'")
    end
  end

  describe "matches?/2" do
    test "empty rule matches everything" do
      {:ok, rule} = MatchRules.parse("")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matches?(rule, signal)
    end

    test "empty rule matches method_call" do
      {:ok, rule} = MatchRules.parse("")
      msg = Message.method_call("/test", "com.example.Test", "Foo")
      assert MatchRules.matches?(rule, msg)
    end

    test "type filter matches signal" do
      {:ok, rule} = MatchRules.parse("type='signal'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matches?(rule, signal)
    end

    test "type filter rejects non-matching type" do
      {:ok, rule} = MatchRules.parse("type='method_call'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      refute MatchRules.matches?(rule, signal)
    end

    test "type filter matches method_return" do
      {:ok, rule} = MatchRules.parse("type='method_return'")
      msg = Message.method_return(1)
      assert MatchRules.matches?(rule, msg)
    end

    test "type filter matches error" do
      {:ok, rule} = MatchRules.parse("type='error'")
      msg = Message.error("org.freedesktop.DBus.Error.Failed", 1)
      assert MatchRules.matches?(rule, msg)
    end

    test "sender filter matches" do
      {:ok, rule} = MatchRules.parse("sender=':1.1'")
      signal = %{Message.signal("/test", "com.example.Test", "Foo") | sender: ":1.1"}
      assert MatchRules.matches?(rule, signal)
    end

    test "sender filter rejects non-matching" do
      {:ok, rule} = MatchRules.parse("sender=':1.1'")
      signal = %{Message.signal("/test", "com.example.Test", "Foo") | sender: ":1.2"}
      refute MatchRules.matches?(rule, signal)
    end

    test "sender filter rejects nil sender" do
      {:ok, rule} = MatchRules.parse("sender=':1.1'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      refute MatchRules.matches?(rule, signal)
    end

    test "interface filter matches" do
      {:ok, rule} = MatchRules.parse("interface='com.example.Test'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matches?(rule, signal)
    end

    test "interface filter rejects non-matching" do
      {:ok, rule} = MatchRules.parse("interface='com.example.Other'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      refute MatchRules.matches?(rule, signal)
    end

    test "member filter matches" do
      {:ok, rule} = MatchRules.parse("member='Foo'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matches?(rule, signal)
    end

    test "member filter rejects non-matching" do
      {:ok, rule} = MatchRules.parse("member='Bar'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      refute MatchRules.matches?(rule, signal)
    end

    test "path filter matches exact path" do
      {:ok, rule} = MatchRules.parse("path='/org/freedesktop/DBus'")
      signal = Message.signal("/org/freedesktop/DBus", "org.freedesktop.DBus", "NameOwnerChanged")
      assert MatchRules.matches?(rule, signal)
    end

    test "path filter rejects non-matching path" do
      {:ok, rule} = MatchRules.parse("path='/org/freedesktop/DBus'")
      signal = Message.signal("/other/path", "org.freedesktop.DBus", "NameOwnerChanged")
      refute MatchRules.matches?(rule, signal)
    end

    test "path filter does not match children (not a prefix match)" do
      {:ok, rule} = MatchRules.parse("path='/org/freedesktop'")
      signal = Message.signal("/org/freedesktop/DBus", "org.freedesktop.DBus", "Sig")
      refute MatchRules.matches?(rule, signal)
    end

    test "path_namespace matches exact namespace" do
      {:ok, rule} = MatchRules.parse("path_namespace='/org/freedesktop'")
      signal = Message.signal("/org/freedesktop", "org.freedesktop.DBus", "Sig")
      assert MatchRules.matches?(rule, signal)
    end

    test "path_namespace matches child path" do
      {:ok, rule} = MatchRules.parse("path_namespace='/org/freedesktop'")
      signal = Message.signal("/org/freedesktop/DBus", "org.freedesktop.DBus", "Sig")
      assert MatchRules.matches?(rule, signal)
    end

    test "path_namespace matches deeply nested child" do
      {:ok, rule} = MatchRules.parse("path_namespace='/org/freedesktop'")
      signal = Message.signal("/org/freedesktop/DBus/Deep/Path", "org.freedesktop.DBus", "Sig")
      assert MatchRules.matches?(rule, signal)
    end

    test "path_namespace rejects non-matching prefix" do
      {:ok, rule} = MatchRules.parse("path_namespace='/org/freedesktop'")
      signal = Message.signal("/org/other", "org.freedesktop.DBus", "Sig")
      refute MatchRules.matches?(rule, signal)
    end

    test "path_namespace rejects nil path" do
      {:ok, rule} = MatchRules.parse("path_namespace='/org/freedesktop'")
      signal = %{Message.signal("/test", "org.freedesktop.DBus", "Sig") | path: nil}
      refute MatchRules.matches?(rule, signal)
    end

    test "destination filter matches" do
      {:ok, rule} = MatchRules.parse("destination=':1.5',eavesdrop='true'")
      signal = %{Message.signal("/test", "com.example.Test", "Foo") | destination: ":1.5"}
      assert MatchRules.matches?(rule, signal)
    end

    test "destination filter rejects non-matching" do
      {:ok, rule} = MatchRules.parse("destination=':1.5',eavesdrop='true'")
      signal = %{Message.signal("/test", "com.example.Test", "Foo") | destination: ":1.6"}
      refute MatchRules.matches?(rule, signal)
    end

    test "arg0 filter matches first body element" do
      {:ok, rule} = MatchRules.parse("arg0='hello'")
      signal = Message.signal("/test", "com.example.Test", "Foo", signature: "s", body: ["hello"])
      assert MatchRules.matches?(rule, signal)
    end

    test "arg0 filter rejects non-matching first body element" do
      {:ok, rule} = MatchRules.parse("arg0='hello'")

      signal =
        Message.signal("/test", "com.example.Test", "Foo", signature: "s", body: ["goodbye"])

      refute MatchRules.matches?(rule, signal)
    end

    test "arg0 filter rejects empty body" do
      {:ok, rule} = MatchRules.parse("arg0='hello'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      refute MatchRules.matches?(rule, signal)
    end

    test "arg0 filter rejects nil body" do
      {:ok, rule} = MatchRules.parse("arg0='hello'")
      signal = %{Message.signal("/test", "com.example.Test", "Foo") | body: nil}
      refute MatchRules.matches?(rule, signal)
    end

    test "arg1 filter matches second body element" do
      {:ok, rule} = MatchRules.parse("arg1='world'")

      signal =
        Message.signal("/test", "com.example.Test", "Foo",
          signature: "ss",
          body: ["hello", "world"]
        )

      assert MatchRules.matches?(rule, signal)
    end

    test "arg0path matches exact path" do
      {:ok, rule} = MatchRules.parse("arg0path='/com/example'")

      signal =
        Message.signal("/test", "com.example.Test", "Foo", signature: "s", body: ["/com/example"])

      assert MatchRules.matches?(rule, signal)
    end

    test "arg0path with trailing slash matches child path" do
      {:ok, rule} = MatchRules.parse("arg0path='/com/example/'")

      signal =
        Message.signal("/test", "com.example.Test", "Foo",
          signature: "s",
          body: ["/com/example/Sub"]
        )

      assert MatchRules.matches?(rule, signal)
    end

    test "arg0path rejects non-matching path" do
      {:ok, rule} = MatchRules.parse("arg0path='/com/example'")

      signal =
        Message.signal("/test", "com.example.Test", "Foo", signature: "s", body: ["/com/other"])

      refute MatchRules.matches?(rule, signal)
    end

    test "arg0path rejects nil body element" do
      {:ok, rule} = MatchRules.parse("arg0path='/com/example'")
      signal = Message.signal("/test", "com.example.Test", "Foo")
      refute MatchRules.matches?(rule, signal)
    end

    test "compound rule matches all fields" do
      {:ok, rule} =
        MatchRules.parse(
          "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'"
        )

      signal = %Message{
        type: :signal,
        serial: 1,
        path: "/org/freedesktop/DBus",
        interface: "org.freedesktop.DBus",
        member: "NameOwnerChanged",
        sender: "org.freedesktop.DBus",
        signature: "sss",
        body: ["com.example.Test", "", ":1.1"]
      }

      assert MatchRules.matches?(rule, signal)
    end

    test "compound rule rejects when one field does not match" do
      {:ok, rule} =
        MatchRules.parse("type='signal',sender='org.freedesktop.DBus',member='NameOwnerChanged'")

      signal = %Message{
        type: :signal,
        serial: 1,
        path: "/org/freedesktop/DBus",
        interface: "org.freedesktop.DBus",
        member: "SomethingElse",
        sender: "org.freedesktop.DBus"
      }

      refute MatchRules.matches?(rule, signal)
    end

    test "multiple arg filters must all match" do
      {:ok, rule} = MatchRules.parse("arg0='hello',arg1='world'")

      signal_match =
        Message.signal("/test", "com.example.Test", "Foo",
          signature: "ss",
          body: ["hello", "world"]
        )

      assert MatchRules.matches?(rule, signal_match)

      signal_partial =
        Message.signal("/test", "com.example.Test", "Foo",
          signature: "ss",
          body: ["hello", "nope"]
        )

      refute MatchRules.matches?(rule, signal_partial)
    end
  end

  describe "GenServer operations" do
    setup do
      Application.stop(:gao_bus)
      start_supervised!(GaoBus.Limits)
      start_supervised!(GaoBus.MatchRules)
      :ok
    end

    test "add_match/2 succeeds for valid rule" do
      peer = spawn_peer()
      assert :ok = MatchRules.add_match(peer, "type='signal'")
    end

    test "add_match/2 returns error for invalid rule" do
      peer = spawn_peer()
      assert {:error, {:invalid_type, "bogus"}} = MatchRules.add_match(peer, "type='bogus'")
    end

    test "add_match/2 returns error for unknown key" do
      peer = spawn_peer()
      assert {:error, {:unknown_key, "nonsense"}} = MatchRules.add_match(peer, "nonsense='val'")
    end

    test "remove_match/2 succeeds after add" do
      peer = spawn_peer()
      rule = "type='signal',interface='org.freedesktop.DBus'"

      :ok = MatchRules.add_match(peer, rule)
      assert :ok = MatchRules.remove_match(peer, rule)
    end

    test "remove_match/2 returns error for non-existent rule" do
      peer = spawn_peer()

      assert {:error, "org.freedesktop.DBus.Error.MatchRuleNotFound"} =
               MatchRules.remove_match(peer, "type='signal',member='NeverAdded'")
    end

    test "remove_match/2 removes duplicate rules added with same string" do
      peer = spawn_peer()
      rule = "type='signal',member='Foo'"

      :ok = MatchRules.add_match(peer, rule)
      :ok = MatchRules.add_match(peer, rule)

      # Each successful AddMatch requires its own RemoveMatch.
      assert :ok = MatchRules.remove_match(peer, rule)

      assert :ok = MatchRules.remove_match(peer, rule)

      assert {:error, "org.freedesktop.DBus.Error.MatchRuleNotFound"} =
               MatchRules.remove_match(peer, rule)
    end

    test "remove_match/2 of one rule does not affect different rules" do
      peer = spawn_peer()
      rule_a = "type='signal',member='Foo'"
      rule_b = "type='signal',member='Bar'"

      :ok = MatchRules.add_match(peer, rule_a)
      :ok = MatchRules.add_match(peer, rule_b)

      # Remove rule_a
      assert :ok = MatchRules.remove_match(peer, rule_a)

      # rule_b still exists
      signal_b = Message.signal("/test", "com.example.Test", "Bar")
      assert peer in MatchRules.matching_peers(signal_b)

      # rule_a is gone
      signal_a = Message.signal("/test", "com.example.Test", "Foo")
      refute peer in MatchRules.matching_peers(signal_a)
    end

    test "matching_peers/1 returns peers with matching rules" do
      peer1 = spawn_peer()
      peer2 = spawn_peer()

      :ok = MatchRules.add_match(peer1, "type='signal',interface='com.example.Test'")
      :ok = MatchRules.add_match(peer2, "type='signal',member='Foo'")

      signal = Message.signal("/test", "com.example.Test", "Foo")
      peers = MatchRules.matching_peers(signal)

      assert peer1 in peers
      assert peer2 in peers
    end

    test "matching_peers/1 excludes peers with non-matching rules" do
      peer1 = spawn_peer()
      peer2 = spawn_peer()

      :ok = MatchRules.add_match(peer1, "type='signal',interface='com.example.Test'")
      :ok = MatchRules.add_match(peer2, "type='signal',interface='com.other.Service'")

      signal = Message.signal("/test", "com.example.Test", "Foo")
      peers = MatchRules.matching_peers(signal)

      assert peer1 in peers
      refute peer2 in peers
    end

    test "matching_peers/1 returns empty list when no rules match" do
      peer = spawn_peer()
      :ok = MatchRules.add_match(peer, "type='method_call'")

      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matching_peers(signal) == []
    end

    test "matching_peers/1 returns unique peer even with multiple matching rules" do
      peer = spawn_peer()

      :ok = MatchRules.add_match(peer, "type='signal'")
      :ok = MatchRules.add_match(peer, "interface='com.example.Test'")

      signal = Message.signal("/test", "com.example.Test", "Foo")
      peers = MatchRules.matching_peers(signal)

      # Peer appears only once despite two matching rules
      assert peers == [peer]
    end

    test "matching_peers/1 returns empty list when ETS table has no entries" do
      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matching_peers(signal) == []
    end

    test "peer_disconnected/1 removes all rules for that peer" do
      peer = spawn_peer()

      :ok = MatchRules.add_match(peer, "type='signal',interface='com.example.A'")
      :ok = MatchRules.add_match(peer, "type='signal',interface='com.example.B'")

      # Verify peer has matching rules
      signal_a = Message.signal("/test", "com.example.A", "Foo")
      assert peer in MatchRules.matching_peers(signal_a)

      # Disconnect peer
      MatchRules.peer_disconnected(peer)
      _ = :sys.get_state(MatchRules)

      # Peer should no longer match
      refute peer in MatchRules.matching_peers(signal_a)

      signal_b = Message.signal("/test", "com.example.B", "Bar")
      refute peer in MatchRules.matching_peers(signal_b)
    end

    test "peer_disconnected/1 does not affect other peers" do
      peer1 = spawn_peer()
      peer2 = spawn_peer()

      :ok = MatchRules.add_match(peer1, "type='signal',interface='com.example.Test'")
      :ok = MatchRules.add_match(peer2, "type='signal',interface='com.example.Test'")

      MatchRules.peer_disconnected(peer1)
      _ = :sys.get_state(MatchRules)

      signal = Message.signal("/test", "com.example.Test", "Foo")
      peers = MatchRules.matching_peers(signal)

      refute peer1 in peers
      assert peer2 in peers
    end

    test "peer_disconnected/1 is safe for peer with no rules" do
      peer = spawn_peer()
      MatchRules.peer_disconnected(peer)
      _ = :sys.get_state(MatchRules)
      # No crash, no error
    end

    test "add_match then remove_match then matching_peers returns empty" do
      peer = spawn_peer()
      rule = "type='signal',interface='com.example.Test'"

      :ok = MatchRules.add_match(peer, rule)
      :ok = MatchRules.remove_match(peer, rule)

      signal = Message.signal("/test", "com.example.Test", "Foo")
      assert MatchRules.matching_peers(signal) == []
    end
  end

  # --- Helpers ---

  defp spawn_peer do
    peer = start_supervised!(%{id: make_ref(), start: {Agent, :start_link, [fn -> :peer end]}})
    :ok = GaoBus.Limits.acquire(peer, %{uid: 1000, gid: 1000, pid: 123})
    :ok = GaoBus.Limits.auth_completed(peer)
    peer
  end
end
