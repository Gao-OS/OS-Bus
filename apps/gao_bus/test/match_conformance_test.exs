defmodule GaoBus.MatchConformanceTest do
  use ExUnit.Case, async: false
  alias ExDBus.Message
  alias GaoBus.MatchRules

  setup do
    Application.stop(:gao_bus)
    start_supervised!(GaoBus.Limits)
    :ok = GaoBus.Limits.acquire(self(), %{uid: 1000, gid: 1000, pid: 123})
    :ok = GaoBus.Limits.auth_completed(self())
    start_supervised!({MatchRules, max_matches_per_peer: 2, max_match_entries: 3})
    :ok
  end

  test "quoted commas and outside-quote apostrophe escaping are parsed literally" do
    assert {:ok, rule} = MatchRules.parse(~S(arg0='a,b',arg1='a'\''b',arg2='\',arg3=\\))

    assert rule.args == %{
             {:arg, 0} => "a,b",
             {:arg, 1} => "a'b",
             {:arg, 2} => "\\",
             {:arg, 3} => "\\\\"
           }

    assert {:ok, ^rule} = MatchRules.parse(~S(arg3='\\',arg2=\,arg1=a\'b,arg0='a,b'))
  end

  test "invalid grammar or typed field values never install a partial rule" do
    for invalid <- [
          "member",
          "member='Foo",
          ",member=Foo",
          "member=Foo,,type=signal",
          "member=Foo,member=Bar",
          "path=/test,path_namespace=/",
          "eavesdrop=maybe",
          "interface=bad",
          "member=bad.member",
          "sender=bad",
          "path=relative",
          "arg64=x",
          "arg0namespace=org..bad",
          <<255>>
        ] do
      assert {:error, _} = MatchRules.add_match(self(), invalid)
      refute MatchRules.has_rules?(self())
    end
  end

  test "duplicate rules count separately and removal uses semantic equality once" do
    assert :ok = MatchRules.add_match(self(), "type='signal',member='Foo'")
    assert :ok = MatchRules.add_match(self(), "member=Foo,type=signal")
    assert {:error, :limits_exceeded} = MatchRules.add_match(self(), "member='Bar'")
    assert :ok = MatchRules.remove_match(self(), "member='Foo',type='signal',eavesdrop='false'")
    assert MatchRules.has_rules?(self())
    assert :ok = MatchRules.remove_match(self(), "type=signal,member=Foo")
    refute MatchRules.has_rules?(self())

    assert {:error, "org.freedesktop.DBus.Error.MatchRuleNotFound"} =
             MatchRules.remove_match(self(), "type=signal,member=Foo")
  end

  test "path namespace root matches all paths and arg path uses symmetric slash-terminated prefixes" do
    {:ok, root} = MatchRules.parse("path_namespace='/'")
    assert MatchRules.matches?(root, signal("s", ["/aa/bb"]))
    {:ok, rule} = MatchRules.parse("arg0path='/aa/bb/'")

    for path <- ["/", "/aa/", "/aa/bb/", "/aa/bb/cc/", "/aa/bb/cc"] do
      assert MatchRules.matches?(rule, signal("s", [path]))
    end

    for path <- ["/aa/b", "/aa", "/aa/bb"] do
      refute MatchRules.matches?(rule, signal("s", [path]))
    end

    assert MatchRules.matches?(rule, signal("o", ["/aa/bb/cc"]))
    refute MatchRules.matches?(rule, signal("g", ["/aa/bb/cc"]))
  end

  test "argument filters inspect wire types rather than only the Elixir value" do
    {:ok, rule} = MatchRules.parse("arg0='/test'")
    assert MatchRules.matches?(rule, signal("s", ["/test"]))
    refute MatchRules.matches?(rule, signal("o", ["/test"]))
    refute MatchRules.matches?(rule, signal("v", [{"s", "/test"}]))
    refute MatchRules.matches?(rule, signal(nil, ["/test"]))
    {:ok, namespace} = MatchRules.parse("arg0namespace='org.foundation'")

    for name <- ["org.foundation", "org.foundation.Service"],
        do: assert(MatchRules.matches?(namespace, signal("s", [name])))

    refute MatchRules.matches?(namespace, signal("s", ["org.foundationOther"]))
    refute MatchRules.matches?(namespace, signal("o", ["org.foundation.Service"]))
  end

  test "well-known sender follows supplied live ownership without resolving per rule" do
    :ok = MatchRules.add_match(self(), "sender='org.foundation.Service'")
    message = %{signal(nil, []) | sender: ":1.1"}
    assert MatchRules.matching_peers(message, [":1.1", "org.foundation.Service"]) == [self()]
    assert MatchRules.matching_peers(message, [":1.1", "org.foundation.Other"]) == []

    assert MatchRules.matching_peers(%{message | sender: ":1.2"}, [
             ":1.2",
             "org.foundation.Service"
           ]) == [self()]
  end

  test "ordinary subscriptions cannot eavesdrop on directed messages" do
    message = %{signal(nil, []) | destination: ":1.2"}
    {:ok, normal} = MatchRules.parse("type='signal'")
    {:ok, monitor} = MatchRules.parse("type='signal',eavesdrop='true'")
    refute MatchRules.matches?(normal, message)
    assert MatchRules.matches?(monitor, message)
  end

  defp signal(signature, body),
    do: Message.signal("/test", "org.foundation.Test", "Foo", signature: signature, body: body)
end
