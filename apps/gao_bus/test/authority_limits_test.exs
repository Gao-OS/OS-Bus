defmodule GaoBus.AuthorityLimitsTest do
  use ExUnit.Case, async: false
  alias GaoBus.{MatchRules, NameRegistry}

  setup do
    Application.stop(:gao_bus)
    start_supervised!(GaoBus.Limits)
    :ok = GaoBus.Limits.acquire(self(), %{uid: 1000, gid: 1000, pid: 123})
    :ok = GaoBus.Limits.auth_completed(self())
    start_supervised!({NameRegistry, max_names_per_peer: 2, max_name_entries: 3})
    start_supervised!({MatchRules, max_matches_per_peer: 2, max_match_entries: 3})
    :ok
  end

  test "RES-01 name and queued-request budgets are checked before mutation" do
    assert {:ok, 1} = NameRegistry.request_name("org.limit.One", 0, self(), ":1.1")
    assert {:ok, 1} = NameRegistry.request_name("org.limit.Two", 0, self(), ":1.1")

    assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
             NameRegistry.request_name("org.limit.Three", 0, self(), ":1.1")

    assert {:error, :name_not_found} = NameRegistry.resolve("org.limit.Three")
    assert {:ok, 1} = NameRegistry.release_name("org.limit.One", self())
    assert {:ok, 1} = NameRegistry.request_name("org.limit.Three", 0, self(), ":1.1")
  end

  test "RES-01 global name budget includes queued requests" do
    other = start_supervised!({Agent, fn -> :peer end})
    :ok = GaoBus.Limits.acquire(other, %{uid: 1000, gid: 1000, pid: 123})
    :ok = GaoBus.Limits.auth_completed(other)
    assert {:ok, 1} = NameRegistry.request_name("org.limit.One", 0, self(), ":1.1")
    assert {:ok, 1} = NameRegistry.request_name("org.limit.Two", 0, self(), ":1.1")
    assert {:ok, 2} = NameRegistry.request_name("org.limit.One", 0, other, ":1.2")

    assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
             NameRegistry.request_name("org.limit.Four", 0, other, ":1.2")

    assert {:error, :name_not_found} = NameRegistry.resolve("org.limit.Four")
  end

  test "RES-01 match budgets bound peers and the complete table" do
    other = start_supervised!({Agent, fn -> :peer end})
    :ok = GaoBus.Limits.acquire(other, %{uid: 1000, gid: 1000, pid: 123})
    :ok = GaoBus.Limits.auth_completed(other)
    assert :ok = MatchRules.add_match(self(), "member='One'")
    assert :ok = MatchRules.add_match(self(), "member='Two'")
    assert {:error, :limits_exceeded} = MatchRules.add_match(self(), "member='Three'")
    assert :ok = MatchRules.add_match(other, "member='One'")
    assert {:error, :limits_exceeded} = MatchRules.add_match(other, "member='Two'")
    assert :ok = MatchRules.remove_match(self(), "member='One'")
    assert :ok = MatchRules.add_match(other, "member='Two'")
  end

  test "RES-01 oversized match grammar is rejected before storing" do
    assert {:error, :match_rule_too_long} =
             MatchRules.add_match(self(), "arg0='" <> :binary.copy("x", 1024) <> "'")

    refute MatchRules.has_rules?(self())
  end
end
