defmodule GaoBus.UIDAuthorityLimitsTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{Limits, MatchRules, NameRegistry, Policy, Router}

  @uid_a 1000
  @uid_b 2000
  @not_found "org.freedesktop.DBus.Error.MatchRuleNotFound"

  setup do
    Application.stop(:gao_bus)
    limits = start_supervised!(Limits)

    start_supervised!(
      {MatchRules, max_matches_per_peer: 8, max_match_entries: 32, max_matches_per_uid: 2}
    )

    # Explicit unit admissions model the accepted identity store. Real kernel
    # credentials and cross-UID socket peers require separate VM qualification.
    %{limits: limits, first: admitted(@uid_a), second: admitted(@uid_a), other: admitted(@uid_b)}
  end

  @tag :uid_identity
  test "UID-I01 accepted UID and admission stay immutable across rejected reacquisition", ctx do
    assert {:ok, %{uid: @uid_a, admission: admission} = identity} =
             peer_identity(ctx.first, ctx.limits)

    assert is_reference(admission)
    assert {:error, :already_acquired} = Limits.acquire(ctx.first, credentials(@uid_b))
    assert {:ok, ^identity} = peer_identity(ctx.first, ctx.limits)

    assert {:ok, %{uid: @uid_a, admission: second_admission}} =
             peer_identity(ctx.second, ctx.limits)

    assert is_reference(second_admission)
    refute second_admission == admission
  end

  @tag :uid_identity
  test "UID-I02 absent and retired admissions provide no identity", ctx do
    unadmitted = peer()
    assert {:error, :unknown_peer} = peer_identity(unadmitted, ctx.limits)
    assert {:ok, token} = Limits.reserve_ingress(ctx.first, 1)
    assert :ok = Limits.release_peer(ctx.first)
    assert {:error, :unknown_peer} = peer_identity(ctx.first, ctx.limits)
    assert :ok = Limits.release(token)
    assert {:error, :unknown_peer} = peer_identity(ctx.first, ctx.limits)
  end

  @tag :uid_identity
  test "UID-I03 dead peers and unavailable accounting provide no identity", ctx do
    monitor = Process.monitor(ctx.first)
    Process.exit(ctx.first, :kill)
    assert_receive {:DOWN, ^monitor, :process, peer, :killed} when peer == ctx.first, 1000
    assert {:error, :unknown_peer} = peer_identity(ctx.first, ctx.limits)

    # A stopped real GenServer gives an immediate finite unavailable result.
    # A live Task that never handles GenServer calls would only test a timeout.
    assert :ok = stop_supervised(Limits)
    assert {:error, :accounting_unavailable} = peer_identity(ctx.second, ctx.limits)
  end

  @tag :uid_identity
  test "UID-I04 a fresh admission has a fresh identity after complete retirement", ctx do
    assert {:ok, %{uid: @uid_a, admission: previous}} = peer_identity(ctx.first, ctx.limits)
    assert :ok = Limits.release_peer(ctx.first)
    assert :ok = Limits.acquire(ctx.first, credentials(@uid_b))
    assert :ok = Limits.auth_completed(ctx.first)
    assert {:ok, %{uid: @uid_b, admission: current}} = peer_identity(ctx.first, ctx.limits)
    assert is_reference(current)
    refute current == previous
  end

  @tag :uid_matches
  test "UID-M01 shared UID N and N+1 leave denied subscriptions absent and another UID healthy",
       ctx do
    assert :ok = MatchRules.add_match(ctx.first, rule("First"))
    assert :ok = MatchRules.add_match(ctx.second, rule("Second"))
    assert recipients("First") == [ctx.first]
    assert recipients("Second") == [ctx.second]

    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.first, rule("Denied"))
    assert recipients("Denied") == []
    assert :ok = MatchRules.add_match(ctx.other, rule("Healthy"))
    assert recipients("Healthy") == [ctx.other]
    assert recipients("First") == [ctx.first]
    assert recipients("Second") == [ctx.second]
  end

  @tag :uid_matches
  test "UID-M02 canonical duplicates consume separate slots and removal restores exactly one",
       ctx do
    canonical = "type='signal',member='Duplicate'"
    equivalent = "member=Duplicate,type=signal"
    assert :ok = MatchRules.add_match(ctx.first, canonical)
    assert :ok = MatchRules.add_match(ctx.first, equivalent)
    assert recipients("Duplicate") == [ctx.first]

    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.second, rule("Replacement"))
    assert :ok = MatchRules.remove_match(ctx.first, equivalent)
    assert recipients("Duplicate") == [ctx.first]
    assert :ok = MatchRules.add_match(ctx.second, rule("Replacement"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.second, rule("Extra"))

    assert :ok = MatchRules.remove_match(ctx.first, canonical)
    assert recipients("Duplicate") == []
    assert {:error, @not_found} = MatchRules.remove_match(ctx.first, canonical)
    assert :ok = MatchRules.add_match(ctx.second, rule("Extra"))
    assert recipients("Replacement") == [ctx.second]
    assert recipients("Extra") == [ctx.second]
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.first, rule("StillFull"))
  end

  @tag :uid_matches
  test "UID-M03 malformed additions and missing removals neither spend nor return UID credit",
       ctx do
    assert {:error, {:invalid_type, "bogus"}} =
             MatchRules.add_match(ctx.first, "type='bogus'")

    refute MatchRules.has_rules?(ctx.first)
    assert {:error, @not_found} = MatchRules.remove_match(ctx.first, rule("Missing"))
    assert :ok = MatchRules.add_match(ctx.first, rule("First"))
    assert :ok = MatchRules.add_match(ctx.second, rule("Second"))

    # Preserve native grammar-error precedence even with the UID budget full.
    assert {:error, {:invalid_type, "bogus"}} =
             MatchRules.add_match(ctx.second, "type='bogus'")

    assert {:error, {:invalid_type, "bogus"}} =
             MatchRules.remove_match(ctx.first, "type='bogus'")

    assert {:error, @not_found} = MatchRules.remove_match(ctx.first, rule("Missing"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.second, rule("Denied"))
    assert recipients("Denied") == []
    assert :ok = MatchRules.remove_match(ctx.first, rule("First"))
    assert :ok = MatchRules.add_match(ctx.second, rule("Reused"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.first, rule("Extra"))
    assert recipients("Second") == [ctx.second]
    assert recipients("Reused") == [ctx.second]
  end

  @tag :uid_matches
  test "UID-M04 concurrent contenders cannot both acquire the last shared UID slot", ctx do
    assert :ok = MatchRules.add_match(ctx.first, rule("Occupied"))
    tasks = start_supervised!(Task.Supervisor)
    parent = self()

    actors =
      for {peer, member} <- [{ctx.first, "ContenderA"}, {ctx.second, "ContenderB"}] do
        Task.Supervisor.async_nolink(tasks, fn ->
          send(parent, {:ready, self()})

          receive do
            :go -> {peer, member, MatchRules.add_match(peer, rule(member))}
          after
            1000 -> flunk("last-slot contender did not receive the barrier release")
          end
        end)
      end

    for task <- actors do
      pid = task.pid
      assert_receive {:ready, ^pid}, 1000
    end

    for task <- actors, do: send(task.pid, :go)
    results = Enum.map(actors, &Task.await(&1, 1000))
    assert Enum.count(results, fn {_, _, result} -> result == :ok end) == 1

    assert Enum.count(results, fn {_, _, result} -> result == {:error, :limits_exceeded} end) ==
             1

    for {peer, member, result} <- results do
      assert recipients(member) == if(result == :ok, do: [peer], else: [])
    end

    assert recipients("Occupied") == [ctx.first]
    assert :ok = MatchRules.add_match(ctx.other, rule("Healthy"))
    assert recipients("Healthy") == [ctx.other]
  end

  @tag :uid_matches
  test "UID-M05 killed peer cleans up without Router and duplicate cleanup frees no extra credit",
       ctx do
    assert Process.whereis(Router) == nil
    assert :ok = MatchRules.add_match(ctx.first, rule("Killed"))
    assert :ok = MatchRules.add_match(ctx.second, rule("Survivor"))
    monitor = Process.monitor(ctx.first)
    Process.exit(ctx.first, :kill)
    assert_receive {:DOWN, ^monitor, :process, peer, :killed} when peer == ctx.first, 1000
    await_no_rules(ctx.first, System.monotonic_time(:millisecond) + 1000)
    assert recipients("Killed") == []

    replacement = admitted(@uid_a)
    assert :ok = MatchRules.add_match(replacement, rule("Replacement"))

    for _ <- 1..2 do
      MatchRules.peer_disconnected(ctx.first)
      _ = :sys.get_state(MatchRules)
    end

    assert recipients("Survivor") == [ctx.second]
    assert recipients("Replacement") == [replacement]
    assert {:error, :limits_exceeded} = MatchRules.add_match(replacement, rule("Extra"))
    assert :ok = MatchRules.remove_match(ctx.second, rule("Survivor"))
    assert :ok = MatchRules.add_match(replacement, rule("Extra"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.second, rule("StillFull"))
  end

  @tag :uid_matches
  test "UID-M06 unadmitted peer cannot allocate a valid subscription", ctx do
    unadmitted = peer()
    assert {:error, :identity_unavailable} = MatchRules.add_match(unadmitted, rule("Unadmitted"))
    refute MatchRules.has_rules?(unadmitted)
    assert recipients("Unadmitted") == []
    assert :ok = MatchRules.add_match(ctx.first, rule("First"))
    assert :ok = MatchRules.add_match(ctx.second, rule("Second"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.first, rule("Extra"))
  end

  @tag :uid_matches
  test "UID-M07 unavailable accounting denies allocation while cached entries remain removable",
       ctx do
    assert :ok = MatchRules.add_match(ctx.first, rule("Retained"))
    assert :ok = stop_supervised(Limits)
    assert {:error, :identity_unavailable} = MatchRules.add_match(ctx.second, rule("Unavailable"))
    assert recipients("Unavailable") == []
    assert recipients("Retained") == [ctx.first]
    assert :ok = MatchRules.remove_match(ctx.first, rule("Retained"))
    refute MatchRules.has_rules?(ctx.first)
  end

  @tag :uid_matches
  test "UID-M08 live PID reacquisition cannot rebind retained matches to a new admission", ctx do
    assert :ok = MatchRules.add_match(ctx.first, rule("Pinned"))
    assert :ok = Limits.release_peer(ctx.first)
    assert :ok = Limits.acquire(ctx.first, credentials(@uid_b))
    assert :ok = Limits.auth_completed(ctx.first)

    assert {:error, :identity_unavailable} = MatchRules.add_match(ctx.first, rule("Rebound"))
    assert recipients("Rebound") == []
    assert recipients("Pinned") == [ctx.first]
    assert :ok = MatchRules.add_match(ctx.second, rule("OldUIDRemaining"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.second, rule("OldUIDFull"))
    assert :ok = MatchRules.add_match(ctx.other, rule("OtherUID"))
    assert :ok = MatchRules.add_match(ctx.other, rule("OtherUIDSecond"))

    assert :ok = MatchRules.remove_match(ctx.first, rule("Pinned"))
    assert :ok = MatchRules.remove_match(ctx.other, rule("OtherUIDSecond"))
    assert :ok = MatchRules.add_match(ctx.first, rule("FreshAfterRemoval"))
    assert recipients("FreshAfterRemoval") == [ctx.first]
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.first, rule("NewUIDFull"))
  end

  @tag :uid_matches
  test "UID-M09 Router credential overwrite cannot change the accepted quota UID", ctx do
    start_supervised!(NameRegistry)
    start_supervised!({Policy, rules: Policy.session_rules()})
    start_supervised!(Router)
    unique = ":1.101"
    Router.register_peer(ctx.first, unique, Map.put(credentials(@uid_a), :unique_name, unique))
    _ = :sys.get_state(Router)
    Router.register_peer(ctx.first, unique, Map.put(credentials(@uid_b), :unique_name, unique))
    state = :sys.get_state(Router)
    assert state.peers[ctx.first].credentials.uid == @uid_b

    assert :ok = MatchRules.add_match(ctx.first, rule("PinnedUID"))
    assert :ok = MatchRules.add_match(ctx.second, rule("SameUID"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.first, rule("SpoofedUID"))
    assert recipients("SpoofedUID") == []
    assert :ok = MatchRules.add_match(ctx.other, rule("ActualOtherUID"))
    assert recipients("ActualOtherUID") == [ctx.other]
    assert recipients("PinnedUID") == [ctx.first]
  end

  @tag :uid_matches
  test "UID-M10 retired ingress tombstone cannot authorize a new match", ctx do
    assert :ok = MatchRules.add_match(ctx.first, rule("Retained"))
    assert {:ok, token} = Limits.reserve_ingress(ctx.first, 1)
    assert :ok = Limits.release_peer(ctx.first)

    assert {:error, :identity_unavailable} = MatchRules.add_match(ctx.first, rule("Retired"))
    assert recipients("Retired") == []
    assert recipients("Retained") == [ctx.first]
    assert :ok = MatchRules.remove_match(ctx.first, rule("Retained"))
    assert :ok = Limits.release(token)
    assert {:error, :identity_unavailable} = MatchRules.add_match(ctx.first, rule("Absent"))
    assert recipients("Absent") == []
    assert :ok = MatchRules.add_match(ctx.second, rule("Reclaimed"))
    assert :ok = MatchRules.add_match(ctx.second, rule("ReclaimedSecond"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(ctx.second, rule("Extra"))
  end

  defp peer do
    start_supervised!(
      {Task,
       fn ->
         receive do
           :stop -> :ok
         end
       end},
      id: make_ref()
    )
  end

  defp admitted(uid) do
    peer = peer()
    assert :ok = Limits.acquire(peer, credentials(uid))
    assert :ok = Limits.auth_completed(peer)
    peer
  end

  defp credentials(uid), do: %{uid: uid, gid: 1000, pid: 123}

  # Dynamic dispatch keeps the missing API's RED confined to identity cases;
  # aggregate match tests use only today's admission API in their setup.
  defp peer_identity(peer, limits), do: apply(Limits, :peer_identity, [peer, limits])

  defp rule(member), do: "type='signal',member='#{member}'"

  defp recipients(member),
    do: MatchRules.matching_peers(Message.signal("/uid_test", "org.foundation.UID", member))

  defp await_no_rules(peer, deadline) do
    _ = :sys.get_state(MatchRules)

    if MatchRules.has_rules?(peer) do
      assert System.monotonic_time(:millisecond) < deadline,
             "killed peer retained match rules without Router cleanup"

      await_no_rules(peer, deadline)
    else
      :ok
    end
  end

  describe "aggregate UID names" do
    setup ctx do
      start_supervised!(
        {NameRegistry, max_names_per_peer: 8, max_name_entries: 32, max_names_per_uid: 2}
      )

      actors =
        if ctx[:name_signals] do
          {name_signal_actor(@uid_a), name_signal_actor(@uid_a), name_signal_actor(@uid_b)}
        else
          {ctx.first, ctx.second, ctx.other}
        end

      {owner, waiter, independent} = actors

      names = %{
        name_owner: {owner, ":1.201"},
        name_waiter: {waiter, ":1.202"},
        name_independent: {independent, ":1.203"}
      }

      for {peer, unique} <- Map.values(names) do
        assert :ok = NameRegistry.register_unique(unique, peer)
      end

      if ctx[:name_signals] do
        start_supervised!({Policy, rules: Policy.session_rules()})
        start_supervised!(Router)

        for {{peer, unique}, uid} <- [
              {names.name_owner, @uid_a},
              {names.name_waiter, @uid_a},
              {names.name_independent, @uid_b}
            ] do
          Router.register_peer(peer, unique, Map.put(credentials(uid), :unique_name, unique))
        end

        _ = :sys.get_state(Router)

        assert :ok =
                 MatchRules.add_match(independent, "type='signal',member='NameOwnerChanged'")
      end

      names
    end

    @tag :uid_names
    test "UID-N01 owner plus queue share N slots and another UID remains independent", ctx do
      name = "org.foundation.UIDNames.Shared"
      extra = "org.foundation.UIDNames.Denied"
      assert {:ok, 1} = request_uid_name(name, 0, ctx.name_owner)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)

      assert {:ok, 1} =
               request_uid_name("org.foundation.UIDNames.Healthy", 0, ctx.name_independent)

      before = name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent])

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name(extra, 0, ctx.name_waiter)

      assert {:error, :name_not_found} = NameRegistry.resolve(extra)
      refute extra in NameRegistry.list_names()

      assert name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent]) ==
               before

      assert NameRegistry.get_name_owner("org.foundation.UIDNames.Healthy") ==
               {:ok, elem(ctx.name_independent, 1)}
    end

    @tag :uid_names
    test "UID-N02 new queued association cannot bypass a full shared UID", ctx do
      name = "org.foundation.UIDNames.QueueDenied"
      assert {:ok, 1} = request_uid_name(name, 0, ctx.name_independent)
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.First", 0, ctx.name_owner)
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Second", 0, ctx.name_waiter)
      before = name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent])

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name(name, 0, ctx.name_owner)

      assert name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent]) ==
               before

      assert NameRegistry.list_queued_owners(name) == {:ok, [elem(ctx.name_independent, 1)]}
      refute name in name_policy_names(ctx.name_owner)
    end

    @tag :uid_names
    test "UID-N03 owner and queued repeats preserve slots and queue position", ctx do
      name = "org.foundation.UIDNames.Repeated"
      assert {:ok, 1} = request_uid_name(name, 0, ctx.name_owner)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_independent)
      assert {:ok, 4} = request_uid_name(name, 1, ctx.name_owner)
      before = name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent])
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)

      assert name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent]) ==
               before

      # A queued DO_NOT_QUEUE request removes its association without ownership effects.
      assert {:ok, 3} = request_uid_name(name, 4, ctx.name_waiter)

      assert NameRegistry.list_queued_owners(name) ==
               {:ok, [elem(ctx.name_owner, 1), elem(ctx.name_independent, 1)]}

      refute name in name_policy_names(ctx.name_waiter)
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Reused", 0, ctx.name_waiter)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Extra", 0, ctx.name_owner)
    end

    @tag :uid_names
    test "UID-N04 release promotes an already charged queue entry without a new charge", ctx do
      name = "org.foundation.UIDNames.Promoted"
      assert {:ok, 1} = request_uid_name(name, 0, ctx.name_owner)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)
      assert {:ok, 1} = NameRegistry.release_name(name, elem(ctx.name_owner, 0))
      assert NameRegistry.get_name_owner(name) == {:ok, elem(ctx.name_waiter, 1)}
      assert NameRegistry.list_queued_owners(name) == {:ok, [elem(ctx.name_waiter, 1)]}
      refute name in name_policy_names(ctx.name_owner)

      assert {:ok, 1} =
               request_uid_name("org.foundation.UIDNames.AfterPromotion", 0, ctx.name_owner)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Extra", 0, ctx.name_waiter)
    end

    @tag :uid_names
    test "UID-N05 same UID replacement dropping old owner is net zero at the ceiling", ctx do
      name = "org.foundation.UIDNames.Transfer"
      assert {:ok, 1} = request_uid_name(name, 5, ctx.name_owner)
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Second", 0, ctx.name_waiter)
      assert {:ok, 1} = request_uid_name(name, 2, ctx.name_waiter)
      assert NameRegistry.get_name_owner(name) == {:ok, elem(ctx.name_waiter, 1)}
      assert NameRegistry.list_queued_owners(name) == {:ok, [elem(ctx.name_waiter, 1)]}
      refute name in name_policy_names(ctx.name_owner)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Third", 0, ctx.name_owner)

      assert {:ok, 1} = NameRegistry.release_name(name, elem(ctx.name_waiter, 0))
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Third", 0, ctx.name_owner)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Fourth", 0, ctx.name_waiter)
    end

    @tag :uid_names
    test "UID-N06 replacement retaining old owner needs another same UID association", ctx do
      name = "org.foundation.UIDNames.RequeueDenied"
      assert {:ok, 1} = request_uid_name(name, 1, ctx.name_owner)
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Second", 0, ctx.name_waiter)
      before = name_snapshot(name, [ctx.name_owner, ctx.name_waiter])

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name(name, 2, ctx.name_waiter)

      assert name_snapshot(name, [ctx.name_owner, ctx.name_waiter]) == before
      assert NameRegistry.list_queued_owners(name) == {:ok, [elem(ctx.name_owner, 1)]}
    end

    @tag :uid_names
    test "UID-N07 already queued replacement retains both reservations without double charging",
         ctx do
      name = "org.foundation.UIDNames.QueuedReplacement"
      assert {:ok, 1} = request_uid_name(name, 1, ctx.name_owner)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)
      assert {:ok, 1} = request_uid_name(name, 2, ctx.name_waiter)

      assert NameRegistry.list_queued_owners(name) ==
               {:ok, [elem(ctx.name_waiter, 1), elem(ctx.name_owner, 1)]}

      assert name in name_policy_names(ctx.name_owner)
      assert name in name_policy_names(ctx.name_waiter)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Extra", 0, ctx.name_owner)

      assert {:ok, 1} = NameRegistry.release_name(name, elem(ctx.name_owner, 0))
      assert NameRegistry.list_queued_owners(name) == {:ok, [elem(ctx.name_waiter, 1)]}
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Extra", 0, ctx.name_owner)
    end

    @tag :uid_names
    @tag name_signals: true
    test "UID-N08 cross UID replacement denial is atomic and emits no ownership signals", ctx do
      name = "org.foundation.UIDNames.CrossUID"
      first = "org.foundation.UIDNames.OtherFirst"
      second = "org.foundation.UIDNames.OtherSecond"
      observer = elem(ctx.name_independent, 0)
      assert {:ok, 1} = request_uid_name(name, 5, ctx.name_owner)
      assert_uid_name_signals(name, nil, ctx.name_owner, observer)
      assert {:ok, 1} = request_uid_name(first, 0, ctx.name_independent)
      assert_uid_name_signals(first, nil, ctx.name_independent, observer)
      assert {:ok, 1} = request_uid_name(second, 0, ctx.name_independent)
      assert_uid_name_signals(second, nil, ctx.name_independent, observer)
      sync_uid_name_signals(ctx)
      before = name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent])

      # Dropping UID A's owner cannot supply UID B's missing slot.
      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name(name, 2, ctx.name_independent)

      assert name_snapshot(name, [ctx.name_owner, ctx.name_waiter, ctx.name_independent]) ==
               before

      sync_uid_name_signals(ctx)
      refute_receive {:uid_name_signal, _, _}, 0

      assert {:ok, 1} = NameRegistry.release_name(first, observer)
      assert_uid_name_signals(first, ctx.name_independent, nil, observer)
      assert {:ok, 1} = request_uid_name(name, 2, ctx.name_independent)
      assert_uid_name_signals(name, ctx.name_owner, ctx.name_independent, observer)
      assert NameRegistry.list_queued_owners(name) == {:ok, [elem(ctx.name_independent, 1)]}
      refute name in name_policy_names(ctx.name_owner)
      assert name in name_policy_names(ctx.name_independent)
      sync_uid_name_signals(ctx)
      refute_receive {:uid_name_signal, _, _}, 0

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.OtherExtra", 0, ctx.name_independent)

      sync_uid_name_signals(ctx)
      refute_receive {:uid_name_signal, _, _}, 0
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Healthy", 0, ctx.name_waiter)
      assert_uid_name_signals("org.foundation.UIDNames.Healthy", nil, ctx.name_waiter, observer)
    end

    @tag :uid_names
    test "UID-N09 abnormal owner DOWN promotes queue and duplicate cleanup returns credit once",
         ctx do
      assert Process.whereis(Router) == nil
      name = "org.foundation.UIDNames.KilledOwner"
      assert {:ok, 1} = request_uid_name(name, 0, ctx.name_owner)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)
      {owner, unique} = ctx.name_owner
      monitor = Process.monitor(owner)
      Process.exit(owner, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^owner, :killed}, 1000

      await_uid_name_queue(
        name,
        [elem(ctx.name_waiter, 1)],
        System.monotonic_time(:millisecond) + 1000
      )

      assert {:error, :name_not_found} = NameRegistry.resolve(unique)
      assert NameRegistry.get_name_owner(name) == {:ok, elem(ctx.name_waiter, 1)}
      replacement = {admitted(@uid_a), ":1.204"}
      assert :ok = NameRegistry.register_unique(elem(replacement, 1), elem(replacement, 0))
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Reclaimed", 0, replacement)

      for _ <- 1..2 do
        NameRegistry.peer_disconnected(owner)
        _ = :sys.get_state(NameRegistry)
      end

      assert NameRegistry.get_name_owner(name) == {:ok, elem(ctx.name_waiter, 1)}

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Extra", 0, replacement)

      assert {:ok, 1} =
               NameRegistry.release_name(
                 "org.foundation.UIDNames.Reclaimed",
                 elem(replacement, 0)
               )

      assert {:ok, 2} =
               NameRegistry.release_name(
                 "org.foundation.UIDNames.Reclaimed",
                 elem(replacement, 0)
               )

      assert {:ok, 3} = NameRegistry.release_name(name, elem(replacement, 0))
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Extra", 0, replacement)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.StillFull", 0, ctx.name_waiter)
    end

    @tag :uid_names
    test "UID-N10 abnormal queued DOWN frees one slot without changing the owner", ctx do
      name = "org.foundation.UIDNames.KilledQueue"
      assert {:ok, 1} = request_uid_name(name, 0, ctx.name_owner)
      assert {:ok, 2} = request_uid_name(name, 0, ctx.name_waiter)
      {waiter, unique} = ctx.name_waiter
      monitor = Process.monitor(waiter)
      Process.exit(waiter, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^waiter, :killed}, 1000

      await_uid_name_queue(
        name,
        [elem(ctx.name_owner, 1)],
        System.monotonic_time(:millisecond) + 1000
      )

      assert {:error, :name_not_found} = NameRegistry.resolve(unique)
      replacement = {admitted(@uid_a), ":1.204"}
      assert :ok = NameRegistry.register_unique(elem(replacement, 1), elem(replacement, 0))
      assert {:ok, 2} = request_uid_name(name, 0, replacement)
      NameRegistry.peer_disconnected(waiter)
      _ = :sys.get_state(NameRegistry)

      assert NameRegistry.list_queued_owners(name) ==
               {:ok, [elem(ctx.name_owner, 1), elem(replacement, 1)]}

      assert NameRegistry.get_name_owner(name) == {:ok, elem(ctx.name_owner, 1)}

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Extra", 0, replacement)
    end

    @tag :uid_names
    test "UID-N11 unadmitted peer cannot allocate a well-known association", ctx do
      name = "org.foundation.UIDNames.Unadmitted"
      unadmitted = {peer(), ":1.999"}

      assert {:error, "org.freedesktop.DBus.Error.Failed"} = request_uid_name(name, 0, unadmitted)
      assert {:error, :name_not_found} = NameRegistry.resolve(name)
      assert name_policy_names(unadmitted) == []
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.First", 0, ctx.name_owner)
      assert {:ok, 1} = request_uid_name("org.foundation.UIDNames.Second", 0, ctx.name_waiter)

      assert {:error, "org.freedesktop.DBus.Error.LimitsExceeded"} =
               request_uid_name("org.foundation.UIDNames.Extra", 0, ctx.name_owner)
    end

    @tag :uid_names
    test "UID-N12 unavailable Limits denies a name while cached association remains releasable",
         ctx do
      retained = "org.foundation.UIDNames.Retained"
      denied = "org.foundation.UIDNames.Unavailable"
      assert {:ok, 1} = request_uid_name(retained, 0, ctx.name_owner)
      assert :ok = stop_supervised(Limits)

      assert {:error, "org.freedesktop.DBus.Error.Failed"} =
               request_uid_name(denied, 0, ctx.name_waiter)

      assert {:error, :name_not_found} = NameRegistry.resolve(denied)
      assert NameRegistry.get_name_owner(retained) == {:ok, elem(ctx.name_owner, 1)}
      assert {:ok, 1} = NameRegistry.release_name(retained, elem(ctx.name_owner, 0))
      assert {:error, :name_not_found} = NameRegistry.resolve(retained)
      refute retained in name_policy_names(ctx.name_owner)
    end
  end

  defp request_uid_name(name, flags, {peer, unique}),
    do: NameRegistry.request_name(name, flags, peer, unique)

  defp name_policy_names({peer, _unique}),
    do: NameRegistry.routing_snapshot(peer, :bus).sender_policy_names |> Enum.sort()

  defp name_snapshot(name, actors) do
    {
      NameRegistry.get_name_owner(name),
      NameRegistry.list_queued_owners(name),
      Enum.map(actors, fn {peer, _unique} = actor ->
        {peer, Enum.sort(NameRegistry.names_for(peer)), name_policy_names(actor)}
      end)
    }
  end

  defp await_uid_name_queue(name, expected, deadline) do
    case NameRegistry.list_queued_owners(name) do
      {:ok, ^expected} ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline,
               "killed peer retained a name association without Router cleanup"

        await_uid_name_queue(name, expected, deadline)
    end
  end

  defp name_signal_actor(uid) do
    parent = self()
    actor = start_supervised!({Task, fn -> name_signal_loop(parent) end}, id: make_ref())
    assert :ok = Limits.acquire(actor, credentials(uid))
    assert :ok = Limits.auth_completed(actor)
    actor
  end

  defp name_signal_loop(parent) do
    receive do
      {:send_message, %Message{} = message, {token, _queued_at}} ->
        :ok = Limits.release(token)
        send(parent, {:uid_name_signal, self(), message})
        name_signal_loop(parent)

      {:uid_name_barrier, caller, reference} ->
        send(caller, {:uid_name_barrier, self(), reference})
        name_signal_loop(parent)

      :stop ->
        :ok
    end
  end

  defp sync_uid_name_signals(ctx) do
    _ = :sys.get_state(NameRegistry)
    _ = :sys.get_state(Router)
    reference = make_ref()

    for {peer, _unique} <- [ctx.name_owner, ctx.name_waiter, ctx.name_independent] do
      send(peer, {:uid_name_barrier, self(), reference})
      assert_receive {:uid_name_barrier, ^peer, ^reference}, 1000
    end
  end

  defp assert_uid_name_signals(name, old_owner, new_owner, observer) do
    old_unique = if old_owner, do: elem(old_owner, 1), else: ""
    new_unique = if new_owner, do: elem(new_owner, 1), else: ""

    if old_owner do
      {old_peer, old_name} = old_owner

      assert_receive {:uid_name_signal, ^old_peer,
                      %Message{
                        type: :signal,
                        member: "NameLost",
                        destination: ^old_name,
                        body: [^name]
                      }},
                     1000
    end

    if new_owner do
      {new_peer, new_name} = new_owner

      assert_receive {:uid_name_signal, ^new_peer,
                      %Message{
                        type: :signal,
                        member: "NameAcquired",
                        destination: ^new_name,
                        body: [^name]
                      }},
                     1000
    end

    assert_receive {:uid_name_signal, ^observer,
                    %Message{
                      type: :signal,
                      member: "NameOwnerChanged",
                      destination: nil,
                      body: [^name, ^old_unique, ^new_unique]
                    }},
                   1000
  end
end
