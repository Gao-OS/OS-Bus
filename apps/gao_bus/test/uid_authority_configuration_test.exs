defmodule GaoBus.UIDAuthorityConfigurationTest do
  use ExUnit.Case, async: false

  alias ExDBus.Message
  alias GaoBus.{BusInterface, Limits, MatchRules, NameRegistry}

  @moduletag :uid_configuration
  @uid_a 1000
  @uid_b 2000
  @bus "org.freedesktop.DBus"
  @failed "org.freedesktop.DBus.Error.Failed"
  @limited "org.freedesktop.DBus.Error.LimitsExceeded"
  @invalid_values [0, -1, :infinity, nil, 1.5, "2", false]
  @configurations [
    {MatchRules, :max_matches_per_uid, :invalid_match_limits,
     [max_matches_per_peer: 8, max_match_entries: 32]},
    {NameRegistry, :max_names_per_uid, :invalid_name_limits,
     [max_names_per_peer: 8, max_name_entries: 32]}
  ]

  setup do
    Application.stop(:gao_bus)

    previous =
      Map.new(@configurations, fn {_, key, _, _} ->
        {key, Application.fetch_env(:gao_bus, key)}
      end)

    on_exit(fn ->
      for {key, value} <- previous do
        case value do
          {:ok, original} -> Application.put_env(:gao_bus, key, original)
          :error -> Application.delete_env(:gao_bus, key)
        end
      end
    end)

    for {_, key, _, _} <- @configurations, do: Application.delete_env(:gao_bus, key)
    start_supervised!(Limits)
    :ok
  end

  test "UID-C01 omitted UID ceilings are finite 2048 defaults" do
    %{matches: matches, names: names} = start_authorities()
    assert %{max_matches_per_uid: 2048} = :sys.get_state(matches)
    assert %{max_names_per_uid: 2048} = :sys.get_state(names)
  end

  test "UID-C02 positive env ceilings govern both authorities" do
    put_uid_env(1)
    start_authorities()
    first = admitted(@uid_a)
    second = admitted(@uid_a)
    other = admitted(@uid_b)

    assert :ok = MatchRules.add_match(first, rule("EnvFirst"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(second, rule("EnvDenied"))
    assert recipients("EnvDenied") == []
    assert {:ok, 1} = request_name("EnvFirst", first)
    assert {:error, @limited} = request_name("EnvDenied", second)
    assert {:error, :name_not_found} = NameRegistry.resolve(name("EnvDenied"))
    assert :ok = MatchRules.add_match(other, rule("EnvOther"))
    assert {:ok, 1} = request_name("EnvOther", other, ":1.402")
  end

  test "UID-C03 explicit UID options override lower env ceilings" do
    put_uid_env(1)
    start_authorities([max_matches_per_uid: 2], max_names_per_uid: 2)
    first = admitted(@uid_a)
    second = admitted(@uid_a)

    assert :ok = MatchRules.add_match(first, rule("OptionFirst"))
    assert :ok = MatchRules.add_match(second, rule("OptionSecond"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(first, rule("OptionDenied"))
    assert recipients("OptionDenied") == []
    assert {:ok, 1} = request_name("OptionFirst", first)
    assert {:ok, 1} = request_name("OptionSecond", second, ":1.402")
    assert {:error, @limited} = request_name("OptionDenied", first)
    assert {:error, :name_not_found} = NameRegistry.resolve(name("OptionDenied"))
  end

  test "UID-C04 zero negative infinite and noninteger UID options are rejected" do
    for {module, key, reason, base} <- @configurations, invalid <- @invalid_values do
      assert {:stop, ^reason} = isolated_init(module, Keyword.put(base, key, invalid))
    end
  end

  test "UID-C05 invalid UID env ceilings cannot disable either safety budget" do
    for {module, key, reason, base} <- @configurations, invalid <- @invalid_values do
      Application.put_env(:gao_bus, key, invalid)
      assert {:stop, ^reason} = isolated_init(module, base)
    end
  end

  test "UID-C06 XML per-connection quotas retain native UID and global ceilings" do
    start_authorities(
      [
        xml_limits: %{"max_match_rules_per_connection" => 8},
        max_matches_per_peer: 1,
        max_match_entries: 4,
        max_matches_per_uid: 2
      ],
      xml_limits: %{"max_names_per_connection" => 8},
      max_names_per_peer: 1,
      max_name_entries: 4,
      max_names_per_uid: 2
    )

    first = admitted(@uid_a)
    second = admitted(@uid_a)
    other = admitted(@uid_b)
    third_uid = admitted(3000)

    for {peer, unique} <- [{first, ":1.401"}, {second, ":1.402"}, {other, ":1.403"}] do
      assert :ok = NameRegistry.register_unique(unique, peer)
    end

    # XML replaces the peer ceiling of 1, but never replaces the UID ceiling.
    assert :ok = MatchRules.add_match(first, rule("XMLFirst"))
    assert :ok = MatchRules.add_match(first, rule("XMLSecond"))
    assert {:ok, 1} = request_name("XMLFirst", first)
    assert {:ok, 1} = request_name("XMLSecond", first)
    assert {:error, :limits_exceeded} = MatchRules.add_match(second, rule("XMLUIDDenied"))
    assert {:error, @limited} = request_name("XMLUIDDenied", second, ":1.402")
    assert recipients("XMLUIDDenied") == []
    assert {:error, :name_not_found} = NameRegistry.resolve(name("XMLUIDDenied"))

    for member <- ["XMLOtherFirst", "XMLOtherSecond"] do
      assert :ok = MatchRules.add_match(other, rule(member))
      assert {:ok, 1} = request_name(member, other, ":1.403")
    end

    # A UID with no retained entries still cannot cross the global ceiling.
    assert {:error, :limits_exceeded} = MatchRules.add_match(third_uid, rule("XMLGlobalDenied"))
    assert {:error, @limited} = request_name("XMLGlobalDenied", third_uid, ":1.404")
    assert recipients("XMLGlobalDenied") == []
    assert {:error, :name_not_found} = NameRegistry.resolve(name("XMLGlobalDenied"))
    assert recipients("XMLFirst") == [first]
    assert NameRegistry.get_name_owner(name("XMLFirst")) == {:ok, ":1.401"}
  end

  test "UID-C07 XML zero rejects valid and malformed allocations without retained UID state" do
    %{matches: matches, names: names} =
      start_authorities(
        [xml_limits: %{"max_match_rules_per_connection" => 0}, max_matches_per_uid: 2],
        xml_limits: %{"max_names_per_connection" => 0},
        max_names_per_uid: 2
      )

    first = admitted(@uid_a)
    assert :ok = NameRegistry.register_unique(":1.401", first)
    assert {:error, :limits_exceeded} = MatchRules.add_match(first, rule("Zero"))
    assert {:error, :limits_exceeded} = MatchRules.add_match(first, "type='bogus'")
    assert {:error, @limited} = request_name("Zero", first)
    refute MatchRules.has_rules?(first)
    assert {:error, :name_not_found} = NameRegistry.resolve(name("Zero"))
    assert NameRegistry.resolve(":1.401") == {:ok, first}
    assert %{peers: peers, uid_counts: counts} = :sys.get_state(matches)
    assert peers == %{} and counts == %{}
    assert %{peers: name_peers, uid_counts: name_counts} = :sys.get_state(names)
    assert name_peers == %{} and name_counts == %{}
  end

  test "UID-C08 stale match DOWN cannot delete fresh admission entries or return UID credit" do
    start_authorities(max_matches_per_uid: 1)
    first = admitted(@uid_a)
    assert :ok = MatchRules.add_match(first, rule("OldMatch"))
    assert %{peers: %{^first => old}} = :sys.get_state(MatchRules)
    assert :ok = MatchRules.remove_match(first, rule("OldMatch"))
    assert %{peers: peers, uid_counts: counts} = :sys.get_state(MatchRules)
    assert peers == %{} and counts == %{}
    reacquire(first, @uid_b)
    assert :ok = MatchRules.add_match(first, rule("FreshMatch"))
    assert %{peers: %{^first => current}} = :sys.get_state(MatchRules)
    refute current.monitor == old.monitor
    refute current.admission == old.admission

    send(MatchRules, {:DOWN, old.monitor, :process, first, :killed})
    _ = :sys.get_state(MatchRules)
    assert recipients("FreshMatch") == [first]

    assert {:error, :limits_exceeded} =
             MatchRules.add_match(admitted(@uid_b), rule("StaleMatchDenied"))

    assert recipients("StaleMatchDenied") == []
    assert :ok = MatchRules.add_match(admitted(@uid_a), rule("OldUIDReused"))
  end

  test "UID-C09 stale name DOWN cannot delete fresh names or return UID credit" do
    start_authorities([], max_names_per_uid: 1)
    first = admitted(@uid_a)
    assert :ok = NameRegistry.register_unique(":1.401", first)
    assert {:ok, 1} = request_name("OldName", first)
    assert %{peers: %{^first => old}} = :sys.get_state(NameRegistry)
    assert {:ok, 1} = NameRegistry.release_name(name("OldName"), first)
    assert %{peers: peers, uid_counts: counts} = :sys.get_state(NameRegistry)
    assert peers == %{} and counts == %{}
    reacquire(first, @uid_b)
    assert {:ok, 1} = request_name("FreshName", first)
    assert %{peers: %{^first => current}} = :sys.get_state(NameRegistry)
    refute current.monitor == old.monitor
    refute current.admission == old.admission

    send(NameRegistry, {:DOWN, old.monitor, :process, first, :killed})
    _ = :sys.get_state(NameRegistry)
    assert NameRegistry.resolve(":1.401") == {:ok, first}
    assert NameRegistry.get_name_owner(name("FreshName")) == {:ok, ":1.401"}
    assert NameRegistry.list_queued_owners(name("FreshName")) == {:ok, [":1.401"]}
    assert {:error, @limited} = request_name("StaleNameDenied", admitted(@uid_b), ":1.402")
    assert {:error, :name_not_found} = NameRegistry.resolve(name("StaleNameDenied"))
    assert {:ok, 1} = request_name("OldNameUIDReused", admitted(@uid_a), ":1.403")
  end

  test "UID-C10 retired name admission cannot allocate and cached removal returns credit once" do
    start_authorities([], max_names_per_uid: 1)
    first = admitted(@uid_a)
    assert {:ok, 1} = request_name("RetainedName", first)
    assert {:ok, token} = Limits.reserve_ingress(first, 1)
    assert :ok = Limits.release_peer(first)
    assert {:error, @failed} = request_name("RetiredNameDenied", first)
    assert {:error, :name_not_found} = NameRegistry.resolve(name("RetiredNameDenied"))
    assert NameRegistry.get_name_owner(name("RetainedName")) == {:ok, ":1.401"}
    assert {:ok, 1} = NameRegistry.release_name(name("RetainedName"), first)
    assert {:ok, 2} = NameRegistry.release_name(name("RetainedName"), first)
    assert :ok = Limits.release(token)
    assert {:error, @failed} = request_name("AbsentNameDenied", first)
    assert {:error, :name_not_found} = NameRegistry.resolve(name("AbsentNameDenied"))
    replacement = admitted(@uid_a)
    assert {:ok, 1} = request_name("RetiredCreditReused", replacement, ":1.402")
    assert {:error, @limited} = request_name("RetiredCreditExtra", replacement, ":1.402")
  end

  for new_uid <- [@uid_a, @uid_b] do
    test "UID-C11 name admission drift to UID #{new_uid} cannot rebind retained associations" do
      start_authorities([], max_names_per_uid: 1)
      first = admitted(@uid_a)
      assert :ok = NameRegistry.register_unique(":1.401", first)
      assert {:ok, 1} = request_name("PinnedName", first)
      previous_admission = :sys.get_state(Limits).peers[first].monitor
      reacquire(first, unquote(new_uid))
      assert {:error, @failed} = request_name("ReboundNameDenied", first)
      assert {:error, :name_not_found} = NameRegistry.resolve(name("ReboundNameDenied"))
      assert NameRegistry.get_name_owner(name("PinnedName")) == {:ok, ":1.401"}

      assert Enum.sort(NameRegistry.names_for(first)) ==
               Enum.sort([":1.401", name("PinnedName")])

      assert {:ok, 1} = NameRegistry.release_name(name("PinnedName"), first)
      assert {:ok, 1} = request_name("NewAdmissionName", first)
      assert %{peers: %{^first => current}} = :sys.get_state(NameRegistry)
      assert current.uid == unquote(new_uid)
      refute current.admission == previous_admission

      assert {:error, @limited} =
               request_name("NewAdmissionFull", admitted(unquote(new_uid)), ":1.402")
    end
  end

  test "UID-C12 AddMatch identity absence maps through BusInterface and codec to Failed" do
    start_authorities(max_matches_per_uid: 1)
    first = peer()
    unique = ":1.401"

    state = %{
      peers: %{first => %{unique_name: unique, credentials: credentials(@uid_a)}},
      next_serial: 1
    }

    request = %Message{
      type: :method_call,
      serial: 7,
      path: "/org/freedesktop/DBus",
      destination: @bus,
      sender: unique,
      interface: @bus,
      member: "AddMatch",
      signature: "s",
      body: [rule("WireDenied")]
    }

    assert {:ok, decoded_request, <<>>} =
             Message.decode_message(Message.encode_message(request))

    {reply, updated} = BusInterface.handle_message(decoded_request, first, state)

    assert %Message{
             type: :error,
             error_name: @failed,
             reply_serial: 7,
             destination: ^unique,
             sender: @bus,
             signature: "s",
             body: [explanation]
           } = reply

    assert {:ok,
            %Message{
              type: :error,
              error_name: @failed,
              reply_serial: 7,
              destination: ^unique,
              sender: @bus,
              body: [^explanation]
            }, <<>>} = Message.decode_message(Message.encode_message(reply))

    assert updated.next_serial == 2
    assert updated.peers == state.peers
    refute MatchRules.has_rules?(first)
    assert recipients("WireDenied") == []

    malformed = %{request | serial: 8, body: ["type='bogus'"]}
    {invalid, updated} = BusInterface.handle_message(malformed, first, updated)
    assert %Message{error_name: "org.freedesktop.DBus.Error.MatchRuleInvalid"} = invalid
    healthy = admitted(@uid_a)

    updated =
      put_in(updated.peers[healthy], %{
        unique_name: ":1.402",
        credentials: credentials(@uid_a)
      })

    valid = %{request | serial: 9, sender: ":1.402", body: [rule("WireHealthy")]}
    {success, _updated} = BusInterface.handle_message(valid, healthy, updated)
    assert %Message{type: :method_return, reply_serial: 9, destination: ":1.402"} = success
    assert recipients("WireHealthy") == [healthy]
  end

  defp start_authorities(match_options \\ [], name_options \\ []) do
    matches =
      start_supervised!(
        {MatchRules,
         Keyword.merge([max_matches_per_peer: 8, max_match_entries: 32], match_options)}
      )

    names =
      start_supervised!(
        {NameRegistry, Keyword.merge([max_names_per_peer: 8, max_name_entries: 32], name_options)}
      )

    %{matches: matches, names: names}
  end

  defp isolated_init(module, opts) do
    parent = self()
    reference = make_ref()

    actor =
      start_supervised!(
        {Task,
         fn ->
           receive do
             {:run, ^reference} -> send(parent, {reference, module.init(opts)})
           after
             1000 -> flunk("initialization actor did not receive its barrier release")
           end
         end},
        id: make_ref()
      )

    monitor = Process.monitor(actor)
    send(actor, {:run, reference})
    assert_receive {^reference, result}, 1000
    assert_receive {:DOWN, ^monitor, :process, ^actor, :normal}, 1000
    result
  end

  defp put_uid_env(value) do
    for {_, key, _, _} <- @configurations, do: Application.put_env(:gao_bus, key, value)
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

  # Explicit unit admissions do not establish actual kernel UID attribution.
  defp admitted(uid) do
    peer = peer()
    assert :ok = Limits.acquire(peer, credentials(uid))
    assert :ok = Limits.auth_completed(peer)
    peer
  end

  defp reacquire(peer, uid) do
    assert :ok = Limits.release_peer(peer)
    assert :ok = Limits.acquire(peer, credentials(uid))
    assert :ok = Limits.auth_completed(peer)
  end

  defp credentials(uid), do: %{uid: uid, gid: 1000, pid: 123}
  defp name(member), do: "org.foundation.Configuration.#{member}"
  defp rule(member), do: "type='signal',member='#{member}'"

  defp request_name(member, peer, unique \\ ":1.401"),
    do: NameRegistry.request_name(name(member), 0, peer, unique)

  defp recipients(member),
    do:
      MatchRules.matching_peers(
        Message.signal("/uid_configuration", "org.foundation.UID", member)
      )
end
