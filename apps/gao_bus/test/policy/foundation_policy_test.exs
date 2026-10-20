defmodule GaoBus.FoundationPolicyTest do
  use ExUnit.Case, async: false
  alias GaoBus.Policy

  test "SEC-13 absent policy denies every authorization surface" do
    for action <- [:connect, :own, :send, :receive, :control, :activate, :monitor] do
      assert {:deny, :policy_unavailable} = Policy.authorize(action, %{credentials: %{uid: 0}})
    end
  end

  test "initial missing or invalid rules do not create a policy snapshot" do
    assert {:error, :missing_policy} = Policy.compile(nil)

    assert {:error, {:invalid_rule, 1, :unknown_field}} =
             Policy.compile([%{action: :send, effect: :allow, match: %{unknown_field: true}}])

    assert {:error, :policy_unavailable} = Policy.snapshot()
  end

  test "SEC-08 configured ownership rules apply equally to root and service UIDs" do
    rules = [%{action: :own, effect: :allow, match: %{uid: 1100, name: "org.fixture.Allowed"}}]
    start_supervised!({Policy, rules: rules})

    assert {:allow, 1} =
             Policy.authorize(:own, %{credentials: %{uid: 1100}, name: "org.fixture.Allowed"})

    for uid <- [0, 1, 999, 1101] do
      assert {:deny, :policy_denied} =
               Policy.authorize(:own, %{credentials: %{uid: uid}, name: "org.fixture.Allowed"})
    end

    assert {:deny, :policy_denied} =
             Policy.authorize(:own, %{credentials: %{uid: 1100}, name: "org.fixture.Forbidden"})
  end

  test "SEC-09 send decisions use the resolved destination ownership set" do
    start_supervised!(
      {Policy,
       rules: [
         %{action: :send, effect: :allow, match: %{}},
         %{action: :send, effect: :deny, match: %{destination: "org.fixture.Protected"}}
       ]}
    )

    for address <- ["org.fixture.Protected", "org.fixture.Alias", ":1.3"] do
      context = %{
        credentials: %{uid: 1100},
        destination_names: [":1.3", "org.fixture.Protected", "org.fixture.Alias"],
        message: %{destination: address}
      }

      assert {:deny, :policy_denied} = Policy.authorize(:send, context)
    end
  end

  test "SEC-10 send grants do not grant receive or unsolicited reply permission" do
    start_supervised!(
      {Policy,
       rules: [
         %{action: :send, effect: :allow, match: %{uid: 1100}},
         %{action: :receive, effect: :allow, match: %{uid: 1101, requested_reply: true}}
       ]}
    )

    assert {:allow, 1} = Policy.authorize(:send, %{credentials: %{uid: 1100}})

    assert {:deny, :policy_denied} =
             Policy.authorize(:receive, %{credentials: %{uid: 1101}, requested_reply: false})

    assert {:allow, 1} =
             Policy.authorize(:receive, %{credentials: %{uid: 1101}, requested_reply: true})
  end

  test "SEC-11/12 connection and control scopes are explicit and default deny" do
    start_supervised!(
      {Policy,
       rules: [
         %{action: :connect, effect: :allow, match: %{uid: 1100}},
         %{action: :control, effect: :allow, match: %{uid: 1101, control: :reload}}
       ]}
    )

    assert {:allow, 1} = Policy.authorize(:connect, %{credentials: %{uid: 1100}})
    assert {:deny, :policy_denied} = Policy.authorize(:connect, %{credentials: %{uid: 0}})

    assert {:deny, :policy_denied} =
             Policy.authorize(:control, %{credentials: %{uid: 1100}, control: :reload})

    assert {:allow, 1} =
             Policy.authorize(:control, %{credentials: %{uid: 1101}, control: :reload})

    assert {:deny, :policy_denied} = Policy.authorize(:monitor, %{credentials: %{uid: 1101}})
  end

  test "POL-05/06 failed reload retains the coherent last valid generation" do
    rules = [%{action: :send, effect: :allow, match: %{uid: 1100}}]
    start_supervised!({Policy, rules: rules})
    assert {:ok, 1, ^rules} = Policy.snapshot()

    assert {:error, {:invalid_rule, 1, :unknown_action}} =
             Policy.reload([%{action: :bypass, effect: :allow, match: %{}}])

    assert {:ok, 1, ^rules} = Policy.snapshot()
    assert {:allow, 1} = Policy.authorize(:send, %{credentials: %{uid: 1100}})
    assert {:ok, 2} = Policy.reload([])
    assert {:deny, :policy_denied} = Policy.authorize(:send, %{credentials: %{uid: 1100}})
  end

  test "policy unavailable after owner failure cannot use a permissive fallback" do
    pid =
      start_supervised!({Policy, rules: [%{action: :send, effect: :allow, match: %{}}]},
        restart: :temporary
      )

    assert {:allow, 1} = Policy.authorize(:send, %{})
    monitor = Process.monitor(pid)
    Process.exit(pid, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^pid, :killed}
    assert {:deny, :policy_unavailable} = Policy.authorize(:send, %{})
  end

  test "SEC-12 decision diagnostics have fixed cardinality and retain no identity or payload" do
    start_supervised!({Policy, rules: [%{action: :send, effect: :allow, match: %{}}]})

    for n <- 1..1000 do
      context = %{
        credentials: %{uid: n},
        name: "org.private.Name#{n}",
        message: %{body: ["secret#{n}"]}
      }

      assert {:allow, 1} = Policy.authorize(:send, context)
      assert {:deny, :policy_denied} = Policy.authorize(:own, context)
    end

    assert {:ok, counts} = Policy.decision_counts()
    assert map_size(counts) == 7
    assert counts.send == %{allow: 1000, deny: 0}
    assert counts.own == %{allow: 0, deny: 1000}

    assert Enum.all?(counts, fn {_action, values} ->
             Map.keys(values) |> Enum.sort() == [:allow, :deny]
           end)

    refute inspect(:ets.tab2list(:gao_bus_policy_snapshot)) =~ "secret"
    refute inspect(:sys.get_state(Policy)) =~ "org.private"
    assert {:message_queue_len, 0} = Process.info(Process.whereis(Policy), :message_queue_len)
  end
end
