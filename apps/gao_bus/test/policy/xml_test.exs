defmodule GaoBus.Policy.XMLTest do
  use ExUnit.Case, async: true

  alias GaoBus.{Config, Policy}
  alias GaoBus.Policy.XML

  test "mandatory policy overrides user and default classes independent of file position" do
    policies = [
      block(:mandatory, :deny, %{"own" => "org.test.Service"}),
      block({:uid, 42}, :allow, %{"own" => "org.test.Service"}),
      block(:default, :deny, %{"own" => "*"})
    ]

    assert :deny = decision(policies, :own, %{credentials: identity(), name: "org.test.Service"})

    assert :allow =
             decision(Enum.drop(policies, 1), :own, %{
               credentials: identity(),
               name: "org.test.Service"
             })
  end

  test "account group classes apply before user classes and do not infer process membership" do
    policies = [
      block({:uid, 42}, :deny, %{"own" => "*"}),
      block({:gid, 7}, :allow, %{"own" => "*"})
    ]

    context = %{credentials: identity(), name: "org.test.Service"}
    assert :deny = decision(policies, :own, context)
    assert :allow = decision(Enum.drop(policies, 1), :own, context)
    assert :deny = decision(Enum.drop(policies, 1), :own, put_in(context.credentials.uid, 43))
  end

  test "same-class occurrence order is retained and an absent required identity denies" do
    rules = [block(:default, :deny, %{"own" => "*"}), block(:default, :allow, %{"own" => "*"})]
    assert :allow = decision(rules, :own, %{credentials: identity(), name: "org.test.Service"})

    assert :deny =
             decision(Enum.reverse(rules), :own, %{
               credentials: identity(),
               name: "org.test.Service"
             })

    assert :deny = decision(rules, :own, %{credentials: %{}, name: "org.test.Service"})
  end

  test "XML wildcards include omitted optional headers and undirected signals" do
    rules = [block(:default, :allow, %{"send_interface" => "*", "send_destination" => "*"})]
    assert :allow = decision(rules, :send, context(:method_call))
    assert :allow = decision(rules, :send, context(:signal))
  end

  test "destination and sender matches use resolved ownership aliases" do
    send = [
      block(:default, :allow, %{"send_destination" => "*"}),
      block(:default, :deny, %{"send_destination" => "org.test.Secret"})
    ]

    receive = [
      block(:default, :allow, %{"receive_sender" => "*"}),
      block(:default, :deny, %{"receive_sender" => "org.test.Secret"})
    ]

    ctx = %{context(:signal) | destination_names: [":1.8", "org.test.Secret", "org.test.Other"]}
    assert :deny = decision(send, :send, ctx)
    assert :deny = decision(receive, :receive, %{ctx | sender_names: [":1.8", "org.test.Secret"]})
  end

  test "namespace grants include the namespace root and respect dot boundaries" do
    rules = [block(:default, :allow, %{"own_prefix" => "org.test.Service"})]

    for name <- ["org.test.Service", "org.test.Service.Child"] do
      assert :allow = decision(rules, :own, %{credentials: identity(), name: name})
    end

    assert :deny = decision(rules, :own, %{credentials: identity(), name: "org.test.ServiceX"})
  end

  test "send destination prefix can match a trusted queued ownership snapshot" do
    rules = [block(:default, :allow, %{"send_destination_prefix" => "org.test.Service"})]
    ctx = Map.put(context(:method_call), :destination_policy_names, ["org.test.Service.Queued"])
    assert :allow = decision(rules, :send, ctx)
    assert :deny = decision(rules, :send, context(:method_call))
  end

  test "broadcast modifier distinguishes undirected signals from other traffic" do
    rules = [
      block(:default, :deny, %{"send_destination" => "*"}),
      block(:default, :allow, %{"send_broadcast" => true})
    ]

    assert :allow = decision(rules, :send, context(:signal))
    assert :deny = decision(rules, :send, context(:method_call))
    assert :deny = decision(rules, :send, put_in(context(:signal).message.destination, ":1.8"))
  end

  test "allow reply defaults admit only requested replies while false admits unsolicited replies" do
    defaults = [block(:default, :allow, %{"send_destination" => "*"})]
    any = [block(:default, :allow, %{"send_destination" => "*", "send_requested_reply" => false})]
    assert :deny = decision(defaults, :send, context(:method_return))
    assert :allow = decision(defaults, :send, %{context(:method_return) | requested_reply: true})
    assert :allow = decision(any, :send, context(:error))
  end

  test "deny reply default matches only unsolicited replies and true also matches requested replies" do
    defaults = [
      block(:default, :allow, %{"receive_sender" => "*"}),
      block(:default, :deny, %{"receive_sender" => "*"})
    ]

    all = [
      block(:default, :allow, %{"receive_sender" => "*"}),
      block(:default, :deny, %{"receive_sender" => "*", "receive_requested_reply" => true})
    ]

    assert :deny = decision(defaults, :receive, context(:method_return))

    assert :allow =
             decision(defaults, :receive, %{context(:method_return) | requested_reply: true})

    assert :deny = decision(all, :receive, %{context(:error) | requested_reply: true})
    assert :deny = decision(defaults, :receive, context(:method_call))
  end

  test "eavesdrop modifiers have distinct allow and deny defaults" do
    allow = [block(:default, :allow, %{"receive_sender" => "*"})]
    allow_all = [block(:default, :allow, %{"receive_sender" => "*", "eavesdrop" => true})]

    deny_spy = [
      block(:default, :allow, %{"receive_sender" => "*"}),
      block(:default, :deny, %{"receive_sender" => "*", "eavesdrop" => true})
    ]

    ctx = Map.put(context(:method_call), :eavesdrop, true)
    assert :deny = decision(allow, :receive, ctx)
    assert :allow = decision(allow_all, :receive, ctx)
    assert :allow = decision(deny_spy, :receive, context(:method_call))
    assert :deny = decision(deny_spy, :receive, ctx)
  end

  test "FD bounds test actual validated descriptor count" do
    rules = [
      block(:default, :allow, %{"send_destination" => "*", "min_fds" => 1, "max_fds" => 2})
    ]

    assert :deny = decision(rules, :send, context(:method_call))
    assert :allow = decision(rules, :send, put_in(context(:method_call).message.fds, [:one]))

    assert :deny =
             decision(
               rules,
               :send,
               put_in(context(:method_call).message.fds, [:one, :two, :three])
             )
  end

  test "empty XML policy adds no message grants and admission defaults to daemon identity" do
    assert :allow = decision([], :connect, %{credentials: %{uid: 4}})
    assert :deny = decision([], :connect, %{credentials: identity()})
    assert :deny = decision([], :own, %{credentials: identity(), name: "org.test.Service"})
    assert :deny = decision([], :send, context(:method_call))
    assert :deny = decision([], :send, context(:signal))
    assert :deny = decision([], :send, %{context(:error) | requested_reply: true})
    assert :deny = decision([], :send, context(:error))
    assert :deny = decision([], :receive, context(:method_call))
    assert :deny = decision([], :monitor, context(:method_call))
  end

  test "optional interface denial cannot be bypassed by omitting the header" do
    rules = [
      block(:default, :allow, %{"send_destination" => "*"}),
      block(:default, :deny, %{"send_interface" => "org.test.Secret"})
    ]

    assert :deny = decision(rules, :send, context(:method_call))

    assert :allow =
             decision(
               rules,
               :send,
               put_in(context(:method_call).message.interface, "org.test.Public")
             )

    assert :deny =
             decision(
               [block(:default, :allow, %{"send_interface" => "org.test.Public"})],
               :send,
               context(:method_call)
             )
  end

  test "admission user and group rules use exact trusted account memberships" do
    rules = [block(:default, :allow, %{"group" => 7}), block(:mandatory, :deny, %{"user" => 43})]
    assert :allow = decision(rules, :connect, %{credentials: identity()})
    assert :deny = decision(rules, :connect, %{credentials: %{uid: 43, gid: 7}})
    assert :deny = decision(rules, :connect, %{credentials: %{uid: 44, gid: 7}})

    assert :deny =
             decision([block(:default, :allow, %{"user" => "*"})], :connect, %{
               credentials: %{uid: 44}
             })
  end

  test "unknown attributes, mixed action families and unsupported console identity fail compilation" do
    for attributes <- [
          %{"unknown" => "*"},
          %{"own" => "*", "send_destination" => "*"},
          %{"min_fds" => 1}
        ] do
      assert {:error, %{file: "fixture.conf", line: 3}} =
               compile([block(:default, :allow, attributes)])
    end

    assert {:error, %{reason: :unsupported_console_identity}} =
             compile([block({:at_console, false}, :allow, %{"own" => "*"})])
  end

  test "both effects reject admission outside default and mandatory policy classes" do
    for selector <- [{:uid, 42}, {:gid, 7}],
        effect <- [:allow, :deny],
        attrs <- [%{"user" => 42}, %{"group" => 7}] do
      assert {:error, %{reason: :invalid_admission_policy_class}} =
               compile([block(selector, effect, attrs)])
    end
  end

  test "manually constructed policy rules satisfy reference combinations" do
    for effect <- [:allow, :deny],
        attrs <- [
          %{"send_member" => "Secret"},
          %{"receive_member" => "Secret"},
          %{"send_interface" => "*", "send_error" => "*"},
          %{"send_path" => "/example", "send_member" => "Secret", "send_error" => "*"},
          %{"receive_interface" => "*", "receive_error" => "*"},
          %{"receive_interface" => "*", "receive_member" => "Secret", "receive_error" => "*"},
          %{"send_broadcast" => true, "send_destination" => "org.test.Service"},
          %{"send_type" => :signal, "min_fds" => 2, "max_fds" => 1}
        ] do
      assert {:error, %{reason: :invalid_rule_attributes}} =
               compile([block(:default, effect, attrs)])
    end
  end

  test "complete account snapshots are required when compiling Config candidates" do
    candidate = %Config{policies: [block(:default, :allow, %{"user" => 42})], daemon_uid: 4}

    for accounts <- [
          %{memberships: %{42 => [7]}},
          %{users: nil, groups: nil, memberships: %{42 => [7]}},
          %{users: %{"service" => nil}, groups: %{"service" => 7}, memberships: %{42 => [7]}},
          %{users: %{"service" => 42}, groups: %{"service" => -1}, memberships: %{42 => [7]}}
        ] do
      assert {:error, %{reason: :invalid_account_snapshot}} =
               Policy.compile(%{candidate | accounts: accounts})
    end

    assert {:ok, _} =
             Policy.compile(%{
               candidate
               | accounts: %{
                   users: %{"service" => 42},
                   groups: %{"service" => 7},
                   memberships: %{42 => [7, 7]}
                 }
             })
  end

  test "malformed provenance cannot raise or override the validation reason" do
    for provenance <- [nil, [], "invalid", %{reason: :allow, element: "allow"}] do
      assert {:error, %{reason: :invalid_selector, element: "policy"}} =
               compile([%{selector: :unknown, rules: [], provenance: provenance}])
    end
  end

  test "malformed models deny instead of raising or granting" do
    {:ok, valid} = compile([block(:default, :allow, %{"own" => "*"})])

    for model <- [
          %XML{},
          %{valid | blocks: nil},
          %{valid | memberships: nil},
          %{valid | blocks: [%{selector: :default, rules: nil}]},
          %{
            valid
            | blocks: [
                %{selector: :default, rules: [%{action: :own, effect: :allow, attributes: %{}}]}
              ]
          },
          %{
            valid
            | blocks: [
                %{
                  selector: :default,
                  rules: [%{action: :own, effect: :allow, attributes: %{"unknown" => "*"}}]
                }
              ]
          },
          %{
            valid
            | blocks: [
                %{
                  selector: :mandatory,
                  rules: [%{action: :own, effect: :deny, attributes: %{"own" => "*"}}]
                }
                | valid.blocks
              ]
          }
        ] do
      assert :deny =
               XML.authorize(model, :own, %{credentials: identity(), name: "org.test.Service"})

      assert {:deny, :policy_denied} =
               Policy.authorize({:ok, 1, model}, :own, %{
                 credentials: identity(),
                 name: "org.test.Service"
               })
    end
  end

  test "native policy compilation and ordered authorization remain compatible" do
    rules =
      Policy.session_rules() ++
        [%{action: :own, effect: :deny, match: %{name: "org.test.Restricted"}}]

    assert {:ok, ^rules} = Policy.compile(rules)
    assert {:allow, 9} = Policy.authorize({:ok, 9, rules}, :connect, %{credentials: identity()})

    assert {:allow, 9} =
             Policy.authorize({:ok, 9, rules}, :own, %{
               credentials: identity(),
               name: "org.test.Public"
             })

    assert {:deny, :policy_denied} =
             Policy.authorize({:ok, 9, rules}, :own, %{
               credentials: identity(),
               name: "org.test.Restricted"
             })
  end

  defp decision(policies, action, context) do
    assert {:ok, compiled} = compile(policies)
    XML.authorize(compiled, action, context)
  end

  defp compile(policies),
    do: XML.compile(policies, daemon_uid: 4, memberships: %{4 => [4], 42 => [7], 43 => [9]})

  defp block(selector, effect, attributes),
    do: %{
      selector: selector,
      provenance: %{file: "fixture.conf", line: 2},
      rules: [
        %{effect: effect, attributes: attributes, provenance: %{file: "fixture.conf", line: 3}}
      ]
    }

  defp identity, do: %{uid: 42, gid: 9, pid: 123}

  defp context(type),
    do: %{
      credentials: identity(),
      message: %{
        type: type,
        interface: nil,
        member: nil,
        error_name: nil,
        path: nil,
        destination: nil,
        fds: []
      },
      destination_names: [],
      sender_names: [],
      requested_reply: false
    }
end
