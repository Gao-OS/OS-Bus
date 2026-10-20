ExUnit.start()

defmodule OSBusFoundationPackagedWirePolicyTest do
  use ExUnit.Case, async: true
  alias GaoBus.{Config, Policy}

  def accounts do
    users = %{"root" => 0, "messagebus" => 4, "foundationA" => 1100, "foundationB" => 1101}

    records =
      Map.new(users, fn {name, uid} ->
        gid = if uid >= 1100, do: 100, else: uid
        {name, %{name: name, uid: uid, gid: gid, groups: [gid], provenance: nil}}
      end)

    %{
      users: users,
      groups: %{"root" => 0, "messagebus" => 4, "users" => 100},
      memberships: Map.new(records, fn {_, record} -> {record.uid, record.groups} end),
      user_records: records
    }
  end

  defp configuration do
    Config.load(
      System.get_env("OSBUS_WIRE_POLICY", Path.join(__DIR__, "packaged_wire_policy.xml")),
      accounts: accounts(),
      daemon_uid: 4
    )
  end

  defp invocation,
    do: %{
      profile: :system,
      nofork: true,
      nopidfile: true,
      log_target: :stderr,
      safety_limits: %{}
    }

  defp context(uid, type \\ :method_call) do
    gid = if uid >= 1100, do: 100, else: uid

    %{
      credentials: %{uid: uid, gid: gid, groups: [gid]},
      name: "org.foundation.Observer",
      type: type,
      message: %ExDBus.Message{
        type: type,
        interface: "org.foundation.Allowed",
        sender: ":1.1",
        destination: ":1.2"
      },
      sender_names: [":1.1"],
      destination_names: [":1.2"],
      requested_reply: true,
      eavesdrop: false,
      fds: 0
    }
  end

  defp decide(policy, action, ctx), do: elem(Policy.authorize({:ok, 1, policy}, action, ctx), 0)

  test "literal packaged XML compiles supported pure startup capacities without overrides" do
    assert {:ok, config} = configuration()
    assert config.settings[:type] == :system
    assert config.settings[:user] == 4
    assert config.settings[:auth] == ["EXTERNAL"]
    assert config.services.selected == %{}
    assert {:ok, plan} = Config.Runtime.compile(config, invocation(), %{uid: 4})
    assert plan.listener_options[:socket_path] == "/run/osbus-p08/socket/bus"

    assert plan.router_options[:pending_limits] == %{
             per_peer: 4,
             per_uid: 512,
             global: 4096,
             timeout_ms: 100
           }

    assert plan.safety_limits.global.connections == 8
    assert plan.safety_limits.uid.connections == 8
    assert plan.safety_limits.peer.ingress_bytes == 524_288
    assert plan.safety_limits.global.ingress_bytes == 2_097_152
    assert plan.safety_limits.peer.egress_bytes == 134_479_872
    assert plan.safety_limits.global.egress_bytes == 537_919_488
    assert plan.safety_limits.peer.ingress_messages == 32
    assert plan.safety_limits.global.ingress_messages == 512
    assert plan.safety_limits.peer.egress_messages == 32
    assert plan.safety_limits.global.egress_messages == 512
    assert plan.safety_limits.peer.ingress_fds == 32
    assert plan.safety_limits.global.ingress_fds == 128
    assert plan.safety_limits.peer.egress_fds == 32
    assert plan.safety_limits.global.egress_fds == 128
    assert plan.xml_limits["max_completed_connections"] == 7
    assert plan.xml_limits["max_incomplete_connections"] == 1

    for name <- [
          "max_names_per_connection",
          "max_match_rules_per_connection",
          "max_replies_per_connection"
        ],
        do: assert(plan.xml_limits[name] == 4)

    assert {:error, %{reason: {:inconsistent_safety_limit, :peer, :egress_bytes}}} =
             Config.Runtime.compile(
               config,
               Map.put(invocation(), :safety_limits, %{peer: %{egress_bytes: 262_144}}),
               %{uid: 4}
             )
  end

  test "XML and native admission and ownership have identical exact dot boundaries" do
    assert {:ok, config} = configuration()
    assert {:ok, xml} = Policy.compile(config)
    {rules, _} = Code.eval_file(Path.join(__DIR__, "policy.exs"))
    assert {:ok, native} = Policy.compile(rules)

    for uid <- [0, 4, 1100, 1101, 9999] do
      assert decide(xml, :connect, context(uid)) == decide(native, :connect, context(uid))

      assert decide(xml, :connect, context(uid)) ==
               if(uid in [0, 1100, 1101], do: :allow, else: :deny)

      for name <- [
            "org.foundation.Observer",
            "org.foundation.Observer.Child",
            "org.foundation.Root",
            "org.foundation.Root.Child",
            "org.foundation.RootX",
            "org.foundation.Service",
            "org.foundation.Service.Child",
            "org.foundation.ServiceX",
            "org.foundation.Forbidden"
          ] do
        ctx = %{context(uid) | name: name}
        assert decide(xml, :own, ctx) == decide(native, :own, ctx), "#{uid}/#{name}"

        allowed =
          (uid == 0 and name in ["org.foundation.Root", "org.foundation.Root.Child"]) or
            (uid == 1100 and name == "org.foundation.Observer") or
            (uid == 1101 and name in ["org.foundation.Service", "org.foundation.Service.Child"])

        assert decide(xml, :own, ctx) == if(allowed, do: :allow, else: :deny)
      end
    end
  end

  defp decoded(type, interface) do
    message = %ExDBus.Message{
      type: type,
      serial: 17,
      path: "/foundation",
      member: "Probe",
      interface: interface,
      sender: ":1.1",
      destination: ":1.2",
      signature: "",
      body: [],
      reply_serial: if(type in [:method_return, :error], do: 9),
      error_name: if(type == :error, do: "org.foundation.Expected")
    }

    assert {:ok, decoded, <<>>} =
             message |> ExDBus.Message.encode_message() |> ExDBus.Message.decode_message()

    assert decoded.interface == if(type in [:method_return, :error], do: nil, else: interface)
    decoded
  end

  # Independent standard-policy oracle; native agreement is checked separately.
  defp normative(uid, action, type, interface, observer, protected) do
    cond do
      uid not in [0, 1100, 1101] ->
        :deny

      uid == 1100 and action == :send and protected ->
        :deny

      uid == 1101 and action == :receive and type in [:method_call, :signal] and
          interface in [nil, "org.foundation.ReceiveDenied"] ->
        :deny

      uid == 1101 and action == :receive and type == :method_return and observer ->
        :deny

      true ->
        :allow
    end
  end

  test "valid decoded ordinary replies survive interface denial without bypassing Observer" do
    assert {:ok, config} = configuration()
    assert {:ok, xml} = Policy.compile(config)

    rows =
      for type <- [:method_return, :error],
          requested <- [false, true],
          wire_interface <- [nil, "org.foundation.ReceiveDenied"] do
        ctx = %{
          context(1101, type)
          | message: decoded(type, wire_interface),
            requested_reply: requested
        }

        observer = %{ctx | sender_names: [":1.1", "org.foundation.Observer"]}

        {type, requested, wire_interface, decide(xml, :receive, ctx),
         decide(xml, :receive, observer)}
      end

    expected =
      for type <- [:method_return, :error],
          requested <- [false, true],
          wire_interface <- [nil, "org.foundation.ReceiveDenied"] do
        {type, requested, wire_interface, :allow,
         if(type == :method_return, do: :deny, else: :allow)}
      end

    assert rows == expected
  end

  test "valid wire standard matrix enumerates only the adopted interface-less call delta" do
    assert {:ok, config} = configuration()
    assert {:ok, xml} = Policy.compile(config)
    {rules, _} = Code.eval_file(Path.join(__DIR__, "policy.exs"))
    assert {:ok, native} = Policy.compile(rules)

    partitions = [
      {:method_call, nil},
      {:method_call, "org.foundation.Allowed"},
      {:method_call, "org.foundation.ReceiveDenied"},
      {:signal, "org.foundation.Allowed"},
      {:signal, "org.foundation.ReceiveDenied"},
      {:method_return, nil},
      {:method_return, "org.foundation.Allowed"},
      {:method_return, "org.foundation.ReceiveDenied"},
      {:error, nil},
      {:error, "org.foundation.Allowed"},
      {:error, "org.foundation.ReceiveDenied"}
    ]

    rows =
      for uid <- [0, 4, 1100, 1101, 9999],
          action <- [:send, :receive],
          {type, wire_interface} <- partitions,
          requested <- [false, true],
          observer <- [false, true],
          protected <- [false, true] do
        message = decoded(type, wire_interface)

        ctx = %{
          context(uid, type)
          | message: message,
            requested_reply: requested,
            sender_names: if(observer, do: [":1.1", "org.foundation.Observer"], else: [":1.1"]),
            destination_names:
              if(protected, do: [":1.2", "org.foundation.Service.Protected"], else: [":1.2"])
        }

        expected = normative(uid, action, type, message.interface, observer, protected)
        xml_decision = decide(xml, action, ctx)

        assert xml_decision == expected,
               inspect(
                 {uid, action, type, wire_interface, requested, observer, protected, expected,
                  xml_decision}
               )

        %{
          uid: uid,
          action: action,
          type: type,
          wire_interface: wire_interface,
          requested: requested,
          observer: observer,
          protected: protected,
          xml: xml_decision,
          native: decide(native, action, ctx)
        }
      end

    assert length(rows) == 880
    deltas = Enum.filter(rows, &(&1.xml != &1.native))

    expected_deltas =
      for requested <- [false, true], observer <- [false, true], protected <- [false, true] do
        %{
          uid: 1101,
          action: :receive,
          type: :method_call,
          wire_interface: nil,
          requested: requested,
          observer: observer,
          protected: protected,
          xml: :deny,
          native: :allow
        }
      end

    assert deltas == expected_deltas
    assert Enum.any?(rows, &(&1.xml == :allow)) and Enum.any?(rows, &(&1.xml == :deny))
  end
end
