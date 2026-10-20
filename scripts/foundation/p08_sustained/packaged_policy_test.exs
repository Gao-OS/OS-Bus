ExUnit.start()

defmodule OSBusFoundationPackagedPolicyTest do
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
    Config.load(Path.join(__DIR__, "packaged_policy.xml"), accounts: accounts(), daemon_uid: 4)
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
      end
    end
  end

  test "XML and native send receive matrices agree including reply flags and aliases" do
    assert {:ok, config} = configuration()
    assert {:ok, xml} = Policy.compile(config)
    {rules, _} = Code.eval_file(Path.join(__DIR__, "policy.exs"))
    assert {:ok, native} = Policy.compile(rules)

    rows =
      for uid <- [0, 4, 1100, 1101, 9999],
          action <- [:send, :receive],
          type <- [:method_call, :method_return, :error, :signal],
          requested <- [true, false],
          scenario <- [:normal, :protected, :interface_denied, :observer, :missing_interface] do
        ctx = %{context(uid, type) | requested_reply: requested}

        ctx =
          case scenario do
            :normal ->
              ctx

            :protected ->
              %{ctx | destination_names: [":1.2", "org.foundation.Service.Protected"]}

            :interface_denied ->
              %{ctx | message: %{ctx.message | interface: "org.foundation.ReceiveDenied"}}

            :observer ->
              %{ctx | sender_names: [":1.1", "org.foundation.Observer"]}

            :missing_interface ->
              %{ctx | message: %{ctx.message | interface: nil}}
          end

        %{
          uid: uid,
          action: action,
          type: type,
          requested: requested,
          scenario: scenario,
          xml: decide(xml, action, ctx),
          native: decide(native, action, ctx)
        }
      end

    mismatches = Enum.filter(rows, &(&1.xml != &1.native))

    assert mismatches == [],
           "#{length(mismatches)}/#{length(rows)} mismatches: #{inspect(mismatches, limit: :infinity)}"
  end
end
