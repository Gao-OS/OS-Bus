defmodule GaoBus.Policy.XMLControlBindingTest do
  use ExUnit.Case, async: true

  alias GaoBus.Policy.XML
  @bus "org.freedesktop.DBus"

  test "privileged XML controls require both loaded send permission and a privileged kernel UID" do
    for {action, control, interface, member} <- [
          {:control, :activation_environment, @bus, "UpdateActivationEnvironment"},
          {:monitor, :monitor, @bus <> ".Monitoring", "BecomeMonitor"}
        ],
        uid <- [0, 4, 42] do
      ctx = context(uid, control, interface, member)

      assert XML.authorize(model(:allow), action, ctx) ==
               if(uid in [0, 4], do: :allow, else: :deny)

      assert :deny = XML.authorize(model(:deny), action, ctx)
      assert :deny = XML.authorize(model(:allow), action, %{ctx | credentials: %{}})
    end
  end

  test "explicit service start follows loaded send permission without a privileged UID exemption" do
    for uid <- [0, 4, 42] do
      ctx = context(uid, :start_service, @bus, "StartServiceByName")
      assert :allow = XML.authorize(model(:allow), :activate, ctx)
      assert :deny = XML.authorize(model(:deny), :activate, ctx)
      assert :deny = XML.authorize(model(:allow), :activate, %{ctx | credentials: %{}})
    end
  end

  test "control bindings cannot authorize mismatched or synthetic methods" do
    for {action, control, interface, member} <- [
          {:control, :activation_environment, @bus, "ReloadConfig"},
          {:control, :activation_environment, @bus <> ".Peer", "UpdateActivationEnvironment"},
          {:monitor, :monitor, @bus, "BecomeMonitor"},
          {:activate, :start_service, @bus, "ListNames"}
        ] do
      assert :deny = XML.authorize(model(:allow), action, context(0, control, interface, member))
    end
  end

  defp model(effect) do
    provenance = %{file: "control-binding.conf", line: 1}

    blocks = [
      %{
        selector: :default,
        provenance: provenance,
        rules: [
          %{effect: effect, attributes: %{"send_destination" => @bus}, provenance: provenance}
        ]
      }
    ]

    assert {:ok, policy} =
             XML.compile(blocks, daemon_uid: 4, memberships: %{0 => [], 4 => [], 42 => []})

    policy
  end

  defp context(uid, control, interface, member) do
    %{
      credentials: %{uid: uid, gid: uid, pid: 123, groups: []},
      control: control,
      message: %{
        type: :method_call,
        interface: interface,
        member: member,
        error_name: nil,
        path: "/org/freedesktop/DBus",
        destination: @bus,
        fds: []
      },
      destination_names: [@bus],
      sender_names: [":1.70"],
      requested_reply: false
    }
  end
end
