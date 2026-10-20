defmodule GaoBus.ApiDispatchTest do
  use ExUnit.Case, async: false

  alias ExDBus.{Introspection, Message}
  alias GaoBus.{BusInterface, BusMethod, Ids, Policy}

  @bus "org.freedesktop.DBus"
  @canonical "/org/freedesktop/DBus"
  @paths [@canonical, "/", "/org", "/org/freedesktop", "/unrelated"]
  # Pinned dbus-daemon 1.14.10 bus/driver.c:2525-2618 marks these ANY_PATH.
  @legacy [
    {"Hello", "", []},
    {"RequestName", "su", ["org.foundation.Path", 0]},
    {"ReleaseName", "s", ["org.foundation.Path"]},
    {"GetNameOwner", "s", [":1.1"]},
    {"ListQueuedOwners", "s", ["org.foundation.Path"]},
    {"NameHasOwner", "s", ["org.foundation.Path"]},
    {"ListNames", "", []},
    {"ListActivatableNames", "", []},
    {"GetId", "", []},
    {"GetConnectionUnixUser", "s", [":1.1"]},
    {"GetConnectionUnixProcessID", "s", [":1.1"]},
    {"GetConnectionCredentials", "s", [":1.1"]},
    {"AddMatch", "s", ["type='signal'"]},
    {"RemoveMatch", "s", ["type='signal'"]},
    {"ReloadConfig", "", []},
    {"StartServiceByName", "su", ["org.foundation.Absent", 0]}
  ]
  @universal @legacy ++
               [
                 {"Introspect", "", []},
                 {"Ping", "", []},
                 {"GetMachineId", "", []}
               ]

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    start_supervised!({Policy, rules: Policy.session_rules()})
    start_supervised!(Ids)
    %{state: %{peers: %{}, next_serial: 1, policy_snapshot: Policy.snapshot()}}
  end

  test "legacy, Peer and Introspect schemas accept all valid paths with explicit or absent interface" do
    for {member, signature, body} <- @universal,
        path <- @paths,
        interface <- [interface(member), nil] do
      message = call(member, signature, body, path, interface)
      assert {:ok, validated} = BusMethod.validate(message)
      assert validated.interface == interface(member)
      assert validated.path == path
    end
  end

  test "all universal methods validate signature and exact arity on every path" do
    for {member, signature, body} <- @universal, path <- @paths do
      message = call(member, signature, body, path, interface(member))

      assert {:error, "InvalidArgs", _} =
               BusMethod.validate(%{message | signature: "y", body: [1]})

      assert {:error, "InvalidArgs", _} = BusMethod.validate(%{message | body: body ++ ["extra"]})
      assert {:error, "UnknownObject", _} = BusMethod.validate(%{message | path: "invalid"})
    end
  end

  test "interface applicability and unknown member errors precede argument validation" do
    for path <- @paths, member <- ["ListNames", "Missing"] do
      assert {:error, "UnknownInterface", _} =
               BusMethod.validate(call(member, "y", [1], path, "org.foundation.Unknown"))
    end

    for path <- @paths, interface <- [@bus, @bus <> ".Peer", @bus <> ".Introspectable", nil] do
      assert {:error, "UnknownMethod", _} =
               BusMethod.validate(call("Missing", "y", [1], path, interface))
    end

    for path <- @paths -- [@canonical],
        interface <- [@bus <> ".Properties", @bus <> ".Monitoring"],
        member <- ["Get", "Missing"] do
      assert {:error, "UnknownInterface", _} =
               BusMethod.validate(call(member, "y", [1], path, interface))
    end

    for path <- @paths -- [@canonical], member <- ["Get", "GetAll", "Set", "BecomeMonitor"] do
      assert {:error, "UnknownMethod", _} = BusMethod.validate(call(member, "", [], path, nil))
    end
  end

  test "authorized environment control rejects noncanonical path before its arguments", ctx do
    rules = [%{action: :control, effect: :allow, match: %{control: :activation_environment}}]
    state = %{ctx.state | policy_snapshot: {:ok, 1, rules}}

    for path <- @paths -- [@canonical], {signature, body} <- [{"a{ss}", [[]]}, {"", []}] do
      {reply, after_state} =
        BusInterface.handle_message(
          call("UpdateActivationEnvironment", signature, body, path),
          self(),
          state
        )

      assert_error(reply, "AccessDenied")
      assert after_state.peers == state.peers
    end

    {reply, _} = BusInterface.handle_message(call("UpdateActivationEnvironment"), self(), state)
    assert_error(reply, "InvalidArgs")
  end

  test "denied environment control is denied before path and argument checks", ctx do
    for path <- @paths do
      {reply, after_state} =
        BusInterface.handle_message(
          call("UpdateActivationEnvironment", "", [], path),
          self(),
          ctx.state
        )

      assert_error(reply, "AccessDenied")
      assert after_state.peers == ctx.state.peers
    end
  end

  test "introspection follows path interfaces and hierarchy and includes ReloadConfig", ctx do
    for path <- @paths do
      {reply, _} =
        BusInterface.handle_message(
          call("Introspect", "", [], path, @bus <> ".Introspectable"),
          self(),
          ctx.state
        )

      assert reply.type == :method_return
      assert reply.signature == "s"
      assert [xml] = reply.body
      assert {:ok, ^path, interfaces, children} = Introspection.from_xml(xml)
      expected = [@bus, @bus <> ".Peer", @bus <> ".Introspectable"]
      expected = if path == @canonical, do: [@bus <> ".Properties" | expected], else: expected
      assert Enum.sort(Enum.map(interfaces, & &1.name)) == Enum.sort(expected)

      assert children ==
               Map.get(
                 %{
                   "/" => ["org/freedesktop/DBus"],
                   "/org" => ["freedesktop/DBus"],
                   "/org/freedesktop" => ["DBus"]
                 },
                 path,
                 []
               )

      bus = Enum.find(interfaces, &(&1.name == @bus))
      assert Enum.any?(bus.methods, &(&1.name == "ReloadConfig" and &1.args == []))
    end
  end

  test "constant read-only bus properties emit their const annotation", ctx do
    {reply, _} =
      BusInterface.handle_message(
        call("Introspect", "", [], @canonical, @bus <> ".Introspectable"),
        self(),
        ctx.state
      )

    [xml] = reply.body

    for name <- ["Features", "Interfaces"] do
      assert [_, body] =
               Regex.run(
                 ~r/<property name="#{name}" type="as" access="read">(.*?)<\/property>/s,
                 xml
               )

      assert body =~
               ~s(<annotation name="org.freedesktop.DBus.Property.EmitsChangedSignal" value="const"/>)
    end
  end

  test "GetId ignores a mutable environment override and remains tied to the current epoch",
       ctx do
    previous = Application.fetch_env(:gao_bus, :bus_id)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:gao_bus, :bus_id, value)
        :error -> Application.delete_env(:gao_bus, :bus_id)
      end
    end)

    for value <- ["invalid", "00000000000000000000000000000000"] do
      Application.put_env(:gao_bus, :bus_id, value)
      {reply, _} = BusInterface.handle_message(call("GetId"), self(), ctx.state)
      assert reply.body == [Ids.bus_id()]
    end
  end

  defp call(member, signature \\ "", body \\ [], path \\ @canonical, interface \\ @bus) do
    %Message{
      type: :method_call,
      serial: 70,
      path: path,
      destination: @bus,
      interface: interface,
      member: member,
      sender: ":1.70",
      signature: signature,
      body: body
    }
  end

  defp interface("Introspect"), do: @bus <> ".Introspectable"
  defp interface(member) when member in ["Ping", "GetMachineId"], do: @bus <> ".Peer"
  defp interface(_member), do: @bus

  defp assert_error(reply, name) do
    assert reply.type == :error
    assert reply.error_name == @bus <> ".Error." <> name
    assert reply.reply_serial == 70
    assert reply.sender == @bus
    assert reply.destination == ":1.70"
  end
end
