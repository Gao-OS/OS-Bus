defmodule GaoBus.Policy.FileReloadTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Config, Policy}

  @moduletag :tmp_dir

  setup %{tmp_dir: directory} do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    path = Path.join(directory, "bus.conf")
    included = Path.join(directory, "policy.conf")

    options = [
      daemon_uid: 4,
      accounts: %{users: %{"service" => 42}, groups: %{"service" => 7}, memberships: %{42 => [7]}}
    ]

    File.write!(path, "<busconfig><type>system</type><include>policy.conf</include></busconfig>")
    File.write!(included, policy(:allow))
    assert {:ok, config} = Config.load(path, options)
    start_supervised!({Policy, rules: config, config_file: path, config_options: options})
    %{config_path: path, included: included, configuration: config, config_options: options}
  end

  test "file reload publishes the complete new policy while captured generations remain valid",
       context do
    assert {:ok, 1, original} = Policy.snapshot()
    File.write!(context.included, policy(:deny))
    assert {:ok, 2} = Policy.reload_file()
    assert {:deny, :policy_denied} = Policy.authorize(:own, identity())
    assert {:allow, 1} = Policy.authorize({:ok, 1, original}, :own, identity())
  end

  test "malformed or vanished includes leave the last complete generation active", context do
    assert {:ok, 1, original} = Policy.snapshot()

    for contents <- [
          "<busconfig>",
          "<busconfig><policy context=\"default\"><allow silent_grant=\"*\"/></policy></busconfig>"
        ] do
      File.write!(context.included, contents)
      assert {:error, _} = Policy.reload_file()
      assert {:ok, 1, ^original} = Policy.snapshot()
      assert {:allow, 1} = Policy.authorize(:own, identity())
    end

    File.rm!(context.included)
    assert {:error, _} = Policy.reload_file()
    assert {:ok, 1, ^original} = Policy.snapshot()
  end

  test "runtime changes cannot be accepted as policy-only reloads", context do
    assert {:ok, 1, original} = Policy.snapshot()

    for {setting, elements} <- [
          {"<type>session</type>", ["type"]},
          {"<limit name=\"max_completed_connections\">1</limit>", ["limit", "type"]},
          {"<listen>unix:path=/tmp/another-bus</listen>", ["listen", "type"]}
        ] do
      File.write!(
        context.config_path,
        "<busconfig>#{setting}<include>policy.conf</include></busconfig>"
      )

      assert {:error, %{reason: :configuration_requires_restart, origins: origins}} =
               Policy.reload_file()

      assert Enum.sort(Enum.map(origins, & &1.element)) == elements
      path = context.config_path

      for origin <- origins do
        assert %{file: ^path, line: 1, occurrence: 1, include_chain: []} = origin
      end

      assert {:ok, 1, ^original} = Policy.snapshot()
    end
  end

  test "concurrent readers see policy belonging to the reported file generation", context do
    parent = self()
    gate = make_ref()

    reader =
      start_supervised!(
        {Task,
         fn ->
           send(parent, {:ready, gate})
           receive do: ({:run, ^gate} -> :ok)

           observations =
             for _ <- 1..2000 do
               assert {:ok, generation, model} = Policy.snapshot()
               {generation, Policy.authorize({:ok, generation, model}, :own, identity())}
             end

           send(parent, {:observations, gate, observations})
         end},
        id: gate
      )

    assert_receive {:ready, ^gate}
    send(reader, {:run, gate})

    for generation <- 2..20 do
      File.write!(context.included, policy(if rem(generation, 2) == 1, do: :allow, else: :deny))
      assert {:ok, ^generation} = Policy.reload_file()
    end

    assert_receive {:observations, ^gate, observations}, 5000

    for {generation, result} <- observations do
      expected =
        if rem(generation, 2) == 1, do: {:allow, generation}, else: {:deny, :policy_denied}

      assert result == expected
    end
  end

  test "XML ReloadConfig uses its send permission and denied calls cannot publish", context do
    permission =
      "<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\"/>"

    File.write!(context.included, control_policy(permission))
    assert {:ok, 2} = Policy.reload_file()

    state = %{
      peers: %{self() => %{unique_name: ":1.42", credentials: %{uid: 42, gid: 7, pid: 123}}},
      next_serial: 1,
      policy_snapshot: Policy.snapshot()
    }

    message = %ExDBus.Message{
      type: :method_call,
      serial: 1,
      path: "/org/freedesktop/DBus",
      interface: "org.freedesktop.DBus",
      destination: "org.freedesktop.DBus",
      member: "ReloadConfig",
      sender: ":1.42",
      signature: "",
      body: []
    }

    {reply, _} = GaoBus.BusInterface.handle_message(message, self(), state)
    assert reply.type == :method_return
    assert {:ok, 3, _} = Policy.snapshot()

    denial =
      "<deny send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\" send_member=\"ReloadConfig\"/>"

    File.write!(context.included, control_policy(permission <> denial))
    assert {:ok, 4} = Policy.reload_file()
    assert {:ok, 4, original} = Policy.snapshot()

    {reply, _} =
      GaoBus.BusInterface.handle_message(message, self(), %{
        state
        | policy_snapshot: Policy.snapshot()
      })

    assert reply.error_name == "org.freedesktop.DBus.Error.AccessDenied"
    assert {:ok, 4, ^original} = Policy.snapshot()
  end

  test "XML ReloadConfig preserves required-include FileNotFound and the active generation",
       context do
    permission =
      "<allow send_destination=\"org.freedesktop.DBus\" send_interface=\"org.freedesktop.DBus\"/>"

    File.write!(
      context.included,
      control_policy(permission <> "<allow own=\"org.test.Service\"/>")
    )

    assert {:ok, 2} = Policy.reload_file()
    assert {:ok, 2, original} = snapshot = Policy.snapshot()

    state = %{
      peers: %{self() => %{unique_name: ":1.42", credentials: %{uid: 42, gid: 7, pid: 123}}},
      next_serial: 1,
      policy_snapshot: snapshot
    }

    message = %ExDBus.Message{
      type: :method_call,
      serial: 21,
      path: "/org/freedesktop/DBus",
      interface: "org.freedesktop.DBus",
      destination: "org.freedesktop.DBus",
      member: "ReloadConfig",
      sender: ":1.42",
      signature: "",
      body: []
    }

    for {contents, error_name} <- [
          {"<busconfig>", "Failed"},
          {"<busconfig><include>missing.conf</include></busconfig>", "FileNotFound"}
        ] do
      File.write!(context.included, contents)
      assert {:error, reason} = Config.load(context.config_path, context.config_options)

      if error_name == "FileNotFound" do
        assert %{file: file, element: "include", reason: {:file_error, :enoent}} = reason
        assert file == context.included
      end

      assert {:error, ^reason} = Policy.reload_file()
      assert {:ok, 2, ^original} = Policy.snapshot()

      {reply, _} = GaoBus.BusInterface.handle_message(message, self(), state)

      assert {:ok, 2, ^original} = Policy.snapshot()
      assert {:allow, 2} = Policy.authorize(:own, identity())
      assert reply.type == :error
      assert reply.reply_serial == message.serial
      assert reply.sender == "org.freedesktop.DBus"
      assert reply.destination == ":1.42"
      assert reply.signature == "s"
      assert reply.body == ["Configuration reload was rejected"]
      assert reply.error_name == "org.freedesktop.DBus.Error." <> error_name
    end
  end

  test "a policy process restart cannot restore revoked startup-file grants", context do
    File.write!(context.included, policy(:deny))
    assert {:ok, 2} = Policy.reload_file()
    assert {:deny, :policy_denied} = Policy.authorize(:own, identity())
    :ok = stop_supervised(Policy)

    start_supervised!(
      {Policy,
       rules: context.configuration,
       config_file: context.config_path,
       config_options: context.config_options}
    )

    assert {:deny, :policy_denied} = Policy.authorize(:own, identity())
  end

  test "a restart with an invalid current file fails instead of resurrecting old grants",
       context do
    File.write!(context.included, policy(:deny))
    assert {:ok, 2} = Policy.reload_file()
    File.write!(context.included, "<busconfig>")
    :ok = stop_supervised(Policy)

    assert {:error, _} =
             start_supervised(
               {Policy,
                rules: context.configuration,
                config_file: context.config_path,
                config_options: context.config_options}
             )

    assert {:error, :policy_unavailable} = Policy.snapshot()
  end

  defp control_policy(rules),
    do: "<busconfig><policy context=\"default\">#{rules}</policy></busconfig>"

  defp policy(effect),
    do:
      "<busconfig><policy context=\"default\"><#{effect} own=\"org.test.Service\"/></policy></busconfig>"

  defp identity, do: %{credentials: %{uid: 42}, name: "org.test.Service"}
end
