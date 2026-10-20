defmodule GaoBus.Policy.CoherentDiscoveryTest do
  use ExUnit.Case, async: false

  alias GaoBus.{BusInterface, Config, Policy}

  @moduletag :tmp_dir
  @first "org.test.First"
  @second "org.test.Second"

  setup %{tmp_dir: directory} do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    services = Path.join(directory, "services")
    File.mkdir!(services)

    fixture = %{
      path: Path.join(directory, "bus.conf"),
      passwd: Path.join(directory, "passwd"),
      group: Path.join(directory, "group"),
      services: services
    }

    options = [daemon_uid: 4, passwd: fixture.passwd, group: fixture.group]
    fixture = Map.put(fixture, :options, options)
    write_generation(fixture, 42, 7, @first)
    assert {:ok, config} = Config.load(fixture.path, options)
    start_supervised!({Policy, rules: config, config_file: fixture.path, config_options: options})
    fixture
  end

  test "one row contains settings, accounts, policy, discovery and bounded provenance", fixture do
    assert {:ok, 1, model} = captured = Policy.snapshot()
    assert {:ok, configuration} = Policy.configuration(captured)
    assert configuration == model.configuration
    assert configuration.daemon_uid == 4
    assert configuration.settings.servicedir == [fixture.services]
    assert configuration.accounts.user_records["worker"].uid == 42
    assert configuration.services.selected[@first].account.uid == 42
    assert configuration.services.selected[@first].account.gid == 7
    assert Policy.activatable_names(captured) == [@first]
    assert {:allow, 1} = Policy.authorize(captured, :own, identity(42, @first))
    assert configuration.sources != []
    assert configuration.directives != []
    refute raw_bytes?(configuration)
    assert [%{selector: {:uid, 42}, provenance: origin, rules: [rule]}] = model.blocks
    assert origin.file == fixture.path
    assert origin.element == "policy"
    assert rule.provenance.element == "allow"
  end

  test "old captures remain coherent after account and service files change", fixture do
    assert {:ok, 1, _} = original = Policy.snapshot()
    assert {:ok, old_configuration} = Policy.configuration(original)
    write_generation(fixture, 43, 8, @second)
    assert {:ok, 2} = Policy.reload_file()
    assert {:ok, 2, _} = current = Policy.snapshot()
    assert {:ok, configuration} = Policy.configuration(current)
    assert configuration.accounts.users["worker"] == 43
    assert configuration.services.selected[@second].account.gid == 8
    assert Policy.activatable_names(current) == [@second]
    assert {:allow, 2} = Policy.authorize(current, :own, identity(43, @second))
    assert {:deny, :policy_denied} = Policy.authorize(current, :own, identity(42, @first))
    assert Policy.configuration(original) == {:ok, old_configuration}
    assert Policy.activatable_names(original) == [@first]
    assert {:allow, 1} = Policy.authorize(original, :own, identity(42, @first))
  end

  test "invalid discovery or accounts retain the complete previous row", fixture do
    original = Policy.snapshot()
    original_configuration = Policy.configuration(original)
    write_generation(fixture, 43, 8, @second)
    service = Path.join(fixture.services, @second <> ".service")
    File.write!(service, "[D-BUS Service]\nName=#{@second}\nExec=false\nUser=missing\n")
    assert {:error, _} = Policy.reload_file()
    assert Policy.snapshot() == original
    assert Policy.configuration() == original_configuration
    assert Policy.activatable_names() == [@first]
    File.write!(service, "[D-BUS Service]\nName=#{@second}\nExec=false\nUser=worker\n")
    File.write!(fixture.passwd, "worker:x:invalid:8::/:/bin/false\n")
    assert {:error, _} = Policy.reload_file()
    assert Policy.snapshot() == original
    assert Policy.configuration() == original_configuration
  end

  test "concurrent readers bind authorization, accounts and names to one generation", fixture do
    assert {:ok, first} = Config.load(fixture.path, fixture.options)
    write_generation(fixture, 43, 8, @second)
    assert {:ok, second} = Config.load(fixture.path, fixture.options)
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
               assert {:ok, generation, _} = captured = Policy.snapshot()
               assert {:ok, configuration} = Policy.configuration(captured)
               uid = configuration.accounts.users["worker"]
               [name] = Policy.activatable_names(captured)
               account = configuration.services.selected[name].account

               {generation, uid, name, account.uid, account.gid,
                Policy.authorize(captured, :own, identity(uid, name))}
             end

           send(parent, {:observations, gate, observations})
         end},
        id: gate
      )

    assert_receive {:ready, ^gate}
    send(reader, {:run, gate})

    for generation <- 2..30 do
      candidate = if rem(generation, 2) == 1, do: first, else: second
      assert {:ok, ^generation} = Policy.reload(candidate)
    end

    assert_receive {:observations, ^gate, observations}, 5000

    for {generation, uid, name, account_uid, gid, result} <- observations do
      expected = if rem(generation, 2) == 1, do: {42, @first, 7}, else: {43, @second, 8}
      assert {uid, name, gid} == expected
      assert account_uid == uid
      assert result == {:allow, generation}
    end
  end

  test "ListActivatableNames reads the Router's captured snapshot", fixture do
    original = Policy.snapshot()
    write_generation(fixture, 43, 8, @second)
    assert {:ok, 2} = Policy.reload_file()
    state = %{next_serial: 1, policy_snapshot: original, peers: %{}}

    assert {%{type: :method_return, signature: "as", body: [[@first]]}, updated} =
             BusInterface.handle_message(list_message(), self(), state)

    assert updated.next_serial == 2

    assert {%{type: :method_return, body: [[@second]]}, _} =
             BusInterface.handle_message(list_message(), self(), %{
               state
               | policy_snapshot: Policy.snapshot()
             })
  end

  test "list policies remain empty and unavailable metadata fails closed" do
    assert {:ok, 2} = Policy.reload(Policy.session_rules())
    assert Policy.activatable_names() == []
    assert Policy.configuration() == {:error, :configuration_unavailable}
    assert Policy.activatable_names({:error, :policy_unavailable}) == []
    assert Policy.configuration({:error, :policy_unavailable}) == {:error, :policy_unavailable}

    assert {%{type: :method_return, body: [[]]}, _} =
             BusInterface.handle_message(list_message(), self(), %{
               next_serial: 1,
               peers: %{},
               policy_snapshot: Policy.snapshot()
             })
  end

  defp write_generation(fixture, uid, gid, name) do
    File.write!(fixture.passwd, "worker:x:#{uid}:#{gid}::/:/bin/false\n")
    File.write!(fixture.group, "workers:x:#{gid}:worker\n")

    for previous <- File.ls!(fixture.services),
        do: File.rm!(Path.join(fixture.services, previous))

    File.write!(
      Path.join(fixture.services, name <> ".service"),
      "[D-BUS Service]\nName=#{name}\nExec=false\nUser=worker\n"
    )

    File.write!(
      fixture.path,
      "<busconfig><type>system</type><servicedir>#{fixture.services}</servicedir>" <>
        "<policy user=\"worker\"><allow own=\"#{name}\"/></policy></busconfig>"
    )
  end

  defp identity(uid, name), do: %{credentials: %{uid: uid}, name: name}

  defp list_message do
    %ExDBus.Message{
      type: :method_call,
      serial: 1,
      path: "/org/freedesktop/DBus",
      interface: "org.freedesktop.DBus",
      destination: "org.freedesktop.DBus",
      member: "ListActivatableNames",
      sender: ":1.42",
      signature: "",
      body: []
    }
  end

  defp raw_bytes?(map) when is_map(map),
    do:
      Enum.any?(map, fn {key, value} ->
        (key == :bytes and is_binary(value)) or raw_bytes?(value)
      end)

  defp raw_bytes?(list) when is_list(list), do: Enum.any?(list, &raw_bytes?/1)
  defp raw_bytes?(_value), do: false
end
