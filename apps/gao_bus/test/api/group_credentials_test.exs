defmodule GaoBus.GroupCredentialsTest do
  use ExUnit.Case, async: false
  alias GaoBus.{BusInterface, Config, NameRegistry, Policy}
  alias GaoBus.Unix.Credentials
  @bus "org.freedesktop.DBus"

  setup do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    :ok
  end

  test "complete kernel groups include primary once when absent and retain sorted duplicates" do
    assert {:ok, [7, 9, 9]} = Credentials.decode_groups(<<9::native-32, 9::native-32>>, 7)

    assert {:ok, [7, 7, 9]} =
             Credentials.decode_groups(<<7::native-32, 9::native-32, 7::native-32>>, 7)

    assert {:ok, [7]} = Credentials.decode_groups(<<>>, 7)

    assert {:ok, [7 | groups]} =
             Credentials.decode_groups(:binary.copy(<<9::native-32>>, 65_536), 7)

    assert groups == List.duplicate(9, 65_536)
    assert {:ok, [0xFFFFFFFE]} = Credentials.decode_groups(<<>>, 0xFFFFFFFE)
  end

  test "malformed, unset and oversized group records never become partial snapshots" do
    for record <- [<<1>>, <<0xFFFFFFFF::native-32>>, :binary.copy(<<1::native-32>>, 65_537)] do
      assert {:error, :invalid_peer_groups} = Credentials.decode_groups(record, 7)
    end

    for primary <- [-1, 0xFFFFFFFF, nil] do
      assert {:error, :invalid_peer_groups} = Credentials.decode_groups(<<>>, primary)
    end
  end

  test "unsupported groups are absent while failed reads retain fail-closed provenance" do
    identity = %{uid: 42, gid: 7, pid: 4321}

    for reason <- [:enoprotoopt, :eopnotsupp] do
      assert ^identity = Credentials.with_groups(identity, {:error, reason})
    end

    for result <- [
          {:error, :eperm},
          {:error, :erange},
          {:ok, <<1>>},
          {:ok, <<0xFFFFFFFF::native-32>>}
        ] do
      assert %{groups_error: :peer_groups_unavailable, uid: 42, gid: 7, pid: 4321} =
               Credentials.with_groups(identity, result)

      refute Map.has_key?(Credentials.with_groups(identity, result), :groups)
    end
  end

  test "a group read failure cannot skip a group denial and preserve a broad grant" do
    for {default, group} <- [{:allow, :deny}, {:deny, :allow}] do
      {:ok, policy} =
        Policy.XML.compile(
          [
            block(:default, default, %{"own" => "*"}),
            block({:gid, 7}, group, %{"own" => "*"})
          ],
          daemon_uid: 4,
          memberships: %{42 => [7]}
        )

      for failure <- [:peer_groups_unavailable, nil, "malformed"] do
        assert :deny =
                 Policy.XML.authorize(policy, :own, %{
                   credentials: %{uid: 42, gid: 7, groups_error: failure},
                   name: "org.foundation.Service"
                 })
      end
    end

    {:ok, independent} =
      Policy.XML.compile([block({:uid, 42}, :allow, %{"own" => "*"})], daemon_uid: 4)

    assert :allow =
             Policy.XML.authorize(independent, :own, %{
               credentials: %{uid: 42, groups_error: :peer_groups_unavailable},
               name: "org.foundation.Service"
             })

    {:ok, admission_only} =
      Policy.XML.compile(
        [
          block(:default, :allow, %{"group" => 7}),
          block({:uid, 42}, :allow, %{"own" => "*"})
        ],
        daemon_uid: 4,
        memberships: %{42 => [7]}
      )

    assert :allow =
             Policy.XML.authorize(admission_only, :own, %{
               credentials: %{uid: 42, groups_error: :peer_groups_unavailable},
               name: "org.foundation.Service"
             })
  end

  test "connect uses accounts while client group blocks prefer captured process groups" do
    {:ok, policy} =
      Policy.XML.compile(
        [
          block(:default, :deny, %{"user" => "*"}),
          block(:default, :allow, %{"group" => 7}),
          block(:default, :deny, %{"group" => 9}),
          block({:gid, 7}, :allow, %{"own" => "org.foundation.AccountOnly"}),
          block({:gid, 9}, :allow, %{"own" => "org.foundation.ProcessOnly"})
        ],
        daemon_uid: 4,
        memberships: %{42 => [7]}
      )

    identity = %{uid: 42, gid: 9, groups: [9]}
    assert :allow = Policy.XML.authorize(policy, :connect, %{credentials: identity})

    assert :allow =
             Policy.XML.authorize(policy, :own, %{
               credentials: identity,
               name: "org.foundation.ProcessOnly"
             })

    assert :deny =
             Policy.XML.authorize(policy, :own, %{
               credentials: identity,
               name: "org.foundation.AccountOnly"
             })

    assert :allow =
             Policy.XML.authorize(policy, :own, %{
               credentials: Map.delete(identity, :groups),
               name: "org.foundation.AccountOnly"
             })

    for groups <- [nil, [0xFFFFFFFF], [-1], :binary.copy(<<0>>, 4)] do
      assert :deny =
               Policy.XML.authorize(policy, :own, %{
                 credentials: %{identity | groups: groups},
                 name: "org.foundation.AccountOnly"
               })
    end

    assert :deny = Policy.XML.authorize(policy, :connect, %{credentials: %{identity | uid: 43}})

    assert :allow =
             Policy.XML.authorize(policy, :own, %{
               credentials: %{identity | uid: 43},
               name: "org.foundation.ProcessOnly"
             })
  end

  test "credential dictionaries disclose only complete representable process snapshots" do
    start_supervised!(NameRegistry)
    peer = start_supervised!({Task, fn -> receive do: (:stop -> :ok) end})
    :ok = NameRegistry.register_unique(":1.88", peer)

    for {groups, expected} <- [
          {[7, 9, 9], [{"UnixGroupIDs", {"au", [7, 9, 9]}}]},
          {[9, 7, 9], [{"UnixGroupIDs", {"au", [7, 9, 9]}}]},
          {nil, []},
          {[7, -1], []},
          {[7, 0xFFFFFFFF], []},
          {[9], []}
        ] do
      credentials = %{pid: 4321, uid: 42, gid: 7, groups: groups}

      state = %{
        peers: %{peer => %{unique_name: ":1.88", credentials: credentials}},
        next_serial: 1
      }

      msg = %ExDBus.Message{
        type: :method_call,
        destination: @bus,
        path: "/org/freedesktop/DBus",
        interface: @bus,
        member: "GetConnectionCredentials",
        serial: 1,
        signature: "s",
        body: [":1.88"]
      }

      {reply, _} = BusInterface.handle_message(msg, self(), state)
      assert reply.body == [[{"UnixUserID", {"u", 42}}, {"ProcessID", {"u", 4321}}] ++ expected]

      failed =
        put_in(
          state.peers[peer].credentials,
          Map.put(credentials, :groups_error, :peer_groups_unavailable)
        )

      {reply, _} = BusInterface.handle_message(msg, self(), failed)
      assert reply.body == [[{"UnixUserID", {"u", 42}}, {"ProcessID", {"u", 4321}}]]
    end
  end

  for mode <- ["groups", "exited", "exited-before-auth"] do
    @mode mode
    test "independent private socket actor #{@mode}" do
      path = private_core()

      actor = Path.expand("group_actor.py", __DIR__)

      {output, status} =
        System.cmd(System.find_executable("python3"), ["-B", actor, @mode, path],
          stderr_to_stdout: true
        )

      assert status == 0, output
      assert output =~ ~s("result": "PASS"), output
      IO.puts(output)
    end
  end

  defp private_core do
    identity = GaoBus.Unix.Native.identity()

    process_group =
      if System.get_env("OSBUS_API04_REQUIRE_DIFFERENT_GROUPS") == "1",
        do: 65_534,
        else: identity.gid

    directory = Path.join(System.tmp_dir!(), "gb-groups-#{System.unique_integer([:positive])}")
    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    path = Path.join(directory, "bus")
    config_path = Path.join(directory, "groups.conf")
    # The namespace account is root with [0]; process groups additionally contain 65534.
    File.write!(config_path, """
    <busconfig><auth>EXTERNAL</auth><policy context="default">
      <allow user="*"/><deny group="65534"/>
      <deny own="*"/><allow send_destination="*"/><allow receive_sender="*"/>
      <allow own="org.foundation.Forbidden"/>
    </policy><policy group="#{process_group}"><allow own="org.foundation.ProcessOnly"/>
      <deny own="org.foundation.Forbidden"/>
      <deny send_interface="org.foundation.GroupDenied" send_member="Probe"/>
    </policy></busconfig>
    """)

    assert {:ok, config} = Config.load(config_path, daemon_uid: identity.uid)
    start_supervised!(GaoBus.Ids)
    start_supervised!({Registry, keys: :unique, name: GaoBus.PeerRegistry})
    start_supervised!(GaoBus.Limits)
    start_supervised!({Policy, rules: config})
    start_supervised!(NameRegistry)
    start_supervised!(GaoBus.MatchRules)
    start_supervised!(GaoBus.Router)
    start_supervised!(GaoBus.PeerSupervisor)
    parent = self()

    start_supervised!(
      {Task,
       fn ->
         {:ok, listener} = :socket.open(:local, :stream, :default)
         :ok = :socket.bind(listener, %{family: :local, path: path})
         :ok = :socket.listen(listener)
         send(parent, {:private_listener_ready, path})
         accept(listener)
       end}
    )

    assert_receive {:private_listener_ready, ^path}
    path
  end

  defp accept(listener) do
    {:ok, socket} = :socket.accept(listener)
    {:ok, peer} = GaoBus.PeerSupervisor.start_peer(socket)
    :ok = GaoBus.Listener.transfer_ownership(socket, peer)
    accept(listener)
  end

  defp block(selector, effect, attributes),
    do: %{selector: selector, rules: [%{effect: effect, attributes: attributes}]}
end
