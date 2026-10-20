defmodule GaoBus.ConfigStartupTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Application, Policy}
  alias GaoBus.Unix.Native

  @moduletag :tmp_dir

  setup context do
    Elixir.Application.stop(:gao_bus)
    {:ok, _} = Elixir.Application.ensure_all_started(:crypto)
    identity = Native.identity()
    File.chmod!(context.tmp_dir, 0o700)

    directory =
      Path.join(
        System.tmp_dir!(),
        "obs-config-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    on_exit(fn -> File.rm_rf!(directory) end)
    path = Path.join(directory, "bus")
    file = Path.join(context.tmp_dir, "system.conf")

    values = %{
      profile: :system,
      cluster: false,
      socket_path: path,
      config_file: file,
      config_options: [
        accounts: %{
          users: %{"bus" => identity.uid},
          groups: %{"bus" => identity.gid},
          memberships: %{identity.uid => [identity.gid]}
        }
      ],
      policy_rules: Policy.session_rules()
    }

    previous =
      Map.new(values, fn {key, _} -> {key, Elixir.Application.fetch_env(:gao_bus, key)} end)

    Enum.each(values, fn {key, value} -> Elixir.Application.put_env(:gao_bus, key, value) end)

    on_exit(fn ->
      Enum.each(previous, fn
        {key, {:ok, value}} -> Elixir.Application.put_env(:gao_bus, key, value)
        {key, :error} -> Elixir.Application.delete_env(:gao_bus, key)
      end)
    end)

    %{config_path: file, path: path, identity: identity}
  end

  test "XML configuration is authoritative over broader native fixture rules", context do
    File.write!(context.config_path, """
    <busconfig><type>system</type><auth>EXTERNAL</auth>
      <policy context="default"><allow user="*"/><deny own="*"/><allow own="org.test.Allowed"/></policy>
    </busconfig>
    """)

    start_supervised!(core())

    assert {:allow, 1} =
             Policy.authorize(:own, %{credentials: context.identity, name: "org.test.Allowed"})

    assert {:deny, :policy_denied} =
             Policy.authorize(:own, %{credentials: context.identity, name: "org.test.Forbidden"})

    assert File.exists?(context.path)
  end

  test "invalid initial XML cannot fall back to native grants or create a listener", context do
    File.write!(
      context.config_path,
      "<busconfig><policy context=\"default\"><allow silently_allow=\"true\"/></policy></busconfig>"
    )

    assert {:error, reason} = start_supervised(core())
    assert inspect(reason) =~ "invalid_configuration"
    assert {:error, :policy_unavailable} = Policy.snapshot()
    refute File.exists?(context.path)
    assert Process.whereis(GaoBus.Router) == nil
  end

  test "unbound runtime limit semantics prevent readiness instead of silently ignoring them",
       context do
    File.write!(
      context.config_path,
      "<busconfig><limit name=\"service_start_timeout\">1</limit></busconfig>"
    )

    assert {:error, reason} = start_supervised(core())
    assert inspect(reason) =~ "unimplemented_runtime_limits"
    refute File.exists?(context.path)
    assert Process.whereis(GaoBus.Router) == nil
  end

  test "XML runtime options reach all enforcing consumers before the listener starts", context do
    File.write!(context.config_path, """
    <busconfig><type>system</type><auth>EXTERNAL</auth>
      <limit name="max_completed_connections">1</limit>
      <limit name="max_incomplete_connections">2</limit>
      <limit name="max_connections_per_user">1</limit>
      <limit name="max_names_per_connection">2</limit>
      <limit name="max_match_rules_per_connection">1</limit>
      <limit name="max_replies_per_connection">1</limit>
      <limit name="reply_timeout">0</limit>
      <limit name="max_message_size">8192</limit>
      <limit name="max_message_unix_fds">1</limit>
      <limit name="pending_fd_timeout">7</limit>
      <limit name="max_incoming_bytes">16384</limit>
      <limit name="max_outgoing_bytes">16384</limit>
      <policy context="default"><allow user="*"/><allow send_type="*"/><allow receive_type="*"/></policy>
    </busconfig>
    """)

    start_supervised!(core())
    assert {:ok, stats} = GaoBus.Limits.snapshot()
    assert stats.xml.limits["max_completed_connections"] == 1
    assert stats.xml.queues["max_incoming_bytes"] == 16384
    router = :sys.get_state(GaoBus.Router)
    assert router.pending.limits.per_peer == 1
    assert router.pending.limits.timeout_ms == :infinity
    listener = :sys.get_state(GaoBus.Listener)
    assert listener.peer_options[:xml_limits]["max_message_size"] == 8192
    assert listener.peer_options[:xml_limits]["pending_fd_timeout"] == 7
    assert File.exists?(context.path)
  end

  test "XML profile and daemon UID must agree with the actual configured runtime", context do
    for {xml, error} <- [
          {"<type>session</type>", "configuration_profile_mismatch"},
          {"<user>#{context.identity.uid + 1}</user>", "daemon_uid_mismatch"}
        ] do
      File.write!(context.config_path, "<busconfig>" <> xml <> "</busconfig>")
      assert {:error, reason} = start_supervised(core())
      assert inspect(reason) =~ error
      refute File.exists?(context.path)
    end
  end

  defp core, do: %{id: :xml_core, start: {Application, :start, [:normal, []]}}
end
