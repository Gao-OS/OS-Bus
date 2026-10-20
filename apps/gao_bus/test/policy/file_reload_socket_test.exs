defmodule GaoBus.Policy.FileReloadSocketTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Config, Policy}

  @moduletag timeout: 120_000
  @source __ENV__.file
  @actor Path.expand("../fixtures/reload_actor.py", __DIR__)
  @authorities [GaoBus.Ids, Policy, GaoBus.NameRegistry, GaoBus.Router, GaoBus.Listener]

  setup tags do
    Application.stop(:gao_bus)
    {:ok, _} = Application.ensure_all_started(:crypto)
    identity = GaoBus.Unix.Native.identity()

    assert identity.uid == 0,
           "BLOCKED_ENV: execute reload wire tests as root in a disposable VM with a real ordinary UID"

    ordinary_uid = String.to_integer(System.get_env("OSBUS_RELOAD_ORDINARY_UID", "65534"))
    assert ordinary_uid != identity.uid
    service_uid = String.to_integer(System.get_env("OSBUS_RELOAD_SERVICE_UID", "1100"))

    if tags[:destination_alias] do
      assert length(Enum.uniq([identity.uid, ordinary_uid, service_uid])) == 3
    end

    python = System.find_executable("python3")
    assert python, "BLOCKED_ENV: python3 is required for the independent reload actor"

    fixture =
      Path.join(
        System.tmp_dir!(),
        "gb-reload-#{System.pid()}-#{System.unique_integer([:positive])}"
      )

    File.mkdir!(fixture)
    File.chmod!(fixture, 0o755)
    on_exit(fn -> File.rm_rf!(fixture) end)
    directory = Path.join(fixture, "config")

    prepare =
      cond do
        tags[:api_dispatch] ->
          ["prepare-properties", directory, "0", to_string(ordinary_uid)]

        tags[:properties_get_all] ->
          ["prepare-properties", directory, "0", to_string(ordinary_uid)]

        tags[:properties_set] ->
          ["prepare-properties", directory, "0", to_string(ordinary_uid)]

        tags[:destination_alias] ->
          ["prepare-alias", directory, "0", to_string(ordinary_uid), to_string(service_uid)]

        true ->
          ["prepare", directory, "0", to_string(ordinary_uid)]
      end

    {output, status} = System.cmd(python, ["-B", @actor | prepare], stderr_to_stdout: true)

    assert status == 0, output
    path = Path.join([fixture, "socket", "bus"])
    config_file = Path.join(directory, "bus.conf")

    core =
      if tags[:reference] do
        nil
      else
        settings = %{
          profile: :system,
          cluster: false,
          socket_path: path,
          config_file: config_file,
          config_options: [],
          runtime_invocation: %{},
          resource_limits: %{}
        }

        previous =
          Map.new(settings, fn {key, _} -> {key, Application.fetch_env(:gao_bus, key)} end)

        Enum.each(settings, fn {key, value} -> Application.put_env(:gao_bus, key, value) end)

        on_exit(fn ->
          Enum.each(previous, fn
            {key, {:ok, value}} -> Application.put_env(:gao_bus, key, value)
            {key, :error} -> Application.delete_env(:gao_bus, key)
          end)
        end)

        core =
          start_supervised!(%{
            id: :file_reload_socket_core,
            start: {GaoBus.Application, :start, [:normal, []]}
          })

        # The private 0755 directory permits traversal; the system socket permits
        # the independently credentialed ordinary actor to connect, not edit XML.
        assert {:ok, %{mode: mode}} = File.stat(path)
        assert Bitwise.band(mode, 0o777) == 0o666
        core
      end

    %{
      python: python,
      directory: directory,
      path: path,
      config_file: config_file,
      ordinary_uid: ordinary_uid,
      service_uid: service_uid,
      core: core
    }
  end

  test "wire reload enforces caller identity, coherent traffic and invalid-include rollback",
       ctx do
    assert {:ok, 1, original} = Policy.snapshot()
    authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})
    assert Enum.all?(authorities, fn {_module, pid} -> is_pid(pid) end)

    export_snapshot(ctx, "wire-candidate-original", {:ok, 1, original})

    result =
      try do
        run_actor(ctx, ["candidate", ctx.path, ctx.directory, to_string(ctx.ordinary_uid)])
      after
        export_snapshot(ctx, "wire-candidate-retained", Policy.snapshot())
      end

    assert %{
             "backend" => "candidate",
             "valid_reloads" => 9,
             "invalid_reloads" => 2,
             "denied_reloads" => 4,
             "rounds" => 8,
             "expected_generation" => 10,
             "final_phase" => "new"
           } = result

    assert {:ok, 10, retained} = Policy.snapshot()
    refute retained == original
    assert Map.new(@authorities, &{&1, Process.whereis(&1)}) == authorities
  end

  @tag :reference
  test "the same reload wire scenario executes against a private reference daemon", ctx do
    daemon =
      System.get_env("OSBUS_RELOAD_REFERENCE_DAEMON") || System.find_executable("dbus-daemon")

    assert daemon, "BLOCKED_ENV: a pinned reference dbus-daemon is required"

    result = run_actor(ctx, ["reference", daemon, ctx.directory, to_string(ctx.ordinary_uid)])
    assert result["backend"] == "reference"
    assert byte_size(result["daemon_sha256"]) == 64
  end

  @tag :destination_alias
  test "same XML denies every protected-owner alias until its protected name is released", ctx do
    hashes = config_hashes(ctx.directory)
    assert {:ok, 1, original} = Policy.snapshot()
    authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})
    assert Enum.all?(authorities, fn {_module, pid} -> is_pid(pid) end)

    candidate = run_alias_actor(ctx, "alias-candidate", ctx.path, hashes)
    assert config_hashes(ctx.directory) == hashes
    assert {:ok, 1, ^original} = Policy.snapshot()
    assert Map.new(@authorities, &{&1, Process.whereis(&1)}) == authorities

    core_monitor = Process.monitor(ctx.core)
    listener = authorities[GaoBus.Listener]
    listener_monitor = Process.monitor(listener)
    assert :ok = stop_supervised(:file_reload_socket_core)
    assert_receive {:DOWN, ^core_monitor, :process, core, core_reason}, 5_000
    assert core == ctx.core
    assert core_reason == :shutdown
    assert_receive {:DOWN, ^listener_monitor, :process, ^listener, listener_reason}, 5_000
    assert listener_reason == :shutdown
    assert {:error, :enoent} = File.stat(ctx.path)
    assert Enum.all?(@authorities, &(Process.whereis(&1) == nil))
    assert config_hashes(ctx.directory) == hashes

    daemon =
      System.get_env("OSBUS_RELOAD_REFERENCE_DAEMON") || System.find_executable("dbus-daemon")

    assert daemon, "BLOCKED_ENV: a pinned reference dbus-daemon is required"
    reference = run_alias_actor(ctx, "alias-reference", daemon, hashes)
    assert byte_size(reference["daemon_sha256"]) == 64
    assert config_hashes(ctx.directory) == hashes
    assert {:error, :enoent} = File.stat(ctx.path)

    # Compare decision labels; keep each backend's unmodified raw response bodies
    # and actual unique names in its actor evidence.
    matrix = fn result ->
      Enum.map(result["probes"], fn row ->
        Map.take(row, ["phase", "destination_kind", "allowed", "deliveries", "error_name"])
      end)
    end

    assert matrix.(candidate) == matrix.(reference)

    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.write!(
        Path.join(evidence, "destination-alias-pair.json"),
        :json.encode(%{
          "result" => "PASS",
          "scope" => "destination-alias",
          "config_hashes" => hashes,
          "matrix" => matrix.(candidate),
          "candidate_shutdown" => %{
            "core_down_reason" => Atom.to_string(core_reason),
            "listener_down_reason" => Atom.to_string(listener_reason),
            "socket_removed" => true
          }
        })
      )
    end
  end

  @tag :properties_set
  test "advertised Properties.Set rejects read-only Features on the same XML and socket", ctx do
    hashes = config_hashes(ctx.directory)
    original = Policy.snapshot()
    authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})
    candidate = capture_properties_actor(ctx, "properties-candidate", ctx.path)
    candidate_hashes = config_hashes(ctx.directory)
    retained = Policy.snapshot()
    retained_authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})

    # Retain the candidate's actual failure, then execute the reference before
    # asserting either backend's Set contract.
    core_monitor = Process.monitor(ctx.core)
    listener = authorities[GaoBus.Listener]
    listener_monitor = Process.monitor(listener)
    assert :ok = stop_supervised(:file_reload_socket_core)
    assert_receive {:DOWN, ^core_monitor, :process, core, core_reason}, 5_000
    assert core == ctx.core
    assert core_reason == :shutdown
    assert_receive {:DOWN, ^listener_monitor, :process, ^listener, listener_reason}, 5_000
    assert listener_reason == :shutdown
    assert {:error, :enoent} = File.stat(ctx.path)
    assert Enum.all?(@authorities, &(Process.whereis(&1) == nil))

    handoff_hashes = config_hashes(ctx.directory)

    daemon =
      System.get_env("OSBUS_RELOAD_REFERENCE_DAEMON") || System.find_executable("dbus-daemon")

    assert daemon, "BLOCKED_ENV: a pinned reference dbus-daemon is required"
    reference = capture_properties_actor(ctx, "properties-reference", daemon)
    reference_hashes = config_hashes(ctx.directory)
    reference_socket_removed = File.stat(ctx.path) == {:error, :enoent}

    pair = %{
      "result" => "FAIL",
      "scope" => "properties-set",
      "expected_error" => "org.freedesktop.DBus.Error.PropertyReadOnly",
      "config_hashes" => hashes,
      "config_hashes_candidate_after" => candidate_hashes,
      "config_hashes_reference_before" => handoff_hashes,
      "config_hashes_reference_after" => reference_hashes,
      "candidate_policy_unchanged" => retained == original,
      "candidate_authorities_unchanged" => retained_authorities == authorities,
      "candidate" => candidate,
      "reference" => reference,
      "reference_shutdown" => %{"socket_removed" => reference_socket_removed},
      "candidate_shutdown" => %{
        "core_down_reason" => Atom.to_string(core_reason),
        "listener_down_reason" => Atom.to_string(listener_reason),
        "socket_removed" => true
      }
    }

    write_properties_pair(pair)

    try do
      assert_properties_actor(ctx, candidate, "candidate", hashes)
      assert_properties_actor(ctx, reference, "reference", hashes)
      assert {:ok, 1, _} = original
      assert retained == original
      assert retained_authorities == authorities
      assert Enum.all?(authorities, fn {_module, pid} -> is_pid(pid) end)
      assert candidate_hashes == hashes
      assert handoff_hashes == hashes
      assert reference_hashes == hashes
      assert reference_socket_removed
      assert config_hashes(ctx.directory) == hashes
      assert {:error, :enoent} = File.stat(ctx.path)
      write_properties_pair(%{pair | "result" => "PASS"})
    rescue
      failure ->
        write_properties_pair(Map.put(pair, "assertion_error", Exception.message(failure)))
        reraise failure, __STACKTRACE__
    end
  end

  @tag :properties_get_all
  test "Properties.GetAll matches prior Gets and distinguishes known and unknown interfaces",
       ctx do
    hashes = config_hashes(ctx.directory)
    original = Policy.snapshot()
    authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})
    candidate = capture_properties_actor(ctx, "getall-candidate", ctx.path)
    candidate_hashes = config_hashes(ctx.directory)
    retained = Policy.snapshot()
    retained_authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})

    # Preserve both actual backend outcomes before asserting the GetAll contract.
    core_monitor = Process.monitor(ctx.core)
    listener = authorities[GaoBus.Listener]
    listener_monitor = Process.monitor(listener)
    assert :ok = stop_supervised(:file_reload_socket_core)
    assert_receive {:DOWN, ^core_monitor, :process, core, core_reason}, 5_000
    assert core == ctx.core
    assert core_reason == :shutdown
    assert_receive {:DOWN, ^listener_monitor, :process, ^listener, listener_reason}, 5_000
    assert listener_reason == :shutdown
    assert {:error, :enoent} = File.stat(ctx.path)
    assert Enum.all?(@authorities, &(Process.whereis(&1) == nil))

    handoff_hashes = config_hashes(ctx.directory)

    daemon =
      System.get_env("OSBUS_RELOAD_REFERENCE_DAEMON") || System.find_executable("dbus-daemon")

    assert daemon, "BLOCKED_ENV: a pinned reference dbus-daemon is required"
    reference = capture_properties_actor(ctx, "getall-reference", daemon)
    reference_hashes = config_hashes(ctx.directory)
    reference_socket_removed = File.stat(ctx.path) == {:error, :enoent}

    pair = %{
      "result" => "FAIL",
      "scope" => "properties-get-all",
      "expected_error" => "org.freedesktop.DBus.Error.UnknownInterface",
      "config_hashes" => hashes,
      "config_hashes_candidate_after" => candidate_hashes,
      "config_hashes_reference_before" => handoff_hashes,
      "config_hashes_reference_after" => reference_hashes,
      "candidate_policy_unchanged" => retained == original,
      "candidate_authorities_unchanged" => retained_authorities == authorities,
      "candidate" => candidate,
      "reference" => reference,
      "reference_shutdown" => %{"socket_removed" => reference_socket_removed},
      "candidate_shutdown" => %{
        "core_down_reason" => Atom.to_string(core_reason),
        "listener_down_reason" => Atom.to_string(listener_reason),
        "socket_removed" => true
      }
    }

    write_get_all_pair(pair)

    try do
      assert_get_all_actor(ctx, candidate, "candidate", hashes)
      assert_get_all_actor(ctx, reference, "reference", hashes)
      assert {:ok, 1, _} = original
      assert retained == original
      assert retained_authorities == authorities
      assert Enum.all?(authorities, fn {_module, pid} -> is_pid(pid) end)
      assert candidate_hashes == hashes
      assert handoff_hashes == hashes
      assert reference_hashes == hashes
      assert reference_socket_removed
      assert config_hashes(ctx.directory) == hashes
      assert {:error, :enoent} = File.stat(ctx.path)
      write_get_all_pair(%{pair | "result" => "PASS"})
    rescue
      failure ->
        write_get_all_pair(Map.put(pair, "assertion_error", Exception.message(failure)))
        reraise failure, __STACKTRACE__
    end
  end

  @tag :api_dispatch
  test "paired API dispatch, complete introspection and negative contracts",
       ctx do
    hashes = config_hashes(ctx.directory)
    original = Policy.snapshot()
    original_snapshot = export_snapshot(ctx, "api-candidate-original", original)
    authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})
    candidate = capture_properties_actor(ctx, "api-candidate", ctx.path)
    candidate_hashes = config_hashes(ctx.directory)
    retained = Policy.snapshot()
    retained_snapshot = export_snapshot(ctx, "api-candidate-retained", retained)
    retained_authorities = Map.new(@authorities, &{&1, Process.whereis(&1)})

    # Preserve both actual backend outcomes before asserting the API contract.
    core_monitor = Process.monitor(ctx.core)
    listener = authorities[GaoBus.Listener]
    listener_monitor = Process.monitor(listener)
    assert :ok = stop_supervised(:file_reload_socket_core)
    assert_receive {:DOWN, ^core_monitor, :process, core, core_reason}, 5_000
    assert core == ctx.core
    assert core_reason == :shutdown
    assert_receive {:DOWN, ^listener_monitor, :process, ^listener, listener_reason}, 5_000
    assert listener_reason == :shutdown
    assert {:error, :enoent} = File.stat(ctx.path)
    assert Enum.all?(@authorities, &(Process.whereis(&1) == nil))

    handoff_hashes = config_hashes(ctx.directory)

    daemon =
      System.get_env("OSBUS_RELOAD_REFERENCE_DAEMON") || System.find_executable("dbus-daemon")

    assert daemon, "BLOCKED_ENV: a pinned reference dbus-daemon is required"
    reference = capture_properties_actor(ctx, "api-reference", daemon)
    reference_hashes = config_hashes(ctx.directory)
    reference_socket_removed = File.stat(ctx.path) == {:error, :enoent}

    pair = %{
      "result" => "FAIL",
      "scope" => "api-dispatch",
      "config_hashes" => hashes,
      "config_hashes_candidate_after" => candidate_hashes,
      "config_hashes_reference_before" => handoff_hashes,
      "config_hashes_reference_after" => reference_hashes,
      "candidate_policy_snapshots" => %{
        "original" => Map.drop(original_snapshot, ["term_base64"]),
        "retained" => Map.drop(retained_snapshot, ["term_base64"])
      },
      "candidate_policy_coherent" =>
        match?({{:ok, 1, rules}, {:ok, 2, rules}}, {original, retained}),
      "candidate_policy_generation_before" => elem(original, 1),
      "candidate_policy_generation_after" => elem(retained, 1),
      "candidate_authorities_unchanged" => retained_authorities == authorities,
      "candidate" => candidate,
      "reference" => reference,
      "reference_shutdown" => %{"socket_removed" => reference_socket_removed},
      "candidate_shutdown" => %{
        "core_down_reason" => Atom.to_string(core_reason),
        "listener_down_reason" => Atom.to_string(listener_reason),
        "socket_removed" => true
      }
    }

    write_api_pair(pair)

    try do
      assert_api_actor(ctx, candidate, "candidate", hashes)
      assert_api_actor(ctx, reference, "reference", hashes)
      assert {:ok, 1, _} = original
      assert {:ok, 1, rules} = original
      assert retained == {:ok, 2, rules}
      assert retained_authorities == authorities
      assert Enum.all?(authorities, fn {_module, pid} -> is_pid(pid) end)
      assert candidate_hashes == hashes
      assert handoff_hashes == hashes
      assert reference_hashes == hashes
      assert reference_socket_removed
      assert config_hashes(ctx.directory) == hashes
      assert {:error, :enoent} = File.stat(ctx.path)
      write_api_pair(%{pair | "result" => "PASS"})
    rescue
      failure ->
        write_api_pair(Map.put(pair, "assertion_error", Exception.message(failure)))
        reraise failure, __STACKTRACE__
    end
  end

  defp write_api_pair(pair) do
    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.write!(Path.join(evidence, "api-dispatch-pair.json"), :json.encode(pair))
    end
  end

  defp assert_api_actor(ctx, captured, backend, hashes) do
    result = captured["report"]
    assert is_map(result), inspect(captured)
    assert captured["exit_status"] == 0, inspect(result["contract_failures"])
    assert result["result"] == "PASS"
    assert result["backend"] == backend
    assert result["scope"] == "api-dispatch"
    assert result["readiness"] == "L0"
    assert result["installed_profile_qualified"] == false
    assert result["contract_failures"] == []
    assert result["config_hashes_before"] == hashes
    assert result["config_hashes_after"] == hashes

    selection =
      :json.decode(File.read!(Path.expand("../fixtures/api_contract_selection.json", __DIR__)))

    assert selection["total_count"] == 234
    assert result["operation_count"] == 234

    for {key, count} <- [{"api", 212}, {"api_root", 22}] do
      api = result[key]
      expected = selection["backends"][backend][key]
      assert api["contract_failures"] == []
      assert length(api["rows"]) == api["operation_count"] and api["operation_count"] == count
      assert api["operation_labels"] == Enum.map(expected, & &1["label"])
      assert Enum.map(api["rows"], &Map.take(&1, Map.keys(hd(expected)))) == expected
      assert Enum.all?(api["rows"], &(&1["result"] == "PASS"))
    end

    api = result["api"]
    assert result["bus_ids_before"] == result["bus_ids_after"]
    assert api["bus_id"] == result["bus_id"]
    identities = Map.new(result["identities"], &{&1["actor"], &1})
    assert Enum.sort(Map.keys(identities)) == ["caller", "observer"]

    for {actor, uid} <- [{"caller", ctx.ordinary_uid}, {"observer", 0}] do
      identity = identities[actor]
      assert identity["uid"] == identity["bus_uid"] and identity["uid"] == uid
      assert identity["pid"] == identity["bus_pid"] and identity["pid"] > 0
    end

    assert identities["caller"]["gid"] == ctx.ordinary_uid
    assert identities["caller"]["groups"] == []

    assert identities["caller"]["file_write_denials"] == %{
             "bus.conf" => 13,
             "policy.conf" => 13,
             "rules.conf" => 13
           }

    assert result["cleanup"]["root_sockets_closed"]
    assert [worker] = result["cleanup"]["workers"]
    assert worker["normal_stop"] and worker["socket_closed_receipt"]
    assert worker["exitcode"] == 0
    assert worker["actor"] == "caller" and worker["pid"] == identities["caller"]["pid"]
    receipt = worker["socket_closed_receipt"]

    assert Map.take(receipt, ["actor", "pid", "uid", "name"]) ==
             Map.take(identities["caller"], ["actor", "pid", "uid", "name"])

    assert receipt["closed"] == true and receipt["failed"] == false
    refute worker["terminate"] or worker["kill"]

    if backend == "reference" do
      daemon = result["cleanup"]["daemon"]
      assert daemon["normal_stop"] == true and daemon["terminate"] == true
      assert daemon["kill"] == false and daemon["exitcode"] in [0, -15]

      executable =
        System.get_env("OSBUS_RELOAD_REFERENCE_DAEMON") || System.find_executable("dbus-daemon")

      assert result["daemon_sha256"] ==
               Base.encode16(:crypto.hash(:sha256, File.read!(executable)), case: :lower)
    end
  end

  defp write_get_all_pair(pair) do
    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.write!(Path.join(evidence, "properties-get-all-pair.json"), :json.encode(pair))
    end
  end

  defp assert_get_all_actor(ctx, captured, backend, hashes) do
    result = captured["report"]
    assert is_map(result), inspect(captured)
    assert result["backend"] == backend
    assert result["scope"] == "properties-get-all"
    properties = result["properties"]
    expected_error = "org.freedesktop.DBus.Error.UnknownInterface"
    assert properties["unknown_interface_actual_error"] == expected_error
    assert properties["unknown_interface_expected_error"] == expected_error
    assert captured["exit_status"] == 0
    assert result["result"] == "PASS"
    assert result["contract_failures"] == []
    assert properties["contract_failures"] == []
    assert result["readiness"] == "L0"
    assert result["installed_profile_qualified"] == false
    assert result["config_hashes_before"] == hashes
    assert result["config_hashes_after"] == hashes

    identities = Map.new(result["identities"], &{&1["actor"], &1})
    assert Enum.sort(Map.keys(identities)) == ["caller", "observer"]

    for {actor, uid} <- [{"caller", ctx.ordinary_uid}, {"observer", 0}] do
      identity = identities[actor]
      assert identity["uid"] == uid
      assert identity["bus_uid"] == uid
      assert is_integer(identity["pid"]) and identity["pid"] > 0
      assert identity["bus_pid"] == identity["pid"]
      assert String.starts_with?(identity["name"], ":")
    end

    caller = identities["caller"]
    observer = identities["observer"]
    refute caller["pid"] == observer["pid"]
    refute caller["name"] == observer["name"]
    assert caller["gid"] == ctx.ordinary_uid
    assert caller["groups"] == []

    assert caller["file_write_denials"] == %{
             "bus.conf" => 13,
             "policy.conf" => 13,
             "rules.conf" => 13
           }

    calls =
      Enum.filter(result["trace"], fn item ->
        item["event"] == "call" and item["actor"] == "caller"
      end)

    assert [features, interfaces, bus, peer, unknown, get_id] = calls
    bus_name = "org.freedesktop.DBus"
    properties_interface = bus_name <> ".Properties"
    string_body = fn value -> Base.decode16!(string_body_hex(value), case: :lower) end

    get_body = fn property ->
      interface = string_body.(bus_name)

      interface <>
        :binary.copy(<<0>>, Integer.mod(-byte_size(interface), 4)) <>
        string_body.(property)
    end

    for {call, member, interface, signature, body} <- [
          {features, "Get", properties_interface, "ss", get_body.("Features")},
          {interfaces, "Get", properties_interface, "ss", get_body.("Interfaces")},
          {bus, "GetAll", properties_interface, "s", string_body.(bus_name)},
          {peer, "GetAll", properties_interface, "s", string_body.(bus_name <> ".Peer")},
          {unknown, "GetAll", properties_interface, "s",
           string_body.("org.foundation.UnknownInterface")},
          {get_id, "GetId", bus_name, "", <<>>}
        ] do
      assert call["member"] == member
      assert call["interface"] == interface
      assert call["destination"] == bus_name
      assert call["signature"] == signature
      assert call["body_hex"] == Base.encode16(body, case: :lower)
    end

    for property <- ["features", "interfaces"] do
      assert is_list(properties[property])
      assert Enum.all?(properties[property], &is_binary/1)
    end

    assert properties["bus_properties"] == %{
             "Features" => %{"signature" => "as", "value" => properties["features"]},
             "Interfaces" => %{"signature" => "as", "value" => properties["interfaces"]}
           }

    assert properties["peer_properties"] == %{}
    assert properties["consistent"] == true

    for {message, call, type, signature} <- [
          {properties["features_response"], features, 2, "v"},
          {properties["interfaces_response"], interfaces, 2, "v"},
          {properties["bus_response"], bus, 2, "a{sv}"},
          {properties["peer_response"], peer, 2, "a{sv}"},
          {properties["unknown_interface_response"], unknown, 3, "s"},
          {properties["get_id_response"], get_id, 2, "s"}
        ] do
      assert_raw_message(message)
      assert message["serial"] > 0
      assert message["type"] == type
      assert message["fields"]["5"] == call["serial"]
      assert message["fields"]["6"] == caller["name"]
      assert message["fields"]["7"] == bus_name
      assert message["fields"]["8"] == signature
    end

    assert properties["unknown_interface_response"]["fields"]["4"] == expected_error

    assert properties["unknown_interface_response"]["body_hex"] ==
             string_body_hex(properties["unknown_interface_error_body"])

    assert is_binary(result["bus_id"]) and byte_size(result["bus_id"]) == 32
    assert result["bus_ids_before"] == result["bus_id"]
    assert result["bus_ids_after"] == result["bus_id"]
    assert properties["bus_id"] == result["bus_id"]
    assert properties["get_id_response"]["body_hex"] == string_body_hex(result["bus_id"])
    assert result["cleanup"]["root_sockets_closed"] == true
    assert [worker] = result["cleanup"]["workers"]
    assert worker["actor"] == "caller"
    assert worker["pid"] == caller["pid"]
    assert worker["exitcode"] == 0
    assert worker["normal_stop"] == true
    assert worker["terminate"] == false
    assert worker["kill"] == false
    receipt = worker["socket_closed_receipt"]
    assert receipt["event"] == "socket-closed"
    assert receipt["actor"] == "caller"
    assert receipt["pid"] == caller["pid"]
    assert receipt["uid"] == caller["uid"]
    assert receipt["name"] == caller["name"]
    assert receipt["closed"] == true

    if backend == "reference" do
      assert byte_size(result["daemon_sha256"]) == 64
      daemon = result["cleanup"]["daemon"]
      assert is_integer(daemon["pid"]) and daemon["pid"] > 0
      assert daemon["normal_stop"] == true
      assert daemon["terminate"] == true
      assert daemon["kill"] == false
      assert daemon["exitcode"] in [0, -15]
    end
  end

  defp capture_properties_actor(ctx, mode, endpoint) do
    args = [mode, endpoint, ctx.directory, to_string(ctx.ordinary_uid)]
    {output, status} = System.cmd(ctx.python, ["-B", @actor | args], stderr_to_stdout: true)
    IO.puts(output)

    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.mkdir_p!(evidence)
      File.write!(Path.join(evidence, "#{mode}-actor.log"), output)
      File.write!(Path.join(evidence, "#{mode}-actor.json"), output)

      File.write!(
        Path.join(evidence, "#{mode}-actor.status.json"),
        :json.encode(%{"exit_status" => status})
      )
    end

    try do
      %{"exit_status" => status, "report" => :json.decode(String.trim(output))}
    rescue
      failure ->
        %{
          "exit_status" => status,
          "report" => :null,
          "decode_error" => Exception.message(failure)
        }
    end
  end

  defp write_properties_pair(pair) do
    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.write!(Path.join(evidence, "properties-set-pair.json"), :json.encode(pair))
    end
  end

  defp assert_properties_actor(ctx, captured, backend, hashes) do
    result = captured["report"]
    assert is_map(result), inspect(captured)
    assert result["backend"] == backend
    assert result["scope"] == "properties-set"
    properties = result["properties"]
    expected_error = "org.freedesktop.DBus.Error.PropertyReadOnly"
    assert properties["set_actual_error"] == expected_error
    assert properties["set_expected_error"] == expected_error
    assert captured["exit_status"] == 0
    assert result["result"] == "PASS"
    assert result["contract_failures"] == []
    assert properties["contract_failures"] == []
    assert result["readiness"] == "L0"
    assert result["installed_profile_qualified"] == false
    assert result["config_hashes_before"] == hashes
    assert result["config_hashes_after"] == hashes

    identities = Map.new(result["identities"], &{&1["actor"], &1})
    assert Enum.sort(Map.keys(identities)) == ["caller", "observer"]

    for {actor, uid} <- [{"caller", ctx.ordinary_uid}, {"observer", 0}] do
      identity = identities[actor]
      assert identity["uid"] == uid
      assert identity["bus_uid"] == uid
      assert is_integer(identity["pid"]) and identity["pid"] > 0
      assert identity["bus_pid"] == identity["pid"]
      assert String.starts_with?(identity["name"], ":")
    end

    caller = identities["caller"]
    observer = identities["observer"]
    refute caller["pid"] == observer["pid"]
    refute caller["name"] == observer["name"]
    assert caller["gid"] == ctx.ordinary_uid
    assert caller["groups"] == []

    assert caller["file_write_denials"] == %{
             "bus.conf" => 13,
             "policy.conf" => 13,
             "rules.conf" => 13
           }

    calls =
      Enum.filter(result["trace"], fn item ->
        item["event"] == "call" and item["actor"] == "caller"
      end)

    assert [introspect, before_get, set, after_get, get_id] = calls

    for {call, member, interface} <- [
          {introspect, "Introspect", "org.freedesktop.DBus.Introspectable"},
          {before_get, "Get", "org.freedesktop.DBus.Properties"},
          {set, "Set", "org.freedesktop.DBus.Properties"},
          {after_get, "Get", "org.freedesktop.DBus.Properties"},
          {get_id, "GetId", "org.freedesktop.DBus"}
        ] do
      assert call["member"] == member
      assert call["interface"] == interface
      assert call["destination"] == "org.freedesktop.DBus"
    end

    string_body = fn value -> Base.decode16!(string_body_hex(value), case: :lower) end
    bus_body = string_body.("org.freedesktop.DBus")

    get_body =
      bus_body <>
        :binary.copy(<<0>>, Integer.mod(-byte_size(bus_body), 4)) <>
        string_body.("Features")

    for call <- [before_get, after_get] do
      assert call["signature"] == "ss"
      assert call["body_hex"] == Base.encode16(get_body, case: :lower)
    end

    assert set["signature"] == "ssv"
    assert properties["set_request"] == set
    sentinel = "foundation-property-set-sentinel"
    sentinel_body = string_body.(sentinel)
    variant = get_body <> <<2, "as", 0>>

    set_body =
      variant <>
        :binary.copy(<<0>>, Integer.mod(-byte_size(variant), 4)) <>
        <<byte_size(sentinel_body)::little-unsigned-integer-size(32)>> <> sentinel_body

    assert set["body_hex"] == Base.encode16(set_body, case: :lower)
    assert properties["set_advertised"] == true
    assert properties["unchanged"] == true
    assert is_list(properties["features_before"])
    assert Enum.all?(properties["features_before"], &is_binary/1)
    assert properties["features_after"] == properties["features_before"]
    refute sentinel in properties["features_after"]

    assert properties["features_after_response"]["body_hex"] ==
             properties["features_before_response"]["body_hex"]

    for {message, call, type, signature} <- [
          {properties["introspection_response"], introspect, 2, "s"},
          {properties["features_before_response"], before_get, 2, "v"},
          {properties["set_response"], set, 3, "s"},
          {properties["features_after_response"], after_get, 2, "v"},
          {properties["get_id_response"], get_id, 2, "s"}
        ] do
      assert_raw_message(message)
      assert message["serial"] > 0
      assert message["type"] == type
      assert message["fields"]["5"] == call["serial"]
      assert message["fields"]["6"] == caller["name"]
      assert message["fields"]["7"] == "org.freedesktop.DBus"
      assert message["fields"]["8"] == signature
    end

    assert properties["set_response"]["fields"]["4"] == expected_error
    assert is_binary(result["bus_id"]) and byte_size(result["bus_id"]) == 32
    assert result["bus_ids_before"] == result["bus_id"]
    assert result["bus_ids_after"] == result["bus_id"]
    assert properties["bus_id"] == result["bus_id"]
    assert properties["get_id_response"]["body_hex"] == string_body_hex(result["bus_id"])
    assert result["cleanup"]["root_sockets_closed"] == true
    assert [worker] = result["cleanup"]["workers"]
    assert worker["actor"] == "caller"
    assert worker["pid"] == caller["pid"]
    assert worker["exitcode"] == 0
    assert worker["normal_stop"] == true
    assert worker["terminate"] == false
    assert worker["kill"] == false
    receipt = worker["socket_closed_receipt"]
    assert receipt["event"] == "socket-closed"
    assert receipt["actor"] == "caller"
    assert receipt["pid"] == caller["pid"]
    assert receipt["uid"] == caller["uid"]
    assert receipt["name"] == caller["name"]
    assert receipt["closed"] == true

    if backend == "reference" do
      assert byte_size(result["daemon_sha256"]) == 64
      daemon = result["cleanup"]["daemon"]
      assert is_integer(daemon["pid"]) and daemon["pid"] > 0
      assert daemon["normal_stop"] == true
      assert daemon["terminate"] == true
      assert daemon["kill"] == false
      assert daemon["exitcode"] in [0, -15]
    end
  end

  defp config_hashes(directory) do
    Map.new(["bus.conf", "policy.conf", "rules.conf"], fn filename ->
      hash = :crypto.hash(:sha256, File.read!(Path.join(directory, filename)))
      {filename, Base.encode16(hash, case: :lower)}
    end)
  end

  defp run_alias_actor(ctx, mode, endpoint, hashes) do
    args = [
      mode,
      endpoint,
      ctx.directory,
      to_string(ctx.ordinary_uid),
      to_string(ctx.service_uid)
    ]

    {output, status} = System.cmd(ctx.python, ["-B", @actor | args], stderr_to_stdout: true)
    IO.puts(output)

    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.mkdir_p!(evidence)
      File.write!(Path.join(evidence, "#{mode}-actor.log"), output)
      File.write!(Path.join(evidence, "#{mode}-actor.json"), output)
    end

    assert status == 0, output

    assert %{"result" => "PASS", "scope" => "destination-alias"} =
             result = :json.decode(String.trim(output))

    assert result["backend"] == String.replace_prefix(mode, "alias-", "")
    assert result["readiness"] == "L0"
    assert result["installed_profile_qualified"] == false

    for phase <- ["before", "release", "after"] do
      assert result["config_hashes_#{phase}"] == hashes
    end

    identities = Map.new(result["identities"], &{&1["actor"], &1})
    assert Enum.sort(Map.keys(identities)) == ["caller", "observer", "service"]

    for {actor, uid} <- [
          {"observer", 0},
          {"caller", ctx.ordinary_uid},
          {"service", ctx.service_uid}
        ] do
      identity = identities[actor]
      assert identity["uid"] == uid
      assert identity["bus_uid"] == uid
      assert is_integer(identity["pid"]) and identity["pid"] > 0
      assert identity["bus_pid"] == identity["pid"]
      assert is_integer(identity["gid"])
      assert is_list(identity["groups"])
      assert Enum.all?(identity["groups"], &is_integer/1)
      assert String.starts_with?(identity["name"], ":")

      if actor != "observer" do
        assert identity["gid"] == uid
        assert identity["groups"] == []

        assert identity["file_write_denials"] == %{
                 "bus.conf" => 13,
                 "policy.conf" => 13,
                 "rules.conf" => 13
               }
      end
    end

    assert length(Enum.uniq(Enum.map(result["identities"], & &1["name"]))) == 3
    assert length(Enum.uniq(Enum.map(result["identities"], & &1["pid"]))) == 3
    service = identities["service"]["name"]
    caller = identities["caller"]["name"]
    protected = "org.foundation.Reload.Protected"
    alternate = "org.foundation.Reload.Alternate"

    assert %{
             "protected_request" => 1,
             "alternate_request" => 1,
             "protected_owner" => ^service,
             "alternate_owner" => ^service,
             "protected_release" => 1,
             "protected_after_error" => "org.freedesktop.DBus.Error.NameHasNoOwner",
             "alternate_after_owner" => ^service
           } = result["ownership"]

    expected = [
      {"protected-owned", "protected", protected, false},
      {"protected-owned", "unique", service, false},
      {"protected-owned", "alternate", alternate, false},
      {"protected-released", "unique", service, true},
      {"protected-released", "alternate", alternate, true}
    ]

    assert length(result["probes"]) == 5

    for {row, {phase, kind, destination, allowed}} <- Enum.zip(result["probes"], expected) do
      assert row["phase"] == phase
      assert row["destination_kind"] == kind
      assert row["destination"] == destination
      assert row["allowed"] == allowed
      count = if allowed, do: 1, else: 0
      assert row["deliveries"] == count
      assert length(row["requests"]) == count
      assert is_integer(row["caller_serial"])
      assert is_binary(row["marker"]) and byte_size(row["marker"]) > 0
      marker = string_body_hex(row["marker"])
      response = row["response"]
      assert_raw_message(response)
      assert response["fields"]["5"] == row["caller_serial"]
      assert response["fields"]["6"] == caller

      if allowed do
        assert row["error_name"] == :null
        assert response["type"] == 2
        assert response["fields"]["7"] == service
        assert response["fields"]["8"] == "s"
        assert response["body_hex"] == marker
        [request] = row["requests"]
        assert_raw_message(request)
        assert request["type"] == 1
        assert request["serial"] == row["caller_serial"]
        assert request["fields"]["6"] == destination
        assert request["fields"]["7"] == caller
        assert request["body_hex"] == marker
      else
        assert row["error_name"] == "org.freedesktop.DBus.Error.AccessDenied"
        assert response["type"] == 3
        assert response["fields"]["4"] == row["error_name"]
        assert response["fields"]["7"] == "org.freedesktop.DBus"
      end

      assert length(row["fences"]) == 2

      for fence <- row["fences"] do
        assert_raw_message(fence)
        assert fence["type"] == 2
        assert fence["fields"]["8"] == "s"
        assert fence["body_hex"] == string_body_hex(result["bus_id"])
      end
    end

    assert is_binary(result["bus_id"]) and byte_size(result["bus_id"]) == 32

    for phase <- ["before", "release", "after"] do
      assert result["bus_ids_#{phase}"] == result["bus_id"]
    end

    assert result["cleanup"]["root_sockets_closed"] == true
    workers = result["cleanup"]["workers"]
    assert Enum.sort(Enum.map(workers, & &1["actor"])) == ["caller", "service"]

    for worker <- workers do
      assert worker["pid"] == identities[worker["actor"]]["pid"]
      assert worker["exitcode"] == 0
      assert worker["normal_stop"] == true
      assert worker["terminate"] == false
      assert worker["kill"] == false
      receipt = worker["socket_closed_receipt"]
      assert receipt["event"] == "socket-closed"
      assert receipt["actor"] == worker["actor"]
      assert receipt["pid"] == worker["pid"]
      assert receipt["name"] == identities[worker["actor"]]["name"]
      assert receipt["uid"] == identities[worker["actor"]]["uid"]
      assert receipt["closed"] == true
    end

    if mode == "alias-reference" do
      daemon = result["cleanup"]["daemon"]
      assert is_integer(daemon["pid"]) and daemon["pid"] > 0
      assert daemon["normal_stop"] == true
      assert daemon["terminate"] == true
      assert daemon["kill"] == false
      assert daemon["exitcode"] in [0, -15]
    end

    assert is_list(result["trace"]) and length(result["trace"]) > 0
    result
  end

  defp string_body_hex(value) do
    Base.encode16(<<byte_size(value)::little-unsigned-integer-size(32), value::binary, 0>>,
      case: :lower
    )
  end

  defp assert_raw_message(message) do
    assert is_integer(message["type"])
    assert is_integer(message["flags"])
    assert is_integer(message["serial"])
    assert is_map(message["fields"])
    assert is_binary(message["body_hex"])
    assert is_binary(message["wire_hex"])
    assert byte_size(message["wire_hex"]) >= 32
    assert String.ends_with?(message["wire_hex"], message["body_hex"])
    assert message["rights"] == 0
  end

  defp snapshot_record(ctx, label, term) do
    binary = :erlang.term_to_binary(term)

    %{
      "schema" => 1,
      "scope" => "complete-policy-snapshot-diagnostic",
      "readiness" => "L0",
      "installed_profile_qualified" => false,
      "artifact" => label <> ".snapshot.json",
      "label" => label,
      "encoding" => "erlang-external-term/base64",
      "term_base64" => Base.encode64(binary),
      "term_bytes" => byte_size(binary),
      "term_sha256" => Base.encode16(:crypto.hash(:sha256, binary), case: :lower),
      "generation" =>
        case term do
          {:ok, generation, _} when is_integer(generation) -> generation
          _ -> :null
        end,
      "config_file" => ctx.config_file,
      "socket_path" => ctx.path,
      "current_config_hashes" => config_hashes(ctx.directory),
      "test_source_sha256" =>
        Base.encode16(:crypto.hash(:sha256, File.read!(@source)), case: :lower),
      "actor_source_sha256" =>
        Base.encode16(:crypto.hash(:sha256, File.read!(@actor)), case: :lower)
    }
  end

  defp export_snapshot(ctx, label, term, details \\ %{}) do
    record = Map.merge(snapshot_record(ctx, label, term), details)

    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.mkdir_p!(evidence)
      File.write!(Path.join(evidence, label <> ".snapshot.json"), :json.encode(record))
    else
      IO.puts(:json.encode(record))
    end

    record
  end

  defp capture_actor_lines(ctx, lines, output, baseline, rows, port) do
    Enum.reduce(lines, {output, baseline, rows}, fn line, {output, baseline, rows} ->
      request =
        try do
          :json.decode(line)
        rescue
          _ -> nil
        end

      if is_map(request) and request["event"] == "snapshot-checkpoint" do
        expected = [
          "denied-before-first-success",
          "denied-after-first-success",
          "last-successful-reload",
          "malformed-xml-rejected",
          "malformed-xml-denied",
          "rules-restored-before-missing-include",
          "missing-include-rejected",
          "missing-include-denied",
          "policy-restored",
          "rules-restored-final"
        ]

        assert request["label"] == Enum.at(expected, length(rows))
        assert request["request_id"] == length(rows) + 1
        term = Policy.snapshot()
        retained = if baseline == nil, do: :null, else: term == baseline

        record =
          export_snapshot(ctx, "wire-candidate-" <> request["label"], term, %{
            "request_id" => request["request_id"],
            "expected_generation" => request["expected_generation"],
            "retained_equals_last_successful" => retained
          })

        rows = [Map.drop(record, ["term_base64"]) | rows]

        if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
          File.write!(
            Path.join(evidence, "wire-candidate-checkpoints.json"),
            :json.encode(%{
              "schema" => 1,
              "selected" => 10,
              "captured" => length(rows),
              "checkpoints" => Enum.reverse(rows)
            })
          )
        end

        assert record["generation"] == request["expected_generation"]

        if request["label"] == "last-successful-reload" do
          assert {:ok, 10, published} = term
          assert {:ok, config} = Config.load(ctx.config_file, daemon_uid: 0)
          compiled = Policy.compile(config)
          export_snapshot(ctx, "wire-candidate-fresh-compile", compiled)
          assert {:ok, ^published} = compiled
        end

        if baseline != nil, do: assert(term == baseline)

        acknowledgement = %{
          "event" => "snapshot-captured",
          "label" => request["label"],
          "request_id" => request["request_id"],
          "generation" => record["generation"],
          "term_sha256" => record["term_sha256"]
        }

        assert Port.command(port, [:json.encode(acknowledgement), "\n"])
        baseline = if request["label"] == "last-successful-reload", do: term, else: baseline
        {output, baseline, rows}
      else
        {[[line, "\n"] | output], baseline, rows}
      end
    end)
  end

  defp receive_actor(ctx, port, deadline, buffer \\ "", output \\ [], baseline \\ nil, rows \\ []) do
    remaining = max(0, deadline - System.monotonic_time(:millisecond))

    receive do
      {^port, {:data, data}} ->
        parts = :binary.split(buffer <> data, "\n", [:global])
        {lines, [buffer]} = Enum.split(parts, -1)
        {output, baseline, rows} = capture_actor_lines(ctx, lines, output, baseline, rows, port)
        receive_actor(ctx, port, deadline, buffer, output, baseline, rows)

      {^port, {:exit_status, status}} ->
        assert Policy.snapshot() == baseline
        {IO.iodata_to_binary([Enum.reverse(output), buffer]), status, Enum.reverse(rows)}
    after
      remaining -> flunk("snapshot diagnostic actor bounded execution deadline")
    end
  end

  defp run_checkpoint_actor(ctx, args) do
    port =
      Port.open({:spawn_executable, ctx.python}, [
        :binary,
        :exit_status,
        :use_stdio,
        :stderr_to_stdout,
        args: ["-B", @actor | args ++ ["--snapshot-checkpoints"]]
      ])

    try do
      receive_actor(ctx, port, System.monotonic_time(:millisecond) + 120_000)
    after
      if Port.info(port) != nil, do: Port.close(port)
    end
  end

  defp run_actor(ctx, args) do
    [backend | _] = args

    {output, status, checkpoints} =
      if backend == "candidate" do
        run_checkpoint_actor(ctx, args)
      else
        {output, status} = System.cmd(ctx.python, ["-B", @actor | args], stderr_to_stdout: true)
        {output, status, []}
      end

    IO.puts(output)

    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.mkdir_p!(evidence)
      File.write!(Path.join(evidence, "#{backend}-actor.log"), output)
    end

    assert status == 0, output
    assert %{"result" => "PASS"} = result = :json.decode(String.trim(output))

    if evidence = System.get_env("OSBUS_RELOAD_EVIDENCE_DIRECTORY") do
      File.write!(Path.join(evidence, "#{backend}-actor.json"), output)
    end

    identities = result["identities"]
    assert %{"uid" => 0} = Enum.find(identities, &(&1["actor"] == "authorized"))
    assert %{"uid" => uid} = Enum.find(identities, &(&1["actor"] == "ordinary"))
    assert uid == ctx.ordinary_uid
    assert result["counts"]["call"] > 0
    assert result["counts"]["receive"] > 0
    assert result["counts"]["publication"] == 8
    assert result["counts"]["rollback"] == 2

    if backend == "candidate" do
      assert length(checkpoints) == 10
      assert result["counts"]["snapshot-checkpoint"] == 10
    end

    assert result["rollback_errors"] == %{
             "malformed-xml" => "org.freedesktop.DBus.Error.Failed",
             "missing-include" => "org.freedesktop.DBus.Error.FileNotFound"
           }

    assert result["error_name_delta"] == %{}
    assert result["exact_error_equivalence"] == true
    assert result["exact_error_equivalence_scope"] == ["malformed-xml", "missing-include"]
    assert result["installed_profile_qualified"] == false
    result
  end
end
