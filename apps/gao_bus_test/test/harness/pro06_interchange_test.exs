defmodule GaoBusTest.E2E.PRO06InterchangeTest do
  use ExUnit.Case, async: false

  alias GaoBusTest.E2E.{ChildProcess, Qualification}

  @moduletag :e2e
  @moduletag :tmp_dir
  @id "PRO-06-normal-interchange"
  @actors [:independent_service, :independent_client, :external_observer]

  for backend <- ["reference", "gao_bus"] do
    @tag timeout: 100_000
    test "PRO-06 normal nested interchange on #{backend}", %{tmp_dir: tmp_dir} do
      run_backend(unquote(backend), tmp_dir)
    end
  end

  defp run_backend(backend, tmp_dir) do
    assert File.read!("/etc/osbus-security-guest") == "isolated-vm\n"
    assert System.version() == "1.17.3"
    assert to_string(:erlang.system_info(:otp_release)) == "27"
    assert File.lstat!("/etc/osbus-security-guest").uid == 0
    assert ChildProcess.available?()
    bindings = System.fetch_env!("PRO06_BINDINGS") |> File.read!() |> Jason.decode!()
    assert bindings["profile"] == "core"
    refute bindings["installed_policy_qualified"]
    Enum.each(bindings["inputs"], fn {path, sha} -> assert digest(File.read!(path)) == sha end)
    assert bindings["actor"] in Map.keys(bindings["inputs"])
    assert ChildProcess.guard_path() in Map.keys(bindings["inputs"])

    assert File.regular?(
             Path.join(bindings["tree"], "support/e2e/fixtures/h04_system_daemon.exs")
           )

    artifacts = Path.join(File.cwd!(), backend)
    File.mkdir!(artifacts)
    write(artifacts, "selection.json", %{id: @id, backend: backend, profile: "core", seed: 4321})
    File.write!(Path.join(tmp_dir, "artifacts"), artifacts)
    directory = "/run/osbus-security/sec01-complete/" <> backend
    File.mkdir_p!(Path.dirname(directory))
    # mkdir is deliberately exclusive: no pre-existing endpoint may be adopted.
    File.mkdir!(directory)
    File.chmod!(directory, 0o755)
    control = Path.join(directory, "pro06-control")
    File.mkdir!(control)
    File.chmod!(control, 0o755)
    socket = Path.join(directory, "bus")
    policy_name = if backend == "reference", do: "reference.conf", else: "policy.exs"
    policy = Path.join(directory, policy_name)
    config = File.read!(Path.join(bindings["donor"], policy_name))
    File.write!(policy, config)
    File.chmod!(policy, 0o600)

    row = %{
      e2e_id: @id,
      backend: if(backend == "reference", do: :reference, else: :gao_bus),
      profile: :core,
      actors: @actors
    }

    blocked =
      Map.merge(row, %{
        status: :blocked,
        actors_executed: [],
        evidence: %{},
        outcome: %{
          complete: false,
          reason: "partial PRO-06: FD-index values and FD transfer excluded"
        }
      })

    report(artifacts, row, blocked)

    try do
      {command, args} = daemon_command(backend, bindings, socket, policy)

      with_child(:daemon, command, args, artifacts, fn daemon ->
        predicate =
          if backend == "reference",
            do: &String.contains?(&1, "unix:path=" <> socket),
            else: &String.contains?(&1, "\"event\":\"ready\"")

        assert {:ok, daemon_ready} = ChildProcess.await_ready(daemon, predicate, 10_000)
        inode = File.lstat!(socket)
        assert Bitwise.band(inode.mode, 0o170000) == 0o140000
        File.chmod!(socket, 0o666)

        backend_evidence = %{
          command: command,
          args: args,
          daemon: daemon_ready,
          socket: socket,
          socket_inode: inode.inode,
          config: config,
          config_sha256: digest(config)
        }

        write(artifacts, "backend.json", backend_evidence)

        try do
          with_actor("service", backend, bindings, control, nil, artifacts, fn service,
                                                                               service_ready ->
            service_identity = identity(service_ready, 1101)
            write(artifacts, "service-identity.json", service_identity)

            service_row = %{
              blocked
              | actors_executed: [:independent_service],
                evidence: %{independent_service: service_identity}
            }

            report(artifacts, row, service_row)
            File.write!(Path.join(control, "service.go"), "go\n")

            with_actor("observer", backend, bindings, control, nil, artifacts, fn observer,
                                                                                  observer_ready ->
              observer_identity = identity(observer_ready, 1100)
              write(artifacts, "observer-identity.json", observer_identity)

              observer_row = %{
                service_row
                | actors_executed: [:independent_service, :external_observer],
                  evidence: Map.put(service_row.evidence, :external_observer, observer_identity)
              }

              report(artifacts, row, observer_row)
              File.write!(Path.join(control, "observer.go"), "go\n")

              with_actor(
                "client",
                backend,
                bindings,
                control,
                service_ready["unique_name"],
                artifacts,
                fn client, client_ready ->
                  client_identity = identity(client_ready, 1101)
                  write(artifacts, "client-identity.json", client_identity)

                  client_row = %{
                    observer_row
                    | actors_executed: @actors,
                      evidence:
                        Map.put(observer_row.evidence, :independent_client, client_identity)
                  }

                  report(artifacts, row, client_row)
                  File.write!(Path.join(control, "client.go"), "go\n")
                  client_result = ChildProcess.await_exit(client, 70_000)
                  write(artifacts, "client-result.json", client_result)
                  assert client_result.exit_status == 0, client_result.output
                  refute client_result.timed_out?
                  client_events = events(client_result.output)
                  cases = Enum.filter(client_events, &(&1["event"] == "case"))
                  assert length(cases) == 12

                  assert Enum.map(cases, &{&1["endian"], &1["index"]}) ==
                           for(endian <- ["little", "big"], index <- 0..5, do: {endian, index})

                  Enum.each(cases, fn event ->
                    assert event["semantic_equal"]
                    assert event["expected"] == event["actual"]

                    assert event["signature"] in [
                             "a{sv}",
                             "a(it)",
                             "(ayaay)",
                             "(ynqiuxtbdsog)",
                             "v",
                             "(aaia{sv}av)"
                           ]

                    assert event["outgoing_first_byte"] ==
                             if(event["endian"] == "little", do: 108, else: 66)

                    assert event["reply_first_byte"] in [108, 66]
                    assert event["unix_fds"] == 0
                  end)

                  assert [%{"method_count" => 12, "expected_count" => 12}] =
                           Enum.filter(client_events, &(&1["event"] == "client_complete"))

                  assert identity(service_ready, 1101).starttime_ticks ==
                           service_identity.starttime_ticks

                  assert identity(observer_ready, 1100).starttime_ticks ==
                           observer_identity.starttime_ticks

                  File.write!(Path.join(control, "finish"), "finish\n")
                  service_result = ChildProcess.await_exit(service, 7_000)
                  observer_result = ChildProcess.await_exit(observer, 7_000)
                  write(artifacts, "service-result.json", service_result)
                  write(artifacts, "observer-result.json", observer_result)
                  assert service_result.exit_status == 0, service_result.output
                  assert observer_result.exit_status == 0, observer_result.output
                  refute service_result.timed_out?
                  refute observer_result.timed_out?

                  assert [%{"method_count" => 12, "expected_count" => 12}] =
                           Enum.filter(
                             events(service_result.output),
                             &(&1["event"] == "service_complete")
                           )

                  assert [continuity] =
                           Enum.filter(
                             events(observer_result.output),
                             &(&1["event"] == "observer_complete")
                           )

                  assert continuity["equal"] and continuity["same_connection"]
                  assert continuity["before_id"] == continuity["after_id"]
                  assert continuity["before_owner"] == continuity["after_owner"]
                  assert continuity["before_owner"] == observer_ready["unique_name"]
                  assert continuity["pid"] == observer_ready["pid"]
                  assert continuity["uid"] == 1100 and continuity["gid"] == 1100

                  executed = %{
                    blocked
                    | actors_executed: @actors,
                      evidence: %{
                        independent_service: service_identity,
                        independent_client: client_identity,
                        external_observer: %{identity: observer_identity, continuity: continuity}
                      }
                  }

                  executed = Map.put(executed, :backend_evidence, backend_evidence)
                  report(artifacts, row, executed)

                  write(artifacts, "result.json", %{
                    id: @id,
                    backend: backend,
                    seed: 4321,
                    normal_slice: "passed",
                    complete: false,
                    qualification: "blocked",
                    calls: cases,
                    actors_executed: @actors,
                    excluded: ["FD-index values", "FD transfer"],
                    reply_byte_orders: "observed only; not forced"
                  })
                end
              )
            end)
          end)
        after
          # The daemon is reaped by with_child before endpoint cleanup below.
          write(artifacts, "owned-endpoint.json", %{
            device: inode.major_device,
            inode: inode.inode
          })
        end
      end)
    after
      cleanup_endpoint(socket, artifacts)

      for name <- ["service.go", "observer.go", "client.go", "finish"],
          do: File.rm(Path.join(control, name))

      File.rmdir!(control)
      File.rm!(policy)
      File.rmdir!(directory)

      started = Path.wildcard(Path.join(artifacts, "*-started.json"))

      reaped =
        Enum.map(started, fn path ->
          role = Path.basename(path, "-started.json")
          {role, File.exists?(Path.join(artifacts, role <> "-reaped.json"))}
        end)

      write(artifacts, "teardown.json", %{
        owned_children_reaped: Enum.all?(reaped, fn {_role, confirmed} -> confirmed end),
        reaped: Map.new(reaped),
        private_directory_removed: true
      })

      assert Enum.all?(reaped, fn {_role, confirmed} -> confirmed end)
    end
  end

  defp daemon_command("reference", bindings, _socket, policy),
    do:
      {bindings["reference"],
       ["--nofork", "--nopidfile", "--print-address", "--config-file=" <> policy]}

  defp daemon_command("gao_bus", bindings, socket, policy) do
    ebins = Path.wildcard(Path.join([bindings["candidate"], "lib", "*", "ebin"]))
    assert ebins != []

    {bindings["elixir"],
     ["--erl", "+S 2:2"] ++
       Enum.flat_map(ebins, &["-pa", &1]) ++
       [
         Path.join(bindings["tree"], "support/e2e/fixtures/h04_system_daemon.exs"),
         socket,
         policy,
         bindings["original"]
       ]}
  end

  defp with_actor(role, backend, bindings, control, destination, artifacts, fun) do
    args =
      [
        "-u",
        if(role == "observer", do: "foundationA", else: "foundationB"),
        "--",
        bindings["actor"],
        role,
        "unix:path=/run/osbus-security/sec01-complete/#{backend}/bus"
      ] ++
        if(destination, do: [destination, control], else: [control])

    with_child(role, bindings["runuser"], args, artifacts, fn child ->
      assert {:ok, snapshot} =
               ChildProcess.await_ready(
                 child,
                 &String.contains?(&1, "\"event\":\"ready\""),
                 7_000
               )

      assert [ready] = Enum.filter(events(snapshot.output), &(&1["event"] == "ready"))
      assert ready["role"] == role
      assert String.starts_with?(ready["unique_name"], ":")
      observed = identity(ready, if(role == "observer", do: 1100, else: 1101))
      assert descendant?(ready["pid"], snapshot.pid)

      write(artifacts, role <> "-ready.json", %{
        actor: ready,
        external: observed,
        guardian: snapshot
      })

      fun.(child, ready)
    end)
  end

  defp with_child(role, command, args, artifacts, fun) do
    id = {:pro06, role, make_ref()}

    child =
      start_supervised!(
        Supervisor.child_spec({ChildProcess, command: command, args: args, owner: self()}, id: id)
      )

    on_exit(id, fn -> ChildProcess.stop(child) end)
    write(artifacts, "#{role}-started.json", %{command: command, args: args})

    try do
      fun.(child)
    after
      try do
        File.write!(Path.join(artifacts, "#{role}.log"), ChildProcess.snapshot(child).output)
      after
        :ok = ChildProcess.stop(child)
        write(artifacts, "#{role}-reaped.json", %{guardian_confirmed_reaping: true})
      end
    end
  end

  defp identity(ready, uid) do
    pid = ready["pid"]
    assert ready["uid"] == uid and ready["gid"] == uid
    before = File.read!("/proc/#{pid}/stat")
    status = File.read!("/proc/#{pid}/status")
    after_stat = File.read!("/proc/#{pid}/stat")
    assert ticks(before) == ticks(after_stat)

    for field <- ["Uid", "Gid"] do
      [_, values] = Regex.run(~r/^#{field}:\s+(.+)$/m, status)
      assert values |> String.split() |> Enum.map(&String.to_integer/1) == [uid, uid, uid, uid]
    end

    %{
      pid: pid,
      starttime_ticks: ticks(before),
      proc_stat: before,
      proc_stat_after: after_stat,
      proc_status: status
    }
  end

  defp ticks(stat),
    do: stat |> String.split(") ", parts: 2) |> List.last() |> String.split() |> Enum.at(19)

  defp descendant?(pid, pid), do: true

  defp descendant?(pid, ancestor) when pid > 1 do
    [_, parent] = Regex.run(~r/^PPid:\s+(\d+)$/m, File.read!("/proc/#{pid}/status"))
    descendant?(String.to_integer(parent), ancestor)
  end

  defp descendant?(_, _), do: false

  defp cleanup_endpoint(socket, artifacts) do
    case File.lstat(socket) do
      {:error, :enoent} ->
        :ok

      {:ok, info} ->
        owned = Path.join(artifacts, "owned-endpoint.json") |> File.read!() |> Jason.decode!()
        assert info.inode == owned["inode"] and info.major_device == owned["device"]
        assert Bitwise.band(info.mode, 0o170000) == 0o140000
        File.rm!(socket)
    end
  end

  defp report(dir, row, executed) do
    metadata = [
      seed: 4321,
      complete: false,
      scope: "normal nested live interchange only; partial PRO-06"
    ]

    {:ok, _} = Qualification.write_report(dir, Qualification.report([row], [executed], metadata))
  end

  defp events(output), do: output |> String.split("\n", trim: true) |> Enum.map(&Jason.decode!/1)
  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp write(dir, name, value),
    do: File.write!(Path.join(dir, name), Jason.encode!(value, pretty: true))
end
