defmodule GaoBus.Policy.AsyncReloadTest do
  use ExUnit.Case, async: false

  alias GaoBus.{Config, Limits, Policy}

  @moduletag :tmp_dir
  @first "org.test.First"
  @second "org.test.Second"
  @supervisor GaoBus.Policy.ReloadSupervisor

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

    fixture =
      Map.put(fixture, :options, daemon_uid: 4, passwd: fixture.passwd, group: fixture.group)

    write_generation(fixture, 42, 7, @first)
    assert {:ok, config} = Config.load(fixture.path, fixture.options)
    %{fixture: fixture, config: config}
  end

  test "direct file reload waits for real preparation and publishes one coherent row", ctx do
    gate = make_ref()
    policy = start_policy(ctx, reload_prepare_barrier: {self(), gate})
    assert {:ok, 1, _} = original = Policy.snapshot()
    write_generation(ctx.fixture, 43, 8, @second)
    request = call_async(&Policy.reload_file/0)

    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    monitor = Process.monitor(worker)
    assert Policy.snapshot() == original
    assert {:ok, configuration} = Policy.configuration(original)
    assert configuration.accounts.users["worker"] == 42
    assert Policy.activatable_names(original) == [@first]
    assert {:allow, 1} = Policy.authorize(original, :own, identity(42, @first))
    assert Task.Supervisor.children(@supervisor) == [worker]
    assert is_map(:sys.get_state(policy))
    refute_receive {:api_result, ^request, _}, 0

    # Changing the files again cannot change the already prepared candidate.
    write_generation(ctx.fixture, 44, 9, @first)
    send(worker, {:release_reload, gate})
    assert_receive {:api_result, ^request, {:ok, 2}}, 2000
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 2000
    assert {:ok, 2, _} = current = Policy.snapshot()
    assert {:ok, configuration} = Policy.configuration(current)
    assert configuration.accounts.users["worker"] == 43
    assert configuration.services.selected[@second].account.gid == 8
    assert Policy.activatable_names(current) == [@second]
    assert {:allow, 2} = Policy.authorize(current, :own, identity(43, @second))
    assert {:deny, :policy_denied} = Policy.authorize(current, :own, identity(42, @first))
    assert {:allow, 1} = Policy.authorize(original, :own, identity(42, @first))
    assert Task.Supervisor.children(@supervisor) == []
  end

  test "completed result retains the single worker slot until actual DOWN", ctx do
    gate = make_ref()
    start_policy(ctx, reload_result_barrier: {self(), gate})
    request = call_async(&Policy.reload_file/0)
    assert_receive {:reload_result_barrier, ^gate, worker}, 2000
    monitor = Process.monitor(worker)
    _ = :sys.get_state(Policy)
    assert {:ok, 2, _} = Policy.snapshot()
    refute_receive {:api_result, ^request, _}, 0
    assert {:error, :reload_busy} = Policy.reload_file()
    assert Task.Supervisor.children(@supervisor) == [worker]
    send(worker, {:release_reload, gate})
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 2000
    assert_receive {:api_result, ^request, {:ok, 2}}, 2000

    next = call_async(&Policy.reload_file/0)
    assert_receive {:reload_result_barrier, ^gate, next_worker}, 2000
    assert next_worker != worker
    send(next_worker, {:release_reload, gate})
    assert_receive {:api_result, ^next, {:ok, 3}}, 2000
  end

  test "router publication requires exact caller, epoch, job and base generation", ctx do
    register_router()
    gate = make_ref()
    policy = start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    original = Policy.snapshot()
    write_generation(ctx.fixture, 43, 8, @second)
    assert {:ok, {^policy, epoch, job}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    assert {:error, :reload_busy} = request_reload(self())
    assert Policy.snapshot() == original
    send(worker, {:release_reload, gate})
    assert_receive {:policy_reload_prepared, ^policy, ^epoch, ^job, 1}, 2000
    assert Policy.snapshot() == original

    alien = call_async(fn -> commit(policy, epoch, job, 1) end)
    assert_receive {:api_result, ^alien, {:error, :stale_reload}}, 2000
    assert {:error, :stale_reload} = commit(policy, make_ref(), job, 1)
    assert {:error, :stale_reload} = commit(policy, epoch, make_ref(), 1)
    assert {:error, :stale_reload} = commit(policy, epoch, job, 0)
    assert Policy.snapshot() == original
    assert {:ok, 2} = commit(policy, epoch, job, 1)
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:ok, 2}}, 2000
    assert {:error, :stale_reload} = commit(policy, epoch, job, 1)
    refute_receive {:policy_reload_finished, ^policy, ^epoch, ^job, _}, 0
    assert {:ok, 2, _} = Policy.snapshot()
  end

  test "router-mode direct file API waits for Router publication without a wire waiter", ctx do
    register_router()
    start_policy(ctx, publication: :router)
    request = call_async(&Policy.reload_file/0)
    assert_receive {:policy_reload_prepared, policy, epoch, job, 1}, 2000
    refute_receive {:api_result, ^request, _}, 0
    assert {:ok, 1, _} = Policy.snapshot()
    assert {:ok, 2} = commit(policy, epoch, job, 1)
    assert_receive {:api_result, ^request, {:ok, 2}}, 2000
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:ok, 2}}, 2000
  end

  test "router-mode direct replacements follow Router order and reject runtime changes", ctx do
    register_router()
    start_policy(ctx, publication: :router)
    write_generation(ctx.fixture, 43, 8, @second)
    assert {:ok, candidate} = Config.load(ctx.fixture.path, ctx.fixture.options)
    request = call_async(fn -> Policy.reload(candidate) end)
    assert_receive {:policy_reload_prepared, policy, epoch, job, 1}, 2000
    assert {:ok, 1, _} = Policy.snapshot()
    assert {:ok, 2} = commit(policy, epoch, job, 1)
    assert_receive {:api_result, ^request, {:ok, 2}}, 2000
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:ok, 2}}, 2000

    assert {:error, :configuration_requires_restart} =
             Policy.reload(%{candidate | daemon_uid: 5})

    assert {:ok, 2, _} = Policy.snapshot()
  end

  test "missing Router fails closed rather than falling back to standalone publication", ctx do
    gate = make_ref()
    start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    original = Policy.snapshot()
    assert {:error, :router_unavailable} = Policy.reload_file()
    assert {:error, :router_unavailable} = Policy.reload(ctx.config)
    assert {:error, :router_unavailable} = request_reload(self())
    assert Policy.snapshot() == original
    refute_receive {:reload_prepared_barrier, ^gate, _}, 0
    assert Task.Supervisor.children(@supervisor) == []
  end

  test "busy production replacement refuses admission before compiling invalid accounts", ctx do
    register_router()
    gate = make_ref()
    policy = start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    original = Policy.snapshot()
    assert {:ok, {^policy, epoch, job}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000

    assert {:error, :reload_busy} = Policy.reload(%{ctx.config | accounts: :invalid})
    assert Policy.snapshot() == original
    assert Task.Supervisor.children(@supervisor) == [worker]
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()

    send(worker, {:release_reload, gate})
    assert_receive {:policy_reload_prepared, ^policy, ^epoch, ^job, 1}, 2000
    assert {:ok, 2} = commit(policy, epoch, job, 1)
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:ok, 2}}, 2000
  end

  test "an admitted invalid production replacement compiles in the worker and retains the row",
       ctx do
    register_router()
    gate = make_ref()
    policy = start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    original = Policy.snapshot()
    request = call_async(fn -> Policy.reload(%{ctx.config | accounts: :invalid}) end)
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    assert Task.Supervisor.children(@supervisor) == [worker]
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()
    assert Policy.snapshot() == original
    refute_receive {:api_result, ^request, _}, 0

    send(worker, {:release_reload, gate})

    assert_receive {:api_result, ^request,
                    {:error, %{reason: :invalid_account_snapshot} = reason}},
                   2000

    assert_receive {:policy_reload_finished, ^policy, _epoch, _job, {:error, ^reason}}, 2000
    refute_receive {:policy_reload_prepared, ^policy, _, _, _}, 0
    assert Policy.snapshot() == original
    assert {:ok, %{reload_reservations: 0}} = Limits.snapshot()
  end

  test "worker crash preserves the active row and permits a subsequent reload", ctx do
    gate = make_ref()
    policy = start_policy(ctx, reload_prepare_barrier: {self(), gate})
    original = Policy.snapshot()
    request = call_async(&Policy.reload_file/0)
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    monitor = Process.monitor(worker)
    Process.exit(worker, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 2000
    assert_receive {:api_result, ^request, {:error, {:reload_worker_failed, :killed}}}, 2000
    assert Policy.snapshot() == original
    assert is_map(:sys.get_state(policy))
    next = call_async(&Policy.reload_file/0)
    assert_receive {:reload_prepared_barrier, ^gate, next_worker}, 2000
    send(next_worker, {:release_reload, gate})
    assert_receive {:api_result, ^next, {:ok, 2}}, 2000
  end

  test "absolute deadline terminates preparation and refuses late results", ctx do
    gate = make_ref()
    policy = start_policy(ctx, reload_timeout: 1000, reload_prepare_barrier: {self(), gate})
    original = Policy.snapshot()
    write_generation(ctx.fixture, 43, 8, @second)
    assert {:ok, candidate} = Config.load(ctx.fixture.path, ctx.fixture.options)
    assert {:ok, compiled} = Policy.compile(candidate)
    request = call_async(&Policy.reload_file/0)
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    monitor = Process.monitor(worker)
    assert_receive {:api_result, ^request, {:error, :reload_timeout}}, 2500
    assert_receive {:DOWN, ^monitor, :process, ^worker, _}, 2000
    send(policy, {:reload_candidate, worker, make_ref(), {:ok, compiled}})
    _ = :sys.get_state(policy)
    assert Policy.snapshot() == original
    assert Task.Supervisor.children(@supervisor) == []
  end

  test "deadline after preparation refuses a delayed Router commit", ctx do
    register_router()
    gate = make_ref()

    policy =
      start_policy(ctx,
        publication: :router,
        reload_timeout: 1000,
        reload_prepare_barrier: {self(), gate}
      )

    original = Policy.snapshot()
    assert {:ok, compiled} = Policy.compile(ctx.config)
    assert {:ok, {^policy, epoch, job}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    monitor = Process.monitor(worker)
    send(worker, {:release_reload, gate})
    assert_receive {:policy_reload_prepared, ^policy, ^epoch, ^job, 1}, 2000

    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:error, :reload_timeout}},
                   2500

    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 2000
    send(policy, {:reload_candidate, worker, job, {:ok, compiled}})
    _ = :sys.get_state(policy)
    assert {:error, :stale_reload} = commit(policy, epoch, job, 1)
    assert Policy.snapshot() == original
    refute_receive {:policy_reload_finished, ^policy, ^epoch, ^job, _}, 0
  end

  test "caller death does not revoke an admitted preparation", ctx do
    gate = make_ref()
    start_policy(ctx, reload_prepare_barrier: {self(), gate})
    parent = self()

    caller =
      start_supervised!({Task, fn -> send(parent, {:caller_result, Policy.reload_file()}) end})

    caller_monitor = Process.monitor(caller)
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    worker_monitor = Process.monitor(worker)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^caller_monitor, :process, ^caller, :killed}, 2000
    assert Task.Supervisor.children(@supervisor) == [worker]
    send(worker, {:release_reload, gate})
    assert_receive {:DOWN, ^worker_monitor, :process, ^worker, :normal}, 2000
    _ = :sys.get_state(Policy)
    assert {:ok, 2, _} = Policy.snapshot()
    refute_receive {:caller_result, _}, 0
  end

  test "Policy restart shuts down its worker and stale incarnation cannot commit", ctx do
    register_router()
    gate = make_ref()
    policy = start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    supervisor = Process.whereis(@supervisor)
    supervisor_monitor = Process.monitor(supervisor)
    assert {:ok, {^policy, epoch, job}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    worker_monitor = Process.monitor(worker)
    assert :ok = stop_supervised(Policy)
    assert_receive {:DOWN, ^worker_monitor, :process, ^worker, _}, 2000
    assert_receive {:DOWN, ^supervisor_monitor, :process, ^supervisor, _}, 2000
    next_policy = start_policy(ctx, publication: :router)
    assert next_policy != policy
    assert {:error, :policy_unavailable} = commit(policy, epoch, job, 1)
    assert {:error, :stale_reload} = commit(next_policy, epoch, job, 1)
    assert {:ok, 1, _} = Policy.snapshot()
  end

  test "standalone legacy replacements and invalid file errors retain public contracts", ctx do
    start_policy(ctx)
    assert {:ok, 2} = Policy.reload(Policy.session_rules())
    original = Policy.snapshot()
    File.write!(ctx.fixture.path, "<busconfig>")
    assert {:error, _} = Policy.reload_file()
    assert Policy.snapshot() == original

    assert {:error, {:invalid_rule, 1, :invalid_rule_shape}} =
             Policy.reload([%{action: :unknown}])

    assert Policy.snapshot() == original
  end

  test "fresh Policy waits for the previous named supervisor after brutal owner death", ctx do
    options = [
      rules: ctx.config,
      config_file: ctx.fixture.path,
      config_options: ctx.fixture.options
    ]

    policy = start_supervised!({Policy, options}, restart: :temporary)
    policy_monitor = Process.monitor(policy)
    supervisor = Process.whereis(@supervisor)
    supervisor_monitor = Process.monitor(supervisor)
    {:ok, test_supervisor} = ExUnit.fetch_test_supervisor()
    parent = self()
    gate = make_ref()

    {:ok, held_worker} =
      Task.Supervisor.start_child(
        supervisor,
        fn ->
          Process.flag(:trap_exit, true)
          send(parent, {:shutdown_worker_ready, gate, self()})

          receive do
            {:EXIT, ^supervisor, :shutdown} ->
              send(parent, {:supervisor_shutdown_held, gate, self()})

              receive do
                {:release_shutdown, ^gate} -> :ok
              end
          end
        end,
        shutdown: :infinity
      )

    held_worker_monitor = Process.monitor(held_worker)

    request =
      try do
        assert_receive {:shutdown_worker_ready, ^gate, ^held_worker}, 2000
        Process.exit(policy, :kill)
        assert_receive {:DOWN, ^policy_monitor, :process, ^policy, :killed}, 2000
        assert_receive {:supervisor_shutdown_held, ^gate, ^held_worker}, 2000
        assert Process.whereis(Policy) == nil
        assert Process.whereis(@supervisor) == supervisor
        assert stop_supervised(Policy) in [:ok, {:error, :not_found}]

        request =
          call_async(fn ->
            Supervisor.start_child(test_supervisor, Supervisor.child_spec({Policy, options}, []))
          end)

        replacement =
          await_reload_start(supervisor, request, System.monotonic_time(:millisecond) + 2000)

        assert replacement != policy
        assert Process.whereis(@supervisor) == supervisor
        assert {:error, :policy_unavailable} = Policy.snapshot()
        refute_receive {:api_result, ^request, _}, 0
        request
      after
        Process.exit(policy, :kill)
        send(held_worker, {:release_shutdown, gate})
        assert_receive {:DOWN, ^held_worker_monitor, :process, ^held_worker, :normal}, 2000
        assert_receive {:DOWN, ^supervisor_monitor, :process, ^supervisor, :killed}, 2000
      end

    assert_receive {:api_result, ^request, {:ok, replacement}}, 2000
    assert Process.whereis(Policy) == replacement
    assert Process.whereis(@supervisor) != supervisor
    assert {:ok, 1, _} = Policy.snapshot()
  end

  test "Policy startup fails within its deadline without adopting a live named supervisor", ctx do
    supervisor =
      start_supervised!({Task.Supervisor, name: @supervisor, max_children: 1}, id: @supervisor)

    {:ok, test_supervisor} = ExUnit.fetch_test_supervisor()
    options = [rules: ctx.config]

    request =
      call_async(fn ->
        Supervisor.start_child(test_supervisor, Supervisor.child_spec({Policy, options}, []))
      end)

    policy = await_reload_start(supervisor, request, System.monotonic_time(:millisecond) + 2000)
    {:links, links} = Process.info(supervisor, :links)
    refute policy in links
    assert {:error, :policy_unavailable} = Policy.snapshot()

    assert_receive {:api_result, ^request, {:error, {:already_started, ^supervisor}}}, 6000
    assert Process.whereis(Policy) == nil
    assert Process.whereis(@supervisor) == supervisor
    assert Task.Supervisor.children(supervisor) == []
    assert is_map(:sys.get_state(supervisor))
    {:monitored_by, monitors} = Process.info(supervisor, :monitored_by)
    refute policy in monitors
  end

  test "orphan reserved admission expires without input and releases its separate slot", ctx do
    register_router()
    gate = make_ref()
    policy = start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    assert {:ok, orphan} = Limits.reserve_reload(policy, 100)
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()
    await_reload_empty(System.monotonic_time(:millisecond) + 2000)
    assert {:ok, {^policy, epoch, job}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    GenServer.cast(policy, {:begin_reload, epoch, orphan, :file, self()})
    send(policy, {:reload_timeout, orphan})
    _ = :sys.get_state(policy)
    assert Task.Supervisor.children(@supervisor) == [worker]
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()
    send(worker, {:release_reload, gate})
    assert_receive {:policy_reload_prepared, ^policy, ^epoch, ^job, 1}, 2000
    assert {:ok, 2} = commit(policy, epoch, job, 1)
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:ok, 2}}, 2000
  end

  test "duplicate and malformed preparation inputs cannot cancel or multiply an admitted job",
       ctx do
    register_router()
    gate = make_ref()
    policy = start_policy(ctx, publication: :router, reload_prepare_barrier: {self(), gate})
    assert {:ok, {^policy, epoch, job}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, worker}, 2000
    monitor = Process.monitor(worker)
    GenServer.cast(policy, {:begin_reload, epoch, job, :file, self()})
    GenServer.cast(policy, {:begin_reload, make_ref(), job, :file, self()})
    _ = :sys.get_state(policy)
    assert Task.Supervisor.children(@supervisor) == [worker]
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()
    send(worker, {:release_reload, gate})
    assert_receive {:policy_reload_prepared, ^policy, ^epoch, ^job, 1}, 2000
    assert {:ok, 2} = commit(policy, epoch, job, 1)
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^job, {:ok, 2}}, 2000
    assert_receive {:DOWN, ^monitor, :process, ^worker, :normal}, 2000
    await_reload_empty(System.monotonic_time(:millisecond) + 2000)

    assert {:ok, {^policy, ^epoch, next}} = request_reload(self())
    assert_receive {:reload_prepared_barrier, ^gate, next_worker}, 2000
    GenServer.cast(policy, {:begin_reload, epoch, job, :file, self()})
    send(policy, {:reload_timeout, job})
    _ = :sys.get_state(policy)
    assert Task.Supervisor.children(@supervisor) == [next_worker]
    assert {:ok, %{reload_reservations: 1}} = Limits.snapshot()
    send(next_worker, {:release_reload, gate})
    assert_receive {:policy_reload_prepared, ^policy, ^epoch, ^next, 2}, 2000
    assert {:ok, 3} = commit(policy, epoch, next, 2)
    assert_receive {:policy_reload_finished, ^policy, ^epoch, ^next, {:ok, 3}}, 2000
  end

  defp start_policy(ctx, options \\ []) do
    if Keyword.get(options, :publication) == :router and is_nil(Process.whereis(Limits)),
      do: start_supervised!({Limits, []})

    start_supervised!(
      {Policy,
       Keyword.merge(
         [rules: ctx.config, config_file: ctx.fixture.path, config_options: ctx.fixture.options],
         options
       )}
    )
  end

  defp register_router do
    assert Process.register(self(), GaoBus.Router)
  end

  defp request_reload(router), do: apply(Policy, :request_reload_file, [router])

  defp commit(policy, epoch, job, generation),
    do: apply(Policy, :commit_reload, [policy, epoch, job, generation])

  defp call_async(callback) do
    parent = self()
    tag = make_ref()
    start_supervised!({Task, fn -> send(parent, {:api_result, tag, callback.()}) end}, id: tag)
    tag
  end

  defp await_reload_empty(deadline) do
    case Limits.snapshot() do
      {:ok, %{reload_reservations: 0}} ->
        :ok

      _ ->
        assert System.monotonic_time(:millisecond) < deadline, "reload admission drain deadline"
        await_reload_empty(deadline)
    end
  end

  defp await_reload_start(supervisor, request, deadline) do
    receive do
      {:api_result, ^request, result} ->
        flunk("Policy returned before previous supervisor DOWN: #{inspect(result)}")
    after
      0 ->
        policy = Process.whereis(Policy)
        {:monitored_by, monitors} = Process.info(supervisor, :monitored_by)

        if is_pid(policy) and policy in monitors do
          policy
        else
          assert System.monotonic_time(:millisecond) < deadline, "Policy startup wait deadline"
          await_reload_start(supervisor, request, deadline)
        end
    end
  end

  defp write_generation(fixture, uid, gid, name) do
    File.write!(fixture.passwd, "worker:x:#{uid}:#{gid}::/:/bin/false\n")
    File.write!(fixture.group, "workers:x:#{gid}:worker\n")
    for file <- File.ls!(fixture.services), do: File.rm!(Path.join(fixture.services, file))

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
end
