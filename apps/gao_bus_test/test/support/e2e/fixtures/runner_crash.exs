[backend, artifacts] = System.argv()
Mix.start()
Mix.env(:test)

Mix.Project.in_project(:gao_bus_test, File.cwd!(), fn _ ->
  alias GaoBusTest.E2E.{ChildProcess, Context, Diagnostics, Qualification}

  mod =
    case backend do
      "reference" -> GaoBusTest.E2E.Backend.ReferenceDBusDaemon
      "gao_bus" -> GaoBusTest.E2E.Backend.GaoBusProcess
    end

  row = %{
    e2e_id: "H-runner-crash",
    backend: String.to_existing_atom(backend),
    profile: :session,
    actors: [:raw],
    actors_executed: [],
    status: :selected
  }

  Qualification.start!([row], artifacts)
  Qualification.metadata(:seed, 4321)
  Qualification.begin(row, row.backend)
  {:ok, state} = mod.start()

  context =
    Context.new(
      scenario_id: row.e2e_id,
      backend_name: row.backend,
      backend_mod: mod,
      backend_state: state,
      artifacts_dir: artifacts
    )

  Qualification.backend_ready(context, mod.diagnostics(state))
  source = Path.join(__DIR__, "raw_actor.py")

  {:ok, actor} =
    ChildProcess.start(
      command: "python3",
      args: [source, state.tmpdir, state.socket_path, Base.encode16(<<0, "AUTH\r\n">>)]
    )

  {:ok, snapshot} = ChildProcess.await_ready(actor, &String.contains?(&1, "received_hex"), 5_000)
  observed = Jason.decode!(String.trim(snapshot.output))
  Qualification.actor(context, :raw, observed)
  Diagnostics.write(context, :running)
  daemon = ChildProcess.snapshot(state.worker)

  IO.puts(
    "CRASH_READY " <>
      Jason.encode!(%{
        runner_pid: String.to_integer(System.pid()),
        guard_pids: [daemon.guard_pid, snapshot.guard_pid],
        daemon_pid: state.daemon_pid,
        actor: observed,
        tmpdir: state.tmpdir,
        artifacts: artifacts
      })
  )

  receive do
    :never -> :ok
  end
end)
