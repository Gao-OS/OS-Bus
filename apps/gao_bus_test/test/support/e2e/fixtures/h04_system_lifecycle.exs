# Guest-only inner runner. Its interrupted qualification must remain blocked.
[backend, artifacts, bindings_path] = System.argv()
bindings = :json.decode(File.read!(bindings_path))
true = backend in ["reference", "gao_bus"]
"isolated-vm\n" = File.read!("/etc/osbus-security-guest")
true = System.pid() != "1"
"1.17.3" = System.version()
~c"27" = :erlang.system_info(:otp_release)

"27.3.4.6" =
  File.read!(Path.join([to_string(:code.root_dir()), "releases", "27", "OTP_VERSION"]))
  |> String.trim()

directory = "/run/osbus-security/sec01-complete/" <> backend
socket = Path.join(directory, "bus")
File.mkdir!(directory)
File.chmod!(directory, 0o755)

alias GaoBusTest.E2E.{ChildProcess, Qualification}
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end

write = fn name, value ->
  File.write!(Path.join(artifacts, name), :json.encode(value))
end

fixture = Path.dirname(__ENV__.file)
policy_name = if backend == "reference", do: "reference.conf", else: "policy.exs"
config = File.read!(Path.join(bindings["donor"], policy_name))
policy = Path.join(directory, policy_name)
File.write!(policy, config)
File.chmod!(policy, 0o600)
paths = Path.wildcard(Path.join([bindings["candidate"], "lib", "*", "ebin"]))

daemon_args =
  if backend == "reference" do
    ["--nofork", "--nopidfile", "--print-address", "--config-file=" <> policy]
  else
    ["--erl", "+S 2:2"] ++
      Enum.flat_map(paths, &["-pa", &1]) ++
      [Path.join(fixture, "h04_system_daemon.exs"), socket, policy, bindings["original"]]
  end

daemon_command = if backend == "reference", do: bindings["reference"], else: bindings["elixir"]
{:ok, daemon} = ChildProcess.start(command: daemon_command, args: daemon_args)

ready? =
  if backend == "reference",
    do: &String.contains?(&1, "unix:path=" <> socket),
    else: &String.contains?(&1, "\"event\":\"ready\"")

{:ok, daemon_ready} = ChildProcess.await_ready(daemon, ready?, 10_000)
%{mode: socket_mode} = File.lstat!(socket)
true = Bitwise.band(socket_mode, 0o170000) == 0o140000
File.chmod!(socket, 0o666)

backend_atom = if backend == "reference", do: :reference, else: :gao_bus

row = %{
  e2e_id: "H-04-system-lifecycle",
  backend: backend_atom,
  profile: :core,
  actors: [:independent_client, :external_observer],
  actors_executed: [],
  status: :selected
}

backend_evidence = %{
  profile: "system",
  socket_path: socket,
  config: config,
  config_sha256: digest.(config),
  daemon_pid: daemon_ready.pid,
  command: daemon_command,
  args: daemon_args,
  log: daemon_ready.output
}

metadata = [
  seed: 4321,
  scope: "accepted SEC01 conservative system fixture; not installed XML parity"
]

persist = fn actor, timeout ->
  running =
    Map.merge(row, %{
      status: :running,
      actors_executed: [:independent_client],
      backend_evidence: backend_evidence,
      evidence: %{independent_client: actor, fixture_timeout: timeout}
    })

  Qualification.write_report(artifacts, Qualification.report([row], [running], metadata))

  write.("context.json", %{
    backend: backend,
    profile: "core",
    socket_path: socket,
    selected: [row],
    seed: 4321,
    binding_path: bindings_path
  })

  File.write!(Path.join(artifacts, "backend.log"), ChildProcess.snapshot(daemon).output)
end

start_actor = fn ->
  {:ok, actor} =
    ChildProcess.start(
      command: bindings["runuser"],
      args: [
        "-u",
        "foundationB",
        "--",
        bindings["python"],
        "-B",
        Path.join(fixture, "h04_system_actor.py"),
        bindings["original"],
        socket
      ]
    )

  {:ok, snapshot} = ChildProcess.await_ready(actor, &String.contains?(&1, "\"get_id\""), 5_000)
  observed = :json.decode(String.trim(snapshot.output))
  {actor, snapshot, observed}
end

{timeout_actor, timeout_snapshot, timeout_observed} = start_actor.()
persist.(timeout_observed, nil)

IO.puts(
  "H04_TIMEOUT_READY " <>
    IO.iodata_to_binary(
      :json.encode(%{actor: timeout_observed, guard_pid: timeout_snapshot.guard_pid})
    )
)

"timeout\n" = IO.gets("")
%{timed_out?: true} = timeout_result = ChildProcess.await_exit(timeout_actor, 10)
:ok = ChildProcess.stop(timeout_actor)
write.("fixture-timeout.json", %{actor: timeout_observed, result: timeout_result})
IO.puts("H04_TIMEOUT_REAPED " <> IO.iodata_to_binary(:json.encode(timeout_result)))

{_actor, actor_snapshot, observed} = start_actor.()
persist.(observed, timeout_result)
write.("fixture-actor.json", observed)

IO.puts(
  "H04_CRASH_READY " <>
    IO.iodata_to_binary(
      :json.encode(%{
        runner_pid: String.to_integer(System.pid()),
        daemon_pid: daemon_ready.pid,
        guard_pids: [daemon_ready.guard_pid, actor_snapshot.guard_pid],
        actor: observed,
        directory: directory,
        socket_path: socket
      })
    )
)

receive do
  :never -> :ok
end
