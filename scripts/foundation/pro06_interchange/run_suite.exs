defmodule GaoBusTest.PRO06Events do
  use GenServer
  def init(_options), do: {:ok, []}

  def handle_cast({:test_finished, test}, events) do
    event = %{name: test.name, module: test.module, state: inspect(test.state)}
    events = [event | events]
    File.write!("test-events.json", Jason.encode!(Enum.reverse(events)))
    {:noreply, events}
  end

  def handle_cast(_event, state), do: {:noreply, state}
end

[test, artifacts] = System.argv()
"isolated-vm\n" = File.read!("/etc/osbus-security-guest")
"1.17.3" = System.version()
~c"27" = :erlang.system_info(:otp_release)

"27.3.4.6" =
  otp =
  File.read!(Path.join([to_string(:code.root_dir()), "releases", "27", "OTP_VERSION"]))
  |> String.trim()

File.mkdir_p!(artifacts)
File.cd!(artifacts)

ExUnit.start(
  autorun: false,
  seed: 4321,
  max_cases: 1,
  exclude: [],
  formatters: [ExUnit.CLIFormatter, GaoBusTest.PRO06Events]
)

File.write!(
  "suite-runtime.json",
  Jason.encode!(%{
    os_pid: System.pid(),
    elixir: System.version(),
    otp: otp,
    test: test,
    seed: 4321,
    bindings: System.fetch_env!("PRO06_BINDINGS"),
    cwd: File.cwd!(),
    selected:
      for(
        backend <- ["reference", "gao_bus"],
        do: %{id: "PRO-06-normal-interchange", backend: backend, profile: "core"}
      ),
    complete: false,
    loaded_helpers:
      Map.new(
        [
          GaoBusTest.E2E.ChildProcess,
          GaoBusTest.E2E.Qualification,
          GaoBusTest.E2E.Selection,
          Jason
        ],
        fn module ->
          {module,
           %{
             beam: to_string(:code.which(module)),
             source: to_string(module.module_info(:compile)[:source])
           }}
        end
      )
  })
)

Code.compiler_options(warnings_as_errors: true)
Code.require_file(test)
stats = ExUnit.run()
File.write!("suite-result.json", Jason.encode!(stats))

if stats.total == 2 and stats.failures == 0 and stats.excluded == 0 and stats.skipped == 0 do
  results =
    for backend <- ["reference", "gao_bus"],
        do: File.read!(Path.join(backend, "result.json")) |> Jason.decode!()

  [reference, candidate] =
    Enum.map(results, fn result ->
      Enum.map(
        result["calls"],
        &Map.take(&1, [
          "index",
          "endian",
          "signature",
          "expected",
          "actual",
          "semantic_equal",
          "outgoing_first_byte"
        ])
      )
    end)

  equal = reference == candidate

  File.write!(
    "cross-backend.json",
    Jason.encode!(%{
      normal_semantics_equal: equal,
      complete: false,
      qualification: "blocked",
      excluded: ["FD-index values", "FD transfer"]
    })
  )

  if !equal, do: raise("cross-backend normal semantic inequality")
end

System.halt(
  if stats.total == 2 and stats.failures == 0 and stats.excluded == 0 and stats.skipped == 0,
    do: 0,
    else: 1
)
