defmodule GaoBusTest.H04Events do
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
File.mkdir_p!(artifacts)
File.cd!(artifacts)

ExUnit.start(
  autorun: false,
  seed: 4321,
  max_cases: 1,
  exclude: [],
  formatters: [ExUnit.CLIFormatter, GaoBusTest.H04Events]
)

runtime = %{
  os_pid: System.pid(),
  elixir: System.version(),
  otp: File.read!(Path.join([to_string(:code.root_dir()), "releases", "27", "OTP_VERSION"])),
  test: test,
  seed: 4321,
  bindings: System.fetch_env!("H04_BINDINGS"),
  cwd: File.cwd!(),
  loaded_helpers:
    Map.new(
      [
        GaoBusTest.E2E.ChildProcess,
        GaoBusTest.E2E.Command,
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
}

File.write!(Path.join(artifacts, "suite-runtime.json"), Jason.encode!(runtime))
Code.compiler_options(warnings_as_errors: true)
Code.require_file(test)
stats = ExUnit.run()
File.write!(Path.join(artifacts, "suite-result.json"), Jason.encode!(stats))
passed? = stats.total == 2 and stats.failures == 0 and stats.excluded == 0 and stats.skipped == 0
System.halt(if passed?, do: 0, else: 1)
