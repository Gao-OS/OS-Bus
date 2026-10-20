defmodule GaoBusTest.E2E.Backend.GaoBusProcess do
  @moduledoc "Private separate-BEAM backend for baseline session conformance and resource observation."
  @behaviour GaoBusTest.E2E.Backend

  alias GaoBusTest.E2E.Backend.GaoBus
  alias GaoBusTest.E2E.ChildProcess

  @launcher Path.expand("../fixtures/gao_bus_daemon.exs", __DIR__)

  defstruct [
    :tmpdir,
    :socket_path,
    :bus_address,
    :worker,
    :daemon_pid,
    :config,
    :config_sha256,
    :policy_config,
    :policy_sha256
  ]

  @impl true
  def start(_opts \\ []) do
    dir = Path.join(System.tmp_dir!(), "gp#{System.unique_integer([:positive])}")
    File.mkdir!(dir)
    File.chmod!(dir, 0o700)
    socket = Path.join(dir, "s")
    policy_config = inspect(Elixir.GaoBus.Policy.session_rules(), limit: :infinity)
    policy_sha256 = Base.encode16(:crypto.hash(:sha256, policy_config), case: :lower)

    config =
      "profile=session\nsocket_path=#{socket}\ncluster=false\napplications=gao_bus\n" <>
        "policy_rules=#{policy_config}\npolicy_sha256=#{policy_sha256}\n"

    File.write!(Path.join(dir, "daemon.conf"), config)

    state = %__MODULE__{
      tmpdir: dir,
      socket_path: socket,
      bus_address: "unix:path=#{socket}",
      config: config,
      config_sha256: Base.encode16(:crypto.hash(:sha256, config), case: :lower),
      policy_config: policy_config,
      policy_sha256: policy_sha256
    }

    paths = Path.wildcard(Path.join([Mix.Project.build_path(), "lib", "*", "ebin"]))
    args = ["--erl", "+S 2:2"] ++ Enum.flat_map(paths, &["-pa", &1]) ++ [@launcher, socket]

    case ChildProcess.start(command: "elixir", args: args) do
      {:ok, worker} ->
        state = %{state | worker: worker}

        ready? = &String.contains?(&1, "E2E_GAO_READY #{policy_sha256}")

        case ChildProcess.await_ready(worker, ready?, 10_000) do
          {:ok, %{pid: pid}} ->
            state = %{state | daemon_pid: pid}

            case probe(state) do
              :ok ->
                {:ok, state}

              {:error, reason} ->
                stop(state)
                {:error, reason}
            end

          {:error, reason} ->
            stop(state)
            {:error, reason}
        end

      {:error, reason} ->
        File.rm_rf!(dir)
        {:error, reason}
    end
  end

  @impl true
  def address(state), do: state.bus_address

  @impl true
  def probe(state), do: GaoBus.probe(%GaoBus{bus_address: state.bus_address})

  @impl true
  def diagnostics(state) do
    snapshot = ChildProcess.snapshot(state.worker)

    %{
      backend: "gao_bus",
      profile: "session",
      separate_process: true,
      daemon_pid: state.daemon_pid,
      bus_address: state.bus_address,
      config: state.config,
      config_sha256: state.config_sha256,
      policy_config: state.policy_config,
      policy_sha256: state.policy_sha256,
      log: snapshot.output
    }
  end

  @impl true
  def stop(state) do
    if state.worker, do: ChildProcess.stop(state.worker)
    File.rm_rf!(state.tmpdir)
    :ok
  end
end
