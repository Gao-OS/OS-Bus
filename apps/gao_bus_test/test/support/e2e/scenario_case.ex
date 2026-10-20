defmodule GaoBusTest.E2E.ScenarioCase do
  @moduledoc """
  Helpers for backend/gate selected E2E conformance scenarios.
  """

  alias GaoBusTest.E2E.Backend.{GaoBus, GaoBusProcess, ReferenceDBusDaemon}
  alias GaoBusTest.E2E.{Command, Context, Diagnostics, Qualification, Selection}

  def selected_backends do
    case System.get_env("E2E_BACKEND", "reference") do
      "reference" ->
        [:reference]

      "gao_bus" ->
        [:gao_bus]

      "both" ->
        [:reference, :gao_bus]

      other ->
        raise ArgumentError,
              "invalid E2E_BACKEND=#{inspect(other)}, expected reference | gao_bus | both"
    end
  end

  def selected_gate do
    case System.get_env("E2E_GATE", "all") do
      "smoke" ->
        :smoke

      "release" ->
        :release

      "compat" ->
        :compat

      "stress" ->
        :stress

      "all" ->
        :all

      other ->
        raise ArgumentError,
              "invalid E2E_GATE=#{inspect(other)}, expected smoke | release | compat | stress | all"
    end
  end

  def backend_mod(:reference), do: ReferenceDBusDaemon

  def backend_mod(:gao_bus) do
    if Qualification.strict?() or System.get_env("E2E_GAO_PROCESS") == "1",
      do: GaoBusProcess,
      else: GaoBus
  end

  def prepare_backend_availability! do
    if Qualification.strict?() do
      tools =
        Map.new(
          [
            {:dbus_daemon, "dbus-daemon", ["--version"]},
            {:busctl, "busctl", ["--version"]},
            {:gio, "pkg-config", ["--modversion", "gio-2.0"]}
          ],
          fn {name, command, args} ->
            result = Command.run(command, args)

            {name,
             %{
               executable: result.command,
               version: String.trim(result.stdout),
               exit_status: result.exit_status,
               error: result.stderr
             }}
          end
        )

      Qualification.metadata(:tools, tools)
    end

    for backend_name <- selected_backends() do
      reason = probe_backend(backend_name)
      :persistent_term.put(availability_key(backend_name), reason)
      Qualification.metadata(backend_name, %{probe: reason || :ok})
    end

    :ok
  end

  def skip_reason(tags) when is_map(tags) do
    validate_known_gap!(tags)

    checks = [
      &gate_skip_reason/1,
      &backend_selection_skip_reason/1
    ]

    optional_checks = [
      &known_gap_selection_skip_reason/1,
      &backend_availability_skip_reason/1,
      &fixture_skip_reason/1,
      &busctl_skip_reason/1,
      &gdbus_skip_reason/1
    ]

    (checks ++ if(Qualification.strict?(), do: [], else: optional_checks))
    |> Enum.find_value(fn reason_fun -> reason_fun.(tags) end)
  end

  def requirements(tags, backend, opts \\ []) do
    availability =
      Keyword.get(opts, :availability, %{backend => backend_unavailable_reason(backend)})

    cond do
      backend in Map.get(tags, :known_gap, []) ->
        {:error, {:known_gap, backend}}

      Map.get(availability, backend) != nil ->
        {:error, {:backend_unavailable, Map.fetch!(availability, backend)}}

      true ->
        case Enum.find(Map.get(tags, :actors, []), &(not actor_available?(&1))) do
          nil -> :ok
          actor -> {:error, {:missing_actor, actor}}
        end
    end
  end

  def run_scenario(tags, fun) when is_map(tags) and is_function(fun, 1) do
    validate_known_gap!(tags)
    if Qualification.strict?(), do: Selection.validate!(tags)

    backends =
      if Qualification.strict?(),
        do: selected_backend_names(tags),
        else: runnable_backend_names(tags)

    results = Enum.map(backends, &run_backend(tags, &1, fun))

    case Enum.find(results, &match?({:error, _, _, _}, &1)) do
      nil -> :ok
      {:error, kind, reason, stacktrace} -> :erlang.raise(kind, reason, stacktrace)
    end
  end

  defp run_backend(tags, backend_name, fun) do
    mod = backend_mod(backend_name)
    scenario_id = Map.fetch!(tags, :e2e_id)
    Qualification.begin(tags, backend_name)

    required = if Qualification.strict?(), do: requirements(tags, backend_name), else: :ok

    with :ok <- required,
         {:ok, backend_state} <- mod.start(scenario_id: scenario_id) do
      context =
        Context.new(
          scenario_id: scenario_id,
          backend_name: backend_name,
          backend_mod: mod,
          backend_state: backend_state,
          metadata: Map.take(tags, [:gate, :group, :actors])
        )

      context = %{context | artifacts_dir: Diagnostics.default_artifact_dir(context)}

      Command.start_collector()

      try do
        Qualification.backend_ready(context, mod.diagnostics(backend_state))
        if Qualification.strict?(), do: Diagnostics.write(context, :running)
        fun.(context)

        Qualification.outcome(scenario_id, backend_name, :passed, %{
          backend: mod.diagnostics(backend_state)
        })

        context = %{context | commands: Command.collected()}
        Diagnostics.maybe_write(context, :ok)
      catch
        kind, exception ->
          Qualification.outcome(scenario_id, backend_name, :failed, %{reason: inspect(exception)})
          context = %{context | commands: Command.collected()}
          Diagnostics.maybe_write(context, exception)
          {:error, kind, exception, __STACKTRACE__}
      after
        Command.stop_collector()
        Context.stop_backend(context)
        Context.clear_actor_history(context)
      end
    else
      {:error, reason} ->
        Qualification.outcome(scenario_id, backend_name, :blocked, %{reason: inspect(reason)})

        exception =
          RuntimeError.exception(
            "E2E required #{scenario_id}/#{backend_name} unavailable: #{inspect(reason)}"
          )

        {:error, :error, exception, []}
    end
  end

  defp gate_skipped?(gate) do
    selected_gate() != :all and gate_rank(gate) > gate_rank(selected_gate())
  end

  defp gate_skip_reason(tags) do
    gate = Map.fetch!(tags, :gate)

    if gate_skipped?(gate) do
      "E2E_GATE=#{System.get_env("E2E_GATE", "all")} excludes #{gate}"
    end
  end

  defp backend_selection_skip_reason(tags) do
    if selected_backend_names(tags) == [] do
      "E2E_BACKEND=#{System.get_env("E2E_BACKEND", "reference")} excludes #{inspect(Map.fetch!(tags, :backends))}"
    end
  end

  defp known_gap_selection_skip_reason(tags) do
    if runnable_backend_names(tags) == [] do
      known_gap_skip_reason(tags)
    end
  end

  defp backend_availability_skip_reason(tags) do
    runnable_backends = runnable_backend_names(tags)

    if Enum.all?(runnable_backends, &backend_unavailable?/1) do
      Enum.map_join(runnable_backends, "; ", &backend_unavailable_reason/1)
    end
  end

  defp fixture_skip_reason(tags) do
    if requires_fixture?(tags) and not GaoBusTest.E2E.Actor.GLibFixture.available?() do
      GaoBusTest.E2E.Actor.GLibFixture.missing_reason()
    end
  end

  defp busctl_skip_reason(tags) do
    if requires_busctl?(tags) and not GaoBusTest.E2E.Actor.Busctl.available?() do
      GaoBusTest.E2E.Actor.Busctl.missing_reason()
    end
  end

  defp gdbus_skip_reason(tags) do
    if requires_gdbus?(tags) and not GaoBusTest.E2E.Actor.GDBus.available?() do
      GaoBusTest.E2E.Actor.GDBus.missing_reason()
    end
  end

  defp gate_rank(:smoke), do: 1
  defp gate_rank(:release), do: 2
  defp gate_rank(:compat), do: 3
  defp gate_rank(:stress), do: 4
  defp gate_rank(_), do: 999

  defp selected_backend_names(tags) do
    allowed = Map.fetch!(tags, :backends)
    Enum.filter(selected_backends(), &(&1 in allowed))
  end

  defp runnable_backend_names(tags) do
    known_gap = Map.get(tags, :known_gap, [])
    Enum.reject(selected_backend_names(tags), &(&1 in known_gap))
  end

  defp known_gap_skip_reason(tags) do
    tags
    |> selected_backend_names()
    |> Enum.filter(&(&1 in Map.get(tags, :known_gap, [])))
    |> case do
      [backend] -> "known gap on #{backend} (see docs/e2e-matrix.md)"
      backends -> "known gap on #{Enum.join(backends, ", ")} (see docs/e2e-matrix.md)"
    end
  end

  defp validate_known_gap!(tags) do
    known_gap = Map.get(tags, :known_gap, [])

    cond do
      :reference in known_gap ->
        raise ArgumentError, "known_gap must not include :reference"

      known_gap != [] and Map.fetch!(tags, :gate) == :smoke ->
        raise ArgumentError, "smoke scenarios must not be tagged with known_gap"

      true ->
        :ok
    end
  end

  defp backend_unavailable?(backend_name), do: backend_unavailable_reason(backend_name) != nil

  defp backend_unavailable_reason(backend_name) do
    :persistent_term.get(availability_key(backend_name), nil)
  end

  defp availability_key(backend_name), do: {__MODULE__, :backend_unavailable_reason, backend_name}

  defp probe_backend(backend_name) do
    mod = backend_mod(backend_name)

    case mod.start() do
      {:ok, state} ->
        mod.stop(state)
        nil

      {:error, {:missing_executable, executable}} ->
        "#{executable} not found on PATH"

      {:error, reason} ->
        "#{backend_name} backend unavailable: #{inspect(reason)}"
    end
  end

  defp requires_fixture?(tags), do: :glib_fixture in Map.get(tags, :actors, [])
  defp requires_busctl?(tags), do: :busctl in Map.get(tags, :actors, [])
  defp requires_gdbus?(tags), do: :gdbus in Map.get(tags, :actors, [])

  defp actor_available?(:ex_dbus), do: Code.ensure_loaded?(GaoBusTest.E2E.Actor.ExDBusClient)

  defp actor_available?(:elixir_service),
    do: Code.ensure_loaded?(GaoBusTest.E2E.Actor.ElixirService)

  defp actor_available?(:glib_fixture), do: GaoBusTest.E2E.Actor.GLibFixture.available?()
  defp actor_available?(:busctl), do: GaoBusTest.E2E.Actor.Busctl.available?()
  defp actor_available?(:gdbus), do: GaoBusTest.E2E.Actor.GDBus.available?()
  defp actor_available?(:raw), do: Code.ensure_loaded?(GaoBusTest.E2E.Actor.RawUnix)
  defp actor_available?(_actor), do: false
end
