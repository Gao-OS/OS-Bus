defmodule GaoBusTest.E2E.Qualification do
  @moduledoc "Required scenario/backend/actor accounting, independent of ExUnit's test count."

  alias GaoBusTest.E2E.Selection

  def strict?, do: System.get_env("E2E_STRICT") == "1"

  def child_spec(opts),
    do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}, restart: :temporary}

  def start_link(opts) do
    Agent.start_link(
      fn ->
        %{
          expected: Keyword.fetch!(opts, :expected),
          rows: %{},
          metadata: %{},
          dir: Keyword.fetch!(opts, :dir)
        }
      end,
      name: __MODULE__
    )
  end

  def start!(expected, dir) do
    {:ok, _pid} = start_link(expected: expected, dir: dir)

    write_report(dir, report(expected, [], phase: :selected))
  end

  def snapshot_report do
    Agent.get(__MODULE__, fn state ->
      report(state.expected, Map.values(state.rows), Map.to_list(state.metadata))
    end)
  end

  def record_skip(tags, reason) do
    selected =
      Agent.get(__MODULE__, fn state ->
        Enum.filter(state.expected, &(&1.e2e_id == tags.e2e_id))
      end)

    Enum.each(selected, fn row ->
      begin(tags, row.backend)
      outcome(row.e2e_id, row.backend, :skipped, %{reason: reason})
    end)
  end

  def metadata(key, value) do
    update(fn state -> put_in(state, [:metadata, key], value) end)
  end

  def begin(tags, backend) do
    update(fn state ->
      key = {tags.e2e_id, backend, :session}
      expected = Enum.find(state.expected, &(row_key(&1) == key))

      row =
        if Map.has_key?(state.rows, key) do
          %{state.rows[key] | status: :duplicate}
        else
          Map.merge(expected || %{e2e_id: tags.e2e_id, backend: backend, profile: :session}, %{
            actors: tags.actors,
            actors_executed: [],
            status: :running,
            evidence: %{}
          })
        end

      put_in(state, [:rows, key], row)
    end)
  end

  def actor(context, actor, evidence \\ %{}) do
    update_row(context.scenario_id, context.backend_name, fn row ->
      %{
        row
        | actors_executed: Enum.uniq([actor | row.actors_executed]),
          evidence: Map.put(row.evidence, actor, evidence)
      }
    end)
  end

  def backend_ready(context, evidence) do
    update_row(
      context.scenario_id,
      context.backend_name,
      &Map.put(&1, :backend_evidence, evidence)
    )
  end

  def outcome(id, backend, status, evidence \\ %{}) do
    update_row(id, backend, fn row ->
      status = if row.status == :duplicate, do: :duplicate, else: status
      row |> Map.put(:status, status) |> Map.put(:outcome, evidence)
    end)
  end

  def finish!(stats) do
    state = Agent.get(__MODULE__, & &1)
    metadata = Map.put(state.metadata, :stats, stats)
    result = report(state.expected, Map.values(state.rows), Map.to_list(metadata))
    {:ok, path} = write_report(state.dir, result)
    Agent.stop(__MODULE__)

    case result.result do
      :ok -> IO.puts("E2E qualification passed: #{length(state.expected)} combinations; #{path}")
      {:error, errors} -> raise "E2E qualification failed: #{inspect(errors)}; evidence: #{path}"
    end
  end

  def evaluate([], _executed), do: {:error, [:zero_selection]}

  def evaluate(expected, executed) do
    errors =
      Enum.flat_map(expected, fn row ->
        case Enum.filter(executed, &(row_key(&1) == row_key(row))) do
          [] -> [{:not_executed, row.e2e_id, row.backend}]
          [result] -> result_errors(row, result)
          _multiple -> [{:duplicate_execution, row.e2e_id, row.backend}]
        end
      end) ++
        for(
          row <- executed,
          not Enum.any?(expected, &(row_key(&1) == row_key(row))),
          do: {:unexpected_execution, row.e2e_id, row.backend}
        )

    if errors == [], do: :ok, else: {:error, errors}
  end

  def report(expected, executed, metadata \\ []) do
    outcomes = Enum.map(expected, &normalize_outcome(&1, executed))

    unexpected =
      Enum.reject(executed, fn row -> Enum.any?(expected, &(row_key(&1) == row_key(row))) end)

    failures = metadata |> Keyword.get(:stats, %{}) |> Map.get(:failures, 0)
    result = evaluate(expected, executed)

    errors =
      case result do
        :ok -> []
        {:error, errors} -> errors
      end

    errors = if failures > 0, do: [{:exunit_failures, failures} | errors], else: errors

    %{
      manifest_version: Selection.version(),
      selected: expected,
      executed: executed,
      outcomes: outcomes,
      unexpected: unexpected,
      counts: counts(expected, outcomes) |> Map.put(:unexpected, length(unexpected)),
      per_backend:
        Map.new(Enum.uniq(Enum.map(expected, & &1.backend)), fn backend ->
          {backend,
           counts(
             Enum.filter(expected, &(&1.backend == backend)),
             Enum.filter(outcomes, &(&1.backend == backend))
           )}
        end),
      result: if(errors == [], do: :ok, else: {:error, errors}),
      metadata: Map.new(metadata),
      runtime: %{
        elixir: System.version(),
        otp: to_string(:erlang.system_info(:otp_release)),
        system_version: to_string(:erlang.system_info(:system_version)),
        cwd: File.cwd!()
      }
    }
  end

  defp counts(expected, outcomes) do
    %{
      selected: length(expected),
      executed: Enum.count(outcomes, &(&1.actors_executed != [])),
      passed: Enum.count(outcomes, &(&1.status == :passed)),
      failed: Enum.count(outcomes, &(&1.status == :failed)),
      blocked: Enum.count(outcomes, &(&1.status == :blocked)),
      skipped: Enum.count(outcomes, &Map.get(&1, :skipped, false))
    }
  end

  defp normalize_outcome(row, executed) do
    case Enum.filter(executed, &(row_key(&1) == row_key(row))) do
      [] ->
        Map.merge(row, %{status: :blocked, reason: :not_executed})

      [%{status: :passed} = result] ->
        case result_errors(row, result) do
          [] -> result
          errors -> Map.merge(result, %{status: :blocked, reason: errors})
        end

      [%{status: :skipped} = result] ->
        Map.merge(result, %{status: :blocked, skipped: true, reason: :unexpected_skip})

      [%{status: :duplicate} = result] ->
        Map.merge(result, %{status: :failed, reason: :duplicate_execution})

      [%{status: :running} = result] ->
        Map.merge(result, %{status: :blocked, reason: :unfinished_execution})

      [result] ->
        result

      _multiple ->
        Map.merge(row, %{status: :failed, reason: :duplicate_execution})
    end
  end

  def write_report(dir, report) do
    File.mkdir_p!(dir)
    path = Path.join(dir, "qualification.json")
    temporary = path <> ".#{System.unique_integer([:positive])}.tmp"
    File.write!(temporary, Jason.encode!(json_value(report), pretty: true))
    File.rename!(temporary, path)
    {:ok, path}
  end

  defp result_errors(row, %{status: :passed} = result) do
    for actor <- row.actors,
        actor not in result.actors_executed,
        do: {:missing_actor_execution, row.e2e_id, row.backend, actor}
  end

  defp result_errors(row, result),
    do: [{:required_result, row.e2e_id, row.backend, result.status}]

  defp row_key(row), do: {row.e2e_id, row.backend, row.profile}

  defp update(fun) do
    if strict?() and Process.whereis(__MODULE__) do
      Agent.update(__MODULE__, fn state ->
        state = fun.(state)

        write_report(
          state.dir,
          report(state.expected, Map.values(state.rows), Map.to_list(state.metadata))
        )

        state
      end)
    else
      :ok
    end
  end

  defp update_row(id, backend, fun) do
    update(fn state ->
      key = {id, backend, :session}
      if Map.has_key?(state.rows, key), do: update_in(state, [:rows, key], fun), else: state
    end)
  end

  defp json_value(value) when is_tuple(value), do: value |> Tuple.to_list() |> json_value()
  defp json_value(value) when is_list(value), do: Enum.map(value, &json_value/1)

  defp json_value(value) when is_map(value),
    do: Map.new(value, fn {key, val} -> {key, json_value(val)} end)

  defp json_value(value), do: value
end
