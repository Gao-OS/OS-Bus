defmodule GaoBusTest.E2E.Diagnostics do
  @moduledoc """
  Writes scenario artifacts for E2E failures and retained runs.
  """

  alias GaoBusTest.E2E.{Context, Qualification}

  def keep_artifacts?, do: System.get_env("E2E_KEEP_ARTIFACTS") == "1" or Qualification.strict?()

  def write(%Context{} = context, reason) do
    context = %{context | actors: Context.actor_history(context)}
    dir = context.artifacts_dir || default_artifact_dir(context)
    File.mkdir_p!(dir)

    File.write!(Path.join(dir, "context.json"), encode(context_payload(context, reason)))
    File.write!(Path.join(dir, "backend.log"), backend_log(context))
    File.write!(Path.join(dir, "fixture.log"), fixture_log(context, reason))
    File.write!(Path.join(dir, "commands.jsonl"), commands_jsonl(context))

    {:ok, dir}
  end

  def maybe_write(%Context{} = context, reason) do
    if keep_artifacts?() or failure?(reason), do: write(context, reason), else: :ok
  end

  def default_artifact_dir(%Context{} = context) do
    unique_id = "#{System.system_time(:millisecond)}_#{System.unique_integer([:positive])}"

    Path.join([
      Mix.Project.build_path(),
      "e2e_artifacts",
      context.scenario_id || "unknown",
      Atom.to_string(context.backend_name || :unknown),
      unique_id
    ])
  end

  defp context_payload(%Context{} = context, reason) do
    %{
      scenario_id: context.scenario_id,
      backend_name: context.backend_name,
      bus_address: context.bus_address,
      tmpdir: context.tmpdir,
      started_at: DateTime.to_iso8601(context.started_at),
      metadata: context.metadata,
      backend: backend_metadata(context),
      actors: Map.keys(context.actors),
      reason: inspect(reason)
    }
  end

  defp backend_log(%Context{backend_mod: mod, backend_state: state}) do
    state
    |> mod.diagnostics()
    |> Map.get(:log, "")
    |> to_string()
  rescue
    exception -> "backend diagnostics failed: #{Exception.message(exception)}"
  end

  defp backend_metadata(%Context{backend_mod: mod, backend_state: state}) do
    mod.diagnostics(state) |> Map.drop([:log])
  rescue
    exception -> %{diagnostics_error: Exception.message(exception)}
  end

  defp fixture_log(%Context{actors: actors}) do
    actors
    |> Map.get(:glib_fixture, %{})
    |> Map.get(:log, "")
    |> to_string()
  end

  defp fixture_log(%Context{} = context, reason) do
    case fixture_log(context) do
      "" -> fixture_log_from_failure(reason)
      log -> log
    end
  end

  defp fixture_log_from_failure(%MatchError{term: {:error, {_reason, log}, context_or_other}})
       when is_binary(log) do
    case context_or_other do
      %Context{} = context ->
        case fixture_log(context) do
          "" -> log
          context_log -> context_log
        end

      _ ->
        log
    end
  end

  defp fixture_log_from_failure(%MatchError{term: {:error, _reason, %Context{} = context}}) do
    fixture_log(context)
  end

  defp fixture_log_from_failure(_reason), do: ""

  defp commands_jsonl(%Context{commands: commands}) do
    commands
    |> Enum.map(fn command ->
      command |> Map.from_struct() |> Map.update!(:env, &Map.new/1) |> encode() |> Kernel.<>("\n")
    end)
    |> IO.iodata_to_binary()
  end

  defp failure?(:ok), do: false
  defp failure?(nil), do: false
  defp failure?(_), do: true

  defp encode(value), do: Jason.encode!(value)
end
