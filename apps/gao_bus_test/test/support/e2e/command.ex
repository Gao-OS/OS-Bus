defmodule GaoBusTest.E2E.Command do
  @moduledoc """
  Unified external command runner for E2E actors.
  """

  alias GaoBusTest.E2E.Result.Command, as: CommandResult
  alias GaoBusTest.E2E.ChildProcess

  @default_timeout 5_000
  @collector_key {__MODULE__, :collector}

  def run(command, args \\ [], opts \\ []) when is_binary(command) and is_list(args) do
    timeout = Keyword.get(opts, :timeout, @default_timeout)
    env = Keyword.get(opts, :env, [])
    cwd = Keyword.get(opts, :cwd)
    started = System.monotonic_time(:millisecond)

    command_result =
      case executable(command) do
        nil ->
          result(command, args, env, cwd, started,
            stderr: "executable not found: #{command}",
            exit_status: 127
          )

        executable ->
          case ChildProcess.start(command: executable, args: args, env: env, cwd: cwd) do
            {:ok, child} ->
              try do
                output = ChildProcess.await_exit(child, timeout)

                result(executable, args, env, cwd, started,
                  stdout: output.output,
                  stderr:
                    if(output.timed_out?, do: "command timed out after #{timeout}ms", else: ""),
                  exit_status: if(output.timed_out?, do: nil, else: output.exit_status),
                  timed_out?: output.timed_out?
                )
              after
                ChildProcess.stop(child)
              end

            {:error, reason} ->
              result(executable, args, env, cwd, started,
                stderr: inspect(reason),
                exit_status: 127
              )
          end
      end

    record(command_result)
    command_result
  end

  def start_collector do
    Process.put(@collector_key, [])
    :ok
  end

  def collected do
    Process.get(@collector_key, [])
    |> Enum.reverse()
  end

  def stop_collector do
    Process.delete(@collector_key)
    :ok
  end

  defp executable(path) do
    cond do
      Path.type(path) == :absolute and File.exists?(path) -> path
      String.contains?(path, "/") and File.exists?(path) -> path
      true -> System.find_executable(path)
    end
  end

  defp result(command, args, env, cwd, started, attrs) do
    %CommandResult{
      command: command,
      args: args,
      env: env,
      cwd: cwd,
      stdout: Keyword.get(attrs, :stdout, ""),
      stderr: Keyword.get(attrs, :stderr, ""),
      exit_status: Keyword.get(attrs, :exit_status),
      timed_out?: Keyword.get(attrs, :timed_out?, false),
      duration_ms: System.monotonic_time(:millisecond) - started
    }
  end

  defp record(%CommandResult{} = result) do
    case Process.get(@collector_key) do
      nil -> :ok
      commands -> Process.put(@collector_key, [result | commands])
    end
  end
end
