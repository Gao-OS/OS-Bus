# File-only control in a dedicated BEAM; evaluate only the copied handler statement.
[launcher, directory] = System.argv()
~c"27" = :erlang.system_info(:otp_release)
"1.17.3" = System.version()
source = File.read!(launcher)
[statement] = source |> String.split("\n") |> Enum.filter(&String.starts_with?(&1, ":ok = :logger.add_handler(:foundation_sink,"))
path = Path.join(directory, "diagnostic-λ.log")
System.put_env("SEC09_SEC12_LOG", path)

try do
  {:ok, []} = Code.eval_string(statement, [], file: launcher)
  {:ok, %{level: :all, config: %{file: configured, type: :file},
          formatter: {:logger_formatter, %{single_line: true}}}} =
    :logger.get_handler_config(:foundation_sink)
  true = is_list(configured)
  true = to_string(configured) == path
  marker = "foundation-file-only-logger-control"
  :ok = :logger.log(:error, marker)
  :ok = :logger_std_h.filesync(:foundation_sink)
  true = String.contains?(File.read!(path), marker)
  IO.inspect(%{status: "PASS_FILE_ONLY", otp: :erlang.system_info(:otp_release),
               erts: :erlang.system_info(:version), elixir: System.version(),
               logger_std_h: :code.which(:logger_std_h), path_is_charlist: true,
               file_received_marker: true})
after
  :logger.remove_handler(:foundation_sink)
end
