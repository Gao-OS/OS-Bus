ExUnit.start()

defmodule GaoBus.Foundation.PRO05.FixtureNullTest do
  use ExUnit.Case, async: false

  test "fixture emit encodes nested absent values as null without changing literal values" do
    source = File.read!(Path.join(__DIR__, "daemon.exs"))

    {_, expressions} =
      source
      |> Code.string_to_quoted!()
      |> Macro.prewalk([], fn
        {:=, _, [{:emit, _, _}, expression]} = node, found ->
          {node, [expression | found]}

        node, found ->
          {node, found}
      end)

    assert [expression] = expressions
    {emit, []} = Code.eval_quoted(expression)

    payload = %{
      peer_options: %{xml_limits: nil, frame_options: %{pending_fd_timeout: nil}},
      resources: %{processes: [%{error: nil, pid: nil, metrics: nil}]},
      complete: true,
      forced: false,
      count: 3,
      elapsed_ms: 1.5,
      path: "/run/pro05/config.xml",
      literal: "nil"
    }

    output = ExUnit.CaptureIO.capture_io(fn -> emit.(payload) end)
    assert "FIXTURE " <> encoded = output

    assert :json.decode(encoded) == %{
             "peer_options" => %{
               "xml_limits" => :null,
               "frame_options" => %{"pending_fd_timeout" => :null}
             },
             "resources" => %{
               "processes" => [%{"error" => :null, "pid" => :null, "metrics" => :null}]
             },
             "complete" => true,
             "forced" => false,
             "count" => 3,
             "elapsed_ms" => 1.5,
             "path" => "/run/pro05/config.xml",
             "literal" => "nil"
           }
  end

  test "ready configuration encodes absent config as JSON null and retains configured paths" do
    previous = Application.fetch_env(:gao_bus, :config_file)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:gao_bus, :config_file, value)
        :error -> Application.delete_env(:gao_bus, :config_file)
      end
    end)

    source = File.read!(Path.join(__DIR__, "daemon.exs"))

    {_, expressions} =
      source
      |> Code.string_to_quoted!()
      |> Macro.prewalk([], fn
        {:config_file, expression} = node, found -> {node, [expression | found]}
        node, found -> {node, found}
      end)

    assert [expression] = expressions

    for setting <- [:absent, nil, "/run/pro05/config.xml"] do
      if setting == :absent,
        do: Application.delete_env(:gao_bus, :config_file),
        else: Application.put_env(:gao_bus, :config_file, setting)

      {value, []} = Code.eval_quoted(expression)
      decoded = :json.decode(:json.encode(%{config_file: value}) |> IO.iodata_to_binary())
      expected = if setting in [:absent, nil], do: :null, else: setting
      assert decoded == %{"config_file" => expected}
    end
  end
end
