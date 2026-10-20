ExUnit.start()

defmodule Res01SerializationTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  @launcher Path.join(__DIR__, "launcher.exs")

  setup do
    expressions = @launcher |> File.read!() |> expressions()
    {:ok, expressions: expressions}
  end

  test "actual FIXTURE emission preserves absent configuration as JSON null", context do
    [emission] =
      Enum.filter(context.expressions, fn expression ->
        match?(
          {{:., _, [{:__aliases__, _, [:IO]}, :puts]}, _, [{:<>, _, ["FIXTURE ", _]}]},
          expression
        )
      end)

    bindings = [
      pin: "original-pin",
      digest: fn _ -> "transformed-digest" end,
      transformed: "not evaluated",
      res01_limits: %{global: %{connections: 6}, uid: %{connections: 4}},
      defaults_profile: %{global: %{connections: 256}},
      controls: %{max_names_per_peer: 2}
    ]

    assert "FIXTURE " <> payload =
             capture_io(fn -> Code.eval_quoted(emission, bindings, file: @launcher) end)

    assert %{
             "event" => "res01_provenance",
             "config_file" => :null,
             "inherited_listener" => false,
             "max_connections" => 256,
             "profile" => %{"global" => %{"connections" => 6}, "uid" => %{"connections" => 4}}
           } = :json.decode(String.trim_trailing(payload, "\n"))
  end

  test "actual observer walker preserves null and scalar types inside maps lists and tuples", context do
    walker = observer_walker(context.expressions)

    input = %{
      nullable: nil,
      values: [nil, true, false, 0, 42],
      tuple: {:authenticated, nil, false, 3},
      nested: [%{absent: nil, phase: :connected}]
    }

    assert round_trip(walker, input) == %{
             "nullable" => :null,
             "values" => [:null, true, false, 0, 42],
             "tuple" => ["authenticated", :null, false, 3],
             "nested" => [%{"absent" => :null, "phase" => "connected"}]
           }
  end

  test "actual observer walker keeps nullable snapshot fields distinct from false and zero", context do
    walker = observer_walker(context.expressions)

    input = %{
      children: [%{unique: nil, phase: :authenticating, auth_phase: nil}],
      accounting: %{reload: nil, retired: %{}, reservations: %{}},
      limits: %{xml: %{limits: nil, queues: nil}, reservations: 0},
      names: %{xml_limits: false},
      matches: %{xml_limits: false}
    }

    assert round_trip(walker, input) == %{
             "children" => [
               %{"unique" => :null, "phase" => "authenticating", "auth_phase" => :null}
             ],
             "accounting" => %{"reload" => :null, "retired" => %{}, "reservations" => %{}},
             "limits" => %{"xml" => %{"limits" => :null, "queues" => :null}, "reservations" => 0},
             "names" => %{"xml_limits" => false},
             "matches" => %{"xml_limits" => false}
           }
  end

  defp expressions(source) do
    {:__block__, _, expressions} = Code.string_to_quoted!(source)
    expressions
  end

  defp observer_walker(launcher_expressions) do
    [observer_assignment] =
      Enum.filter(launcher_expressions, fn expression ->
        match?({:=, _, [{:observer, _, _}, _]}, expression)
      end)

    {:=, _, [_, {:sigil_S, _, [{:<<>>, _, [observer_source]}, []]}]} = observer_assignment
    assert is_binary(observer_source)

    [walker_assignment] =
      observer_source
      |> expressions()
      |> Enum.filter(fn expression ->
        match?({:=, _, [{:json_safe, _, _}, {:fn, _, _}]}, expression)
      end)

    # Only the anonymous-function assignment is evaluated. The observer's
    # snapshot function and all launcher setup/daemon execution remain inert.
    {walker, _bindings} = Code.eval_quoted(walker_assignment, [], file: @launcher)
    walker
  end

  defp round_trip(walker, input) do
    safe = walker.(walker, input)
    :json.decode(IO.iodata_to_binary(:json.encode(safe)))
  end
end
