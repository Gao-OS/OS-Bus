ExUnit.start()

defmodule ResourcesCurrentMappingTest do
  use ExUnit.Case, async: false

  setup_all do
    launcher = Path.join(System.fetch_env!("RESOURCES_ADAPTER"), "res01/launcher.exs")
    source = File.read!(launcher)
    final = "Code.eval_string(mapping_source, [], file: Path.join(here, \"base-launcher.exs\"))\n"
    unless String.ends_with?(source, final), do: raise("direct launcher boundary drift")
    setup = binary_part(source, 0, byte_size(source) - byte_size(final))
    # Execute the actual pinned mapper setup without evaluating the daemon source.
    {mapper, _} = Code.eval_string(setup <> "\nmapping_fun\n", [], file: launcher)
    {:ok, mapper: mapper}
  end

  test "actual compiled mapper preserves canonical native reference identity", %{mapper: mapper} do
    first = make_ref()
    second = make_ref()
    canonical = fn reference -> List.to_string(:erlang.ref_to_list(reference)) end
    assert mapper.(mapper, first) == canonical.(first)
    assert String.starts_with?(mapper.(mapper, first), "#Ref<")
    assert mapper.(mapper, first) != inspect(first)
    assert mapper.(mapper, first) != mapper.(mapper, second)
    assert mapper.(mapper, [first, {first, second}]) ==
             [canonical.(first), [canonical.(first), canonical.(second)]]
    assert :erlang.fun_info(mapper, :module) == {:module, Res01CompiledMapping1}
    assert :erl_eval.fun_data(mapper) == false
  end

  test "actual mapper retains scalar null map and PID observations", %{mapper: mapper} do
    reference = make_ref()
    input = %{nil_value: nil, enabled: true, disabled: false, number: 7,
              text: "literal", actor: self(), nested: [reference, :connected]}
    assert mapper.(mapper, input) == %{
             "nil_value" => :null, "enabled" => true, "disabled" => false,
             "number" => 7, "text" => "literal", "actor" => inspect(self()),
             "nested" => [List.to_string(:erlang.ref_to_list(reference)), "connected"]
           }
  end
end
