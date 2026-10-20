json_safe = fn walk, value ->
  cond do
    is_nil(value) -> :null
    is_struct(value) -> walk.(walk, Map.from_struct(value))
    is_map(value) -> Map.new(value, fn {k, v} ->
      key = if is_atom(k) or is_integer(k), do: to_string(k), else: if(is_binary(k), do: k, else: inspect(k))
      {key, walk.(walk, v)}
    end)
    is_tuple(value) -> walk.(walk, Tuple.to_list(value))
    is_list(value) -> Enum.map(value, &walk.(walk, &1))
    is_pid(value) or is_reference(value) -> inspect(value)
    is_atom(value) and value not in [true, false, nil] -> to_string(value)
    true -> value
  end
end
