# Root parse-only entry: no inspected AST evaluation or macro expansion.
"1.17.3" = System.version()
"27" = System.otp_release()
[overlay, launcher, daemon, helper, setup] = System.argv()
Code.string_to_quoted!(File.read!(overlay), file: overlay)
quoted = Code.string_to_quoted!(File.read!(launcher), file: launcher)
Code.string_to_quoted!(File.read!(daemon), file: daemon)
helper_ast = Code.string_to_quoted!(File.read!(helper), file: helper, line: 1)
Code.string_to_quoted!(File.read!(setup), file: setup)
walk = fn walk, node ->
  own = case node do
    {:=, _, [{:observer, _, nil}, {:sigil_S, _, [{:<<>>, _, [bytes]}, []]}]} when is_binary(bytes) -> [bytes]
    _ -> []
  end
  children = cond do
    is_tuple(node) -> Tuple.to_list(node)
    is_list(node) -> node
    true -> []
  end
  own ++ Enum.flat_map(children, &walk.(walk, &1))
end
[observer] = walk.(walk, quoted)
source = File.read!(daemon)
anchor = "Stream.repeatedly(fn -> IO.read(:stdio, :line) end)"
2 = length(String.split(source, anchor))
3 = length(String.split(source, "GaoBus.Limits.defaults()"))
transformed = source |> String.replace("GaoBus.Limits.defaults()", "res01_limits")
  |> String.replace(anchor, observer <> "\n" <> anchor)
Code.string_to_quoted!(transformed, file: "parse-only-compiled-mapping-inner-daemon")
{:=, _, [{:json_safe, _, _}, {:fn, _, _} = fn_ast]} = helper_ast
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
IO.puts(IO.iodata_to_binary(:json.encode(%{kind: "res01_compiled_mapping_parse_only_v1",
  parsed: 6, evaluation_invocations: 0, macro_expansions: 0, daemon_executions: 0, vm_executions: 0,
  actual_ast_observer_sha256: digest.(observer), actual_ast_observer_bytes: byte_size(observer),
  helper_source_sha256: digest.(File.read!(helper)), helper_fn_ast_sha256: digest.(:erlang.term_to_binary(fn_ast, [:deterministic])),
  actual_transformed_daemon_sha256: digest.(transformed), actual_transformed_daemon_bytes: byte_size(transformed)})))
