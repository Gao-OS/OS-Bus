# Root-only guarded timing overlay; the base launcher and daemon remain frozen.
unless File.read!("/etc/osbus-security-guest") == "isolated-vm\n",
  do: raise("disposable guest required")
[run_socket, _policy] = System.argv()
unless run_socket == "/run/osbus-security/res01/bus", do: raise("private measurement socket required")
base = System.fetch_env!("RES01_MEASUREMENT_BASE")
here = __DIR__
bindings = :json.decode(File.read!(Path.join(here, "BASE_BINDINGS1.json")))
recipes_bytes = File.read!(Path.join(here, "recipe1.json"))
recipes = :json.decode(recipes_bytes)
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
source = File.read!(Path.join(base, "launcher.exs"))
unless digest.(source) == bindings["launcher.exs"]["sha256"], do: raise("base launcher drift")
replace = fn source, changes ->
  Enum.reduce(changes, source, fn change, text ->
    unless length(String.split(text, change["before"])) == change["count"] + 1,
      do: raise("measurement launcher anchor drift")
    String.replace(text, change["before"], change["after"])
  end)
end
# COMPILED_MAPPING_SETUP_BEGIN
mapping_started = System.monotonic_time(:nanosecond)
mapping_bindings_bytes = File.read!(Path.join(here, "MAPPING_BINDINGS1.json"))
unless digest.(mapping_bindings_bytes) == "9af8289d37065c439fd974f7333e888f246fb4c75379391eb96aae30af14eb21", do: raise("compiled mapping bindings drift")
mapping_bindings = :json.decode(mapping_bindings_bytes)
mapping_helper_path = Path.join(here, "mapper-helper.exs")
mapping_helper_bytes = File.read!(mapping_helper_path)
unless digest.(mapping_helper_bytes) == mapping_bindings["helper_source_sha256"] and
  byte_size(mapping_helper_bytes) == 598, do: raise("compiled mapping helper drift")
{:=, _, [{:json_safe, _, _}, {:fn, _, _} = mapping_fn_ast]} =
  Code.string_to_quoted!(mapping_helper_bytes, file: mapping_helper_path, line: 1)
mapping_fn_ast_sha256 = digest.(:erlang.term_to_binary(mapping_fn_ast, [:deterministic]))
unless mapping_fn_ast_sha256 == mapping_bindings["fn_ast_sha256"], do: raise("compiled mapping fn AST drift")
mapping_factory_ast = quote do
  defmodule Res01CompiledMapping1 do
    def build(), do: unquote(mapping_fn_ast)
  end
end
{:defmodule, _, [_, [do: {:def, _, [_, [do: mapping_inserted_ast]]}]]} = mapping_factory_ast
unless mapping_inserted_ast === mapping_fn_ast, do: raise("compiled mapping embedded AST drift")
unless :code.is_loaded(Res01CompiledMapping1) == false, do: raise("compiled mapping module already loaded")
[{Res01CompiledMapping1, mapping_factory_beam}] = Code.compile_quoted(mapping_factory_ast, mapping_helper_path)
mapping_fun = apply(Res01CompiledMapping1, :build, [])
unless :erlang.fun_info(mapping_fun, :module) == {:module, Res01CompiledMapping1} and
  :erl_eval.fun_data(mapping_fun) == false, do: raise("compiled mapping backend drift")
unless length(String.split(source, mapping_helper_bytes)) == 2, do: raise("compiled mapping binding anchor drift")
mapping_source = String.replace(source, mapping_helper_bytes, mapping_bindings["binding_after"])
mapping_provenance = %{kind: "res01_compiled_mapping_diagnostic_v1", diagnostic_only: true,
  helper_source_sha256: digest.(mapping_helper_bytes), helper_source_bytes: byte_size(mapping_helper_bytes),
  mapping_bindings_sha256: digest.(mapping_bindings_bytes), fn_ast_sha256: mapping_fn_ast_sha256,
  exact_embedded_fn_ast: mapping_inserted_ast === mapping_fn_ast,
  factory_beam_sha256: digest.(mapping_factory_beam),
  helper_module: Atom.to_string(Res01CompiledMapping1),
  helper_fun_name: mapping_fun |> :erlang.fun_info(:name) |> elem(1) |> Atom.to_string(),
  helper_fun_arity: mapping_fun |> :erlang.fun_info(:arity) |> elem(1),
  helper_fun_env_entries: mapping_fun |> :erlang.fun_info(:env) |> elem(1) |> length(),
  interpreted_backend: false, mapping_launcher_sha256: digest.(mapping_source),
  startup_elapsed_ns: System.monotonic_time(:nanosecond) - mapping_started,
  authority_deadline_reset: false, held_deadline_changed: false}
# COMPILED_MAPPING_SETUP_END
transformed = replace.(mapping_source, recipes["launcher"])
provenance = %{kind: "res01_timing_experiment_v1", diagnostic_only: true,
  base_launcher_sha256: digest.(source), instrumented_launcher_sha256: digest.(transformed),
  recipe_sha256: digest.(recipes_bytes), overlay_launcher_sha256: digest.(File.read!(__ENV__.file)),
  compiled_mapping: mapping_provenance,
  event_limit: 200_000, clock: "daemon_local_elapsed_ns",
  overhead: "timing reads and bounded metadata retained within unchanged deadlines"}
Process.put(:res01_measurement_origin, System.monotonic_time(:nanosecond))
Process.put(:res01_measurement_events, [])
Process.put(:res01_measurement_count, 0)
Process.put(:res01_measurement_overflow, false)
try do
  Code.eval_string(transformed,
    [measurement_replace: replace, measurement_original_recipe: recipes["original_daemon"],
     measurement_provenance: provenance], file: Path.join(base, "launcher.exs"))
after
  # Only after the original daemon loop terminates: no held-phase chatter/writes.
  records = %{kind: "res01_daemon_timing_v1", provenance: provenance,
    overflow: Process.get(:res01_measurement_overflow),
    events: Enum.reverse(Process.get(:res01_measurement_events)),
    snapshot_count: Process.get(:res01_measurement_ordinal, 0)}
  File.write!("/run/osbus-security/res01/daemon-measurement.json",
    IO.iodata_to_binary(:json.encode(records)) <> "\n")
end
