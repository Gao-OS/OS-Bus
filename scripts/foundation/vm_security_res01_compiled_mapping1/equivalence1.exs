# Root-only pure control. Evaluate the actual isolated startup block, never the overlay or daemon.
"1.17.3" = System.version()
"27" = System.otp_release()
[variant, base, pure_probe] = System.argv()
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
launcher = File.read!(Path.join(variant, "launcher.exs"))
[_, rest] = String.split(launcher, "# COMPILED_MAPPING_SETUP_BEGIN\n")
[setup, _] = String.split(rest, "# COMPILED_MAPPING_SETUP_END\n")
source = File.read!(Path.join(base, "launcher.exs"))
helper = File.read!(Path.join(variant, "mapper-helper.exs"))
{_, values} = Code.eval_string(setup, [here: variant, digest: digest, source: source],
  file: "pure-isolated-actual-mapping-startup-block")
compiled = Keyword.fetch!(values, :mapping_fun)
fn_ast = Keyword.fetch!(values, :mapping_fn_ast)
embedded = Keyword.fetch!(values, :mapping_inserted_ast)
mapped_source = Keyword.fetch!(values, :mapping_source)
provenance = Keyword.fetch!(values, :mapping_provenance)
true = embedded === fn_ast
expected_source = String.replace(source, helper, "json_safe = Res01CompiledMapping1.build()\n")
true = mapped_source == expected_source
# The unchanged literal observer, except its one mapper assignment, is parsed only.
Code.string_to_quoted!(mapped_source, file: "pure-binding-check-no-launcher-evaluation")
{interpreted, _} = Code.eval_string(helper, [], file: Path.join(variant, "mapper-helper.exs"), line: 1)
{:module, :erl_eval} = :erlang.fun_info(interpreted, :module)
{:module, Res01CompiledMapping1} = :erlang.fun_info(compiled, :module)
false = :erl_eval.fun_data(compiled)
# Reuse the root-qualified pure case builders, compiling only their module AST.
probe_path = Path.join(pure_probe, "probe.exs")
{:__block__, _, [{:defmodule, _, _} = utility_ast, _run_call]} =
  Code.string_to_quoted!(File.read!(probe_path), file: probe_path)
[{MappingProbe1, _}] = Code.compile_quoted(utility_ast, probe_path)
saved = :json.decode(File.read!(Path.join(pure_probe, "SNAPSHOT_SHAPES1.json")))
cases = apply(MappingProbe1, :synthetic_cases, []) ++ apply(MappingProbe1, :snapshot_cases, [saved])
26 = length(cases)
checks = Enum.map(cases, fn row -> apply(MappingProbe1, :check_case, [row, interpreted, compiled]) end)
all_equal = Enum.all?(checks, &(&1.outputs_equal and &1.interpreted_equals_expected and &1.compiled_equals_expected))
report = %{kind: "res01_compiled_mapping_equivalence_v1", diagnostic_only: true, product_qualified: false,
  readiness: "L0", inspected_daemon_executions: 0, vm_executions: 0,
  actual_startup_block_evaluated: true, exact_fn_ast_equal: embedded === fn_ast,
  helper_source_sha256: digest.(helper), fn_ast_sha256: digest.(:erlang.term_to_binary(fn_ast, [:deterministic])),
  one_binding_only: mapped_source == expected_source, mapped_launcher_sha256: digest.(mapped_source),
  interpreted_fun_info: apply(MappingProbe1, :info, [interpreted]),
  compiled_fun_info: apply(MappingProbe1, :info, [compiled]), provenance: provenance,
  case_count: length(cases), snapshot_count: length(saved["snapshots"]), equality: checks,
  all_equal: all_equal, throughput_measurements: 0,
  limitation: "Reconstructed/synthetic equality controls do not qualify original400ms daemon regression"}
IO.puts(IO.iodata_to_binary(:json.encode(report)))
true = all_equal
