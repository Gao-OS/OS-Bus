"""Root-only Elixir/Nix parse entry; no inspected source evaluation or VM."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from measurement import apply_recipe

HERE = Path(__file__).resolve().parent
ELIXIR = '/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3'
OTP = '/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6'
PROBE = '''
"1.17.3" = System.version()
[overlay, launcher, daemon] = System.argv()
Code.string_to_quoted!(File.read!(overlay), file: overlay)
quoted = Code.string_to_quoted!(File.read!(launcher), file: launcher)
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
Code.string_to_quoted!(source, file: daemon)
anchor = "Stream.repeatedly(fn -> IO.read(:stdio, :line) end)"
2 = length(String.split(source, anchor))
3 = length(String.split(source, "GaoBus.Limits.defaults()"))
transformed = source |> String.replace("GaoBus.Limits.defaults()", "res01_limits")
  |> String.replace(anchor, observer <> "\\n" <> anchor)
Code.string_to_quoted!(transformed, file: "parse-only-instrumented-daemon")
digest = fn bytes -> Base.encode16(:crypto.hash(:sha256, bytes), case: :lower) end
IO.puts(IO.iodata_to_binary(:json.encode(%{parsed: 4, evaluation_invocations: 0,
  macro_expansions: 0, daemon_executions: 0, vm_executions: 0,
  actual_ast_observer_sha256: digest.(observer), actual_ast_observer_bytes: byte_size(observer),
  actual_transformed_daemon_sha256: digest.(transformed), actual_transformed_daemon_bytes: byte_size(transformed)})))
'''


def main():
    assert sys.argv[1:] == [] and sys.dont_write_bytecode is True
    bindings = json.loads((HERE / 'BASE_BINDINGS1.json').read_text())
    recipe_bytes = (HERE / 'recipe1.json').read_bytes()
    recipes = json.loads(recipe_bytes)
    base = HERE.parent / 'vm_security_res01'
    original = HERE.parent / 'vm_security'
    for key, path in [('launcher.exs', base / 'launcher.exs'), ('original/daemon.exs', original / 'daemon.exs')]:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == bindings[key]['sha256']
    pins = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file()}
    environment = {k: v for k, v in os.environ.items() if not k.startswith('DBUS_')}
    environment['PATH'] = f'{ELIXIR}/bin:{OTP}/bin:' + environment['PATH']
    with tempfile.TemporaryDirectory(prefix='res01-parse-only-') as temporary:
        folder = Path(temporary)
        launcher = folder / 'launcher-instrumented.exs'
        daemon = folder / 'daemon-instrumented.exs'
        launcher.write_text(apply_recipe((base / 'launcher.exs').read_text(), recipes['launcher']))
        daemon.write_text(apply_recipe((original / 'daemon.exs').read_text(), recipes['original_daemon']))
        commands = [[ELIXIR + '/bin/elixir', '--erl', '+S 2:2', '-e', PROBE, '--',
            str(HERE / 'launcher.exs'), str(launcher), str(daemon)],
            ['/run/current-system/sw/bin/nix-instantiate', '--parse', str(HERE / 'test.nix')]]
        results = []
        for command in commands:
            actual = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=20, env=environment)
            result = dict(argv=command, returncode=actual.returncode, stdout=actual.stdout.decode(),
                stderr=actual.stderr.decode(), timeout_seconds=20)
            results.append(result)
            assert actual.returncode == 0, result
        proof = json.loads(results[0]['stdout'])
        assert proof['parsed'] == 4 and proof['evaluation_invocations'] == proof['macro_expansions'] == proof['daemon_executions'] == proof['vm_executions'] == 0
    assert pins == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in HERE.iterdir() if p.is_file()}
    print(json.dumps(dict(kind='res01_measurement_parse_only', passed=True, sources=pins,
        recipe_sha256=hashlib.sha256(recipe_bytes).hexdigest(), actual_ast_proof=proof,
        commands=results, nix_parsed=1, new_vm_executions=0), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
