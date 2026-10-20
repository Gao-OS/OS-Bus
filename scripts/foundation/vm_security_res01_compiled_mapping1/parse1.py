"""Root-only narrow recorder entry. Inert on import; inspected targets never executed."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
REPORT = Path("/data/development/Gao-OS/OS-Bus/.trees/os-bus-foundation/test/reports/foundation/continuation-20261011-full-goal/environment/m1-res01-measurement1/execution1/mapping-repair1")
MANIFEST_SHA256 = "dd60fb4df3dbfc330b62346c4f21a5da871df7c93094815c6fa9182f56a8eb8c"


def inputs():
    data = (REPORT / 'SOURCE_MANIFEST1.json').read_bytes()
    assert hashlib.sha256(data).hexdigest() == MANIFEST_SHA256, 'compiled mapping manifest drift'
    manifest = json.loads(data)
    for row in manifest['preservation_rows'] + manifest['variant_rows'] + manifest['preparation_rows']:
        path = Path(row['path'])
        actual = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                      bytes=path.stat().st_size, mode=stat.S_IMODE(path.stat().st_mode))
        assert actual == row, ('compiled mapping input drift', str(path))
    return manifest


def child(argv, manifest):
    environment = dict(PATH=manifest['runtime']['otp'] + '/bin:/run/current-system/sw/bin:/usr/bin:/bin',
                       HOME=os.environ['HOME'], LANG='C.UTF-8', LC_ALL='C.UTF-8', TZ='UTC',
                       PYTHONDONTWRITEBYTECODE='1', ERL_CRASH_DUMP='/dev/null')
    result = subprocess.run(argv, cwd=HERE, env=environment, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=20)
    receipt = dict(argv=argv, returncode=result.returncode, stdout=result.stdout.decode(),
                   stderr=result.stderr.decode(), timeout_seconds=20)
    print(json.dumps(dict(kind='compiled_mapping_offline_child_v1', **receipt)), flush=True)
    assert result.returncode == 0, receipt
    return result.stdout.decode()


def apply(text, changes):
    for change in changes:
        assert text.count(change['before']) == change['count'], 'frozen measurement recipe anchor drift'
        text = text.replace(change['before'], change['after'])
    return text


def main():
    assert sys.argv[1:] == [] and sys.dont_write_bytecode
    manifest = inputs()
    mapping = json.loads((HERE / 'MAPPING_BINDINGS1.json').read_bytes())
    measurement = HERE.parent / 'vm_security_res01_measurement1'
    recipes = json.loads((measurement / 'recipe1.json').read_bytes())
    helper = (HERE / 'mapper-helper.exs').read_text()
    base = (HERE.parent / 'vm_security_res01/launcher.exs').read_text()
    assert base.count(helper) == 1
    launcher = apply(base.replace(helper, mapping['binding_after']), recipes['launcher'])
    daemon = apply((HERE.parent / 'vm_security/daemon.exs').read_text(), recipes['original_daemon'])
    overlay = (HERE / 'launcher.exs').read_text()
    setup = overlay.split('# COMPILED_MAPPING_SETUP_BEGIN\n', 1)[1].split('# COMPILED_MAPPING_SETUP_END\n', 1)[0]
    with tempfile.TemporaryDirectory(prefix='res01-compiled-mapping-parse-only-') as temporary:
        folder = Path(temporary)
        launcher_file, daemon_file, setup_file = [folder / name for name in ['launcher.exs', 'daemon.exs', 'setup.exs']]
        launcher_file.write_text(launcher)
        daemon_file.write_text(daemon)
        setup_file.write_text(setup)
        proof = json.loads(child([manifest['runtime']['elixir'], '--erl', '+S 2:2',
            str(HERE / 'parse-only1.exs'), str(HERE / 'launcher.exs'), str(launcher_file),
            str(daemon_file), str(HERE / 'mapper-helper.exs'), str(setup_file)], manifest))
        assert proof['parsed'] == 6
        assert proof['evaluation_invocations'] == proof['macro_expansions'] == proof['daemon_executions'] == proof['vm_executions'] == 0
        assert proof['helper_fn_ast_sha256'] == mapping['fn_ast_sha256']
        assert proof['helper_source_sha256'] == mapping['helper_source_sha256']
        assert proof['actual_transformed_daemon_sha256'] == hashlib.sha256((REPORT / 'daemon-transformed1.exs').read_bytes()).hexdigest()
    child(['/run/current-system/sw/bin/nix-instantiate', '--parse', str(HERE / 'test.nix')], manifest)
    inputs()
    print(json.dumps(dict(kind='compiled_mapping_parse_v1', passed=True,
                         manifest_sha256=MANIFEST_SHA256, elixir_parsed=6, nix_parsed=1,
                         inspected_target_executions=0, vm_executions=0)), flush=True)


if __name__ == '__main__':
    main()
