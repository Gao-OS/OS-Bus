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


def main():
    assert sys.argv[1:] == [] and sys.dont_write_bytecode
    manifest = inputs()
    proof = json.loads(child([manifest['runtime']['elixir'], '--erl', '+S 2:2',
        str(HERE / 'equivalence1.exs'), str(HERE), str(HERE.parent / 'vm_security_res01'),
        str(REPORT.parent / 'mapping-probe1')], manifest))
    assert proof['all_equal'] and proof['case_count'] == 26 and proof['snapshot_count'] == 7
    assert proof['exact_fn_ast_equal'] and proof['one_binding_only']
    assert proof['actual_startup_block_evaluated'] and proof['vm_executions'] == proof['inspected_daemon_executions'] == 0
    assert proof['compiled_fun_info']['module'] == 'Elixir.Res01CompiledMapping1'
    assert proof['compiled_fun_info']['erl_eval_fun_data'] is False
    assert proof['provenance']['authority_deadline_reset'] is False
    assert proof['provenance']['held_deadline_changed'] is False
    inputs()
    print(json.dumps(dict(kind='compiled_mapping_controls_v1', passed=True,
                         manifest_sha256=MANIFEST_SHA256, equality_cases=26,
                         inspected_target_executions=0, vm_executions=0)), flush=True)


if __name__ == '__main__':
    main()
