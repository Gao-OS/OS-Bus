"""External H-04 observer. Reaps orphan guardians without terminating them."""
import ctypes
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

backend, artifacts, launcher, *codepaths = sys.argv[1:]
assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0  # CHILD_SUBREAPER
signal.signal(signal.SIGCHLD, lambda *_: None)
with tempfile.TemporaryDirectory(prefix='hc') as private:
    env = dict(os.environ, TMPDIR=private, E2E_STRICT='1')
    command = ['elixir', '--erl', '+S 2:2']
    for path in codepaths:
        command.extend(['-pa', path])
    command.extend([launcher, backend, artifacts])
    runner = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    ready = None
    output = b''
    deadline = time.monotonic() + 20
    try:
        while ready is None:
            assert time.monotonic() < deadline, repr(output)
            if select.select([runner.stdout], [], [], 0.05)[0]:
                chunk = os.read(runner.stdout.fileno(), 4096)
                assert chunk, repr(output)
                output += chunk
                for line in output.splitlines():
                    if line.startswith(b'CRASH_READY '):
                        ready = json.loads(line[len(b'CRASH_READY '):])
        assert ready['runner_pid'] == runner.pid
        assert ready['actor']['pid'] != runner.pid
        assert ready['actor']['uid'] == os.getuid()
        assert ready['actor']['sent_hex'] == b'\0AUTH\r\n'.hex()
        assert bytes.fromhex(ready['actor']['received_hex']).startswith(b'REJECTED ')
        # Port guardians can be children of erl_child_setup, and exited runtime
        # helpers may already be adopted by this subreaper. This observer starts
        # only the runner, so its entire descendant tree belongs to this launch.
        tree = {}
        pending = [os.getpid()]
        while pending:
            parent = pending.pop()
            for children in Path(f'/proc/{parent}/task').glob('*/children'):
                try:
                    pids = children.read_text().split()
                except FileNotFoundError:
                    continue  # A finished thread has no remaining children.
                for pid in map(int, pids):
                    if pid not in tree:
                        proc = Path(f'/proc/{pid}')
                        tree[pid] = {
                            'parent': parent,
                            'name': (proc / 'comm').read_text().strip(),
                            'command': (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(),
                        }
                        pending.append(pid)
        ready['observer_pid'] = os.getpid()
        ready['process_tree'] = tree
        Path(artifacts, 'process-tree.json').write_text(json.dumps(ready, indent=2))
        guards = set(ready['guard_pids'])
        assert guards.issubset(tree)
        guarded = set()
        for pid in tree:
            parent = tree[pid]['parent']
            while parent in tree:
                if parent in guards:
                    guarded.add(pid)
                    break
                parent = tree[parent]['parent']
        assert {ready['daemon_pid'], ready['actor']['pid']}.issubset(guarded)
        runner.kill()  # Actual whole-BEAM SIGKILL, no terminate/after callbacks.
        assert runner.wait(timeout=5) == -signal.SIGKILL
        reaped = {}
        deadline = time.monotonic() + 5
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                assert pid in tree, ('unexpected orphan', pid)
                assert pid not in guarded, ('guardian failed to reap descendant', pid)
                reaped[pid] = os.waitstatus_to_exitcode(status)
            else:
                assert time.monotonic() < deadline, ('guardian teardown timeout', tree, reaped)
                select.select([], [], [], 0.01)
        assert guards.issubset(reaped), ('unobserved guardian exit', guards, reaped)
        for pid in tree:
            assert not Path(f'/proc/{pid}').exists(), ('surviving child', pid)
        report = json.loads(Path(artifacts, 'qualification.json').read_text())
        assert report['counts']['selected'] == report['counts']['executed'] == 1
        assert report['counts']['blocked'] == 1 and report['counts']['passed'] == 0
        assert report['metadata']['seed'] == 4321
        assert len(report['executed'][0]['backend_evidence']['config_sha256']) == 64
        assert Path(artifacts, 'backend.log').read_text()
        ready['reaped_guards'] = {pid: reaped[pid] for pid in ready['guard_pids']}
        ready['reaped_runtime_children'] = {pid: status for pid, status in reaped.items()
                                           if pid not in ready['guard_pids']}
        print(json.dumps(ready), flush=True)
    finally:
        if runner.poll() is None:
            runner.kill()
            runner.wait(timeout=5)
        runner.stdout.close()
        # Only this observer's TemporaryDirectory contains fixture directories.
        # Normal guard shutdown is checked above before this directory cleanup.
