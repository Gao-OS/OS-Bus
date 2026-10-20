"""Guest-only H04 observer; owns one runner and observes its private descendants."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import stat
import subprocess
import sys
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def endpoint_record(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return dict(path=str(path), exists=False)
    return dict(path=str(path), exists=True, socket=stat.S_ISSOCK(info.st_mode),
                device=info.st_dev, inode=info.st_ino, mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid, gid=info.st_gid)


def incarnation(pid):
    root = Path('/proc', str(pid))
    before = (root / 'stat').read_text()
    status = (root / 'status').read_text()
    after = (root / 'stat').read_text()
    ticks = lambda text: int(text[text.rfind(')') + 2:].split()[19])
    assert ticks(before) == ticks(after), ('PID incarnation changed', pid)
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    return dict(pid=pid, starttime_ticks=ticks(before), proc_stat=before,
                proc_stat_after=after, proc_status=status,
                uids=list(map(int, fields['Uid'].split())),
                gids=list(map(int, fields['Gid'].split())))


def gone(identity):
    try:
        return incarnation(identity['pid'])['starttime_ticks'] != identity['starttime_ticks']
    except FileNotFoundError:
        return True


def actor_identity(actor):
    observed = incarnation(actor['pid'])
    assert observed['uids'] == observed['gids'] == [1101] * 4
    assert actor['uid'] == actor['gid'] == 1101
    link = os.readlink(Path('/proc', str(actor['pid']), 'fd', str(actor['fd'])))
    assert link == 'socket:[' + str(actor['inode']) + ']'
    assert not gone(observed)
    observed['socket_link'] = link
    observed['actor'] = actor
    return observed


def tree():
    found = {}
    pending = [os.getpid()]
    while pending:
        parent = pending.pop()
        for children in Path('/proc', str(parent), 'task').glob('*/children'):
            try:
                pids = list(map(int, children.read_text().split()))
            except FileNotFoundError:
                continue
            for pid in pids:
                if pid not in found:
                    try:
                        found[pid] = dict(parent=parent, identity=incarnation(pid))
                        pending.append(pid)
                    except FileNotFoundError:
                        continue  # Only transient runtime helpers may disappear here.
    return found


def validate(bindings):
    assert sys.flags.optimize == 0 and os.getuid() == os.geteuid() == 0
    marker = Path('/etc/osbus-security-guest')
    info = marker.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
    assert stat.S_IMODE(info.st_mode) == 0o444
    assert marker.read_text() == 'isolated-vm\n'
    for user, uid in [('foundationA', 1100), ('foundationB', 1101)]:
        account = pwd.getpwnam(user)
        assert account.pw_uid == account.pw_gid == uid
    assert bindings['schema'] == 1 and bindings['profile'] == 'core'
    assert bindings['installed_policy_qualified'] is False
    inputs = bindings['inputs']
    fixture = Path(__file__).resolve().parent
    required = [fixture / name for name in [
        'h04_system_observer.py', 'h04_system_actor.py',
        'h04_system_lifecycle.exs', 'h04_system_daemon.exs']]
    required += [Path(bindings['original']) / name for name in ['actor.py', 'daemon.exs', 'state.ex']]
    required += [Path(bindings['donor']) / name for name in ['reference.conf', 'policy.exs']]
    required += [Path(bindings[name]) for name in [
        'elixir', 'python', 'runuser', 'reference', 'guard', 'runtime_manifest']]
    for directory in bindings['support_ebins']:
        beams = sorted(Path(directory).glob('*.beam'))
        assert beams, ('empty support ebin', directory)
        required += beams
    assert all(str(path) in inputs for path in required)
    for name, digest in inputs.items():
        path = Path(name)
        assert path.is_absolute() and str(path).startswith('/nix/store/')
        assert stat.S_ISREG(path.stat().st_mode) and path.stat().st_mode & 0o222 == 0
        assert sha(path) == digest, ('input hash', name)
    assert sha(Path(bindings['donor']) / 'reference.conf') == 'c007cd98072be63dfb7c94d99ac2cff40b50e3e34a721d4c4eeb4161a1150e52'
    assert sha(Path(bindings['donor']) / 'policy.exs') == '85968edd3f6925a7b857e5c7d114d8cb47af5910a692c71e2eac4ffb5b99428a'
    for name, digest in {
        'actor.py': '1300769a2946b8b518deabd4899ce78fe7a8a7e048d0e9a33ef19f0e242d9772',
        'daemon.exs': 'cba75169efa99be884ae758d64a690cc3a6e5fd28576adc5faf06260cdcd88fb',
        'state.ex': 'e3af1bf540aeaf881b60ec0ee7019f68866d6d167d80275ce644a21ff5f1f4d0',
    }.items():
        assert sha(Path(bindings['original']) / name) == digest
    assert sha(bindings['runtime_manifest']) == '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
    candidate = Path(bindings['candidate'])
    assert str(candidate).startswith('/nix/store/')
    assert sha(candidate / 'candidate.json') == 'fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82'
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert manifest['source_sha256'] == 'f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c'
    assert len(manifest['files']) == 80 and len(manifest['sources']) == 71
    for name, digest in manifest['files'].items():
        path = candidate / name
        assert Path(name).is_relative_to('lib') and '..' not in Path(name).parts
        assert not path.is_symlink() and path.stat().st_mode & 0o222 == 0
        assert sha(path) == digest
    assert sha(bindings['guard']) == inputs[bindings['guard']]
    assert os.access(bindings['guard'], os.X_OK)


def main(backend, bindings_path):
    assert backend in ('reference', 'gao_bus')
    bindings = json.loads(Path(bindings_path).read_text())
    validate(bindings)
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
    base = Path('/run/osbus-security/h04-current-lifecycle1')
    base.mkdir(mode=0o755, exist_ok=True)
    assert stat.S_ISDIR(base.lstat().st_mode) and base.stat().st_uid == 0
    artifacts = base / backend
    artifacts.mkdir(mode=0o755)
    directory = Path('/run/osbus-security/sec01-complete') / backend
    assert not os.path.lexists(directory)
    directory.parent.mkdir(mode=0o755, exist_ok=True)
    assert stat.S_ISDIR(directory.parent.lstat().st_mode) and directory.parent.stat().st_uid == 0
    command = [bindings['elixir'], '--erl', '+S 2:2']
    for path in bindings['support_ebins']:
        command += ['-pa', path]
    command += [str(Path(__file__).with_name('h04_system_lifecycle.exs')),
                backend, str(artifacts), str(bindings_path)]
    record = dict(backend=backend, profile='core', status='running', command=command,
                  bindings=bindings, bindings_sha256=sha(bindings_path), seed=4321,
                  installed_policy_qualified=False, events=[],
                  wrapper_cleanup=dict(actor='external_h04_observer', performed=False,
                                       action='remove_private_fixture_directory',
                                       daemon_graceful_unlink_claim=False))
    runner = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
    output = bytearray()
    pending = bytearray()
    deadline = time.monotonic() + 20

    def persist():
        (artifacts / 'observer.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        (artifacts / 'runner.log').write_bytes(output)

    def event(prefix):
        marker = prefix.encode() + b' '
        while True:
            while b'\n' in pending:
                line, _, rest = pending.partition(b'\n')
                pending[:] = rest
                if line.startswith(marker):
                    value = json.loads(line[len(marker):])
                    record['events'].append(dict(event=prefix, value=value))
                    persist()
                    return value
            assert time.monotonic() < deadline, ('runner event deadline', prefix, bytes(output))
            if select.select([runner.stdout], [], [], min(0.05, max(0, deadline - time.monotonic())))[0]:
                chunk = os.read(runner.stdout.fileno(), 4096)
                assert chunk, ('runner exited before event', prefix, runner.poll(), bytes(output))
                output.extend(chunk)
                pending.extend(chunk)

    try:
        runner_identity = incarnation(runner.pid)
        first = event('H04_TIMEOUT_READY')
        record['timeout_actor'] = actor_identity(first['actor'])
        record['timeout_guard'] = incarnation(first['guard_pid'])
        assert sha(Path('/proc', str(first['guard_pid']), 'exe')) == inputs_guard_sha(bindings)
        persist()
        runner.stdin.write(b'timeout\n')
        runner.stdin.flush()
        timed_out = event('H04_TIMEOUT_REAPED')
        assert timed_out['timed_out?'] is True and timed_out['exit_status'] is not None
        assert gone(record['timeout_actor']) and gone(record['timeout_guard'])
        record['timeout_fixture_reaped'] = True
        ready = event('H04_CRASH_READY')
        assert ready['runner_pid'] == runner.pid
        assert ready['directory'] == str(directory) and ready['socket_path'] == str(directory / 'bus')
        record['actor'] = actor_identity(ready['actor'])
        record['daemon'] = incarnation(ready['daemon_pid'])
        assert record['daemon']['uids'] == record['daemon']['gids'] == [0] * 4
        observed = tree()
        guards = set(ready['guard_pids'])
        assert guards.issubset(observed)
        for pid in guards:
            assert sha(Path('/proc', str(pid), 'exe')) == inputs_guard_sha(bindings)
        guarded = set()
        for pid in observed:
            parent = observed[pid]['parent']
            while parent in observed:
                if parent in guards:
                    guarded.add(pid)
                    break
                parent = observed[parent]['parent']
        assert {ready['daemon_pid'], ready['actor']['pid']}.issubset(guarded)
        assert not gone(runner_identity)
        record['process_tree'] = observed
        record['runner_identity'] = runner_identity
        persist()
        runner.kill()  # This unreaped Popen child cannot have its PID reused.
        assert runner.wait(timeout=5) == -signal.SIGKILL
        record['runner_exit'] = runner.returncode
        reaped = {}
        reap_deadline = time.monotonic() + 5
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid:
                assert pid in observed and pid not in guarded, ('guardian failed to reap', pid)
                reaped[pid] = os.waitstatus_to_exitcode(status)
            else:
                assert time.monotonic() < reap_deadline, ('guardian teardown deadline', reaped)
                select.select([], [], [], 0.01)
        assert guards.issubset(reaped)
        assert all(gone(value['identity']) for value in observed.values())
        report = json.loads((artifacts / 'qualification.json').read_text())
        assert report['counts']['selected'] == report['counts']['executed'] == 1
        assert report['counts']['blocked'] == 1 and report['counts']['passed'] == 0
        assert report['metadata']['seed'] == 4321
        selected, = report['selected']
        executed, = report['executed']
        assert selected['e2e_id'] == executed['e2e_id'] == 'H-04-system-lifecycle'
        assert selected['profile'] == executed['profile'] == 'core'
        assert executed['backend_evidence']['config_sha256'] == sha(directory / (
            'reference.conf' if backend == 'reference' else 'policy.exs'))
        for name in ['context.json', 'backend.log', 'fixture-timeout.json', 'fixture-actor.json']:
            assert (artifacts / name).stat().st_size > 0
        record['pre_wrapper_cleanup_endpoint'] = endpoint_record(directory / 'bus')
        persist()
        shutil.rmtree(directory)
        record['wrapper_cleanup']['performed'] = True
        record.update(status='passed', reaped=reaped, inner_qualification='blocked',
                      all_observed_incarnations_reaped=True,
                      private_directory_removed=not os.path.lexists(directory))
        persist()
    except BaseException as error:
        record.update(status='failed', failure=repr(error),
                      failure_endpoint=endpoint_record(directory / 'bus'))
        persist()
        raise
    finally:
        try:
            if runner.poll() is None:
                runner.kill()
                runner.wait(timeout=5)
            cleanup_reaped = {}
            cleanup_deadline = time.monotonic() + 5
            while True:
                try:
                    pid, status = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid:
                    cleanup_reaped[pid] = os.waitstatus_to_exitcode(status)
                else:
                    assert time.monotonic() < cleanup_deadline, 'failure cleanup guardian deadline'
                    select.select([], [], [], 0.01)
            record['observer_cleanup'] = dict(owned_children_reaped=True, reaped=cleanup_reaped)
        except BaseException as error:
            record.update(status='failed', cleanup_failure=repr(error))
            raise
        finally:
            runner.stdin.close()
            runner.stdout.close()
            record['export_endpoint'] = endpoint_record(directory / 'bus')
            persist()
    # Command/ChildProcess retain at most1MiB. Keep the full tree/bindings on
    # disk and emit a small hash-bound receipt instead of risking truncation.
    summary = {name: record[name] for name in [
        'backend', 'profile', 'status', 'timeout_fixture_reaped', 'runner_exit',
        'all_observed_incarnations_reaped', 'private_directory_removed',
        'inner_qualification', 'installed_policy_qualified']}
    evidence_file = artifacts / 'observer.json'
    summary.update(observer_json=str(evidence_file), observer_sha256=sha(evidence_file),
                   observer_bytes=evidence_file.stat().st_size,
                   daemon_graceful_unlink_claim=False)
    receipt = json.dumps(summary, sort_keys=True)
    assert len(receipt.encode()) < 4096
    print(receipt, flush=True)


def inputs_guard_sha(bindings):
    return bindings['inputs'][bindings['guard']]


if __name__ == '__main__':
    assert len(sys.argv) == 3
    main(sys.argv[1], Path(sys.argv[2]).resolve())
