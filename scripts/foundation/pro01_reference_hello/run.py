"""Explicit private reference-only runner; no build, host-bus discovery or Gao run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

from actor import validate_barrier, validate_cases, validate_completion

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    temporary.replace(path)


def clean_env():
    return dict(PATH=os.defpath, LANG='C.UTF-8', PYTHONDONTWRITEBYTECODE='1')


def check_inputs(inputs):
    for path, digest in inputs['pins'].items():
        assert sha(path) == digest, 'changed pinned input: ' + path


def process_identity(pid):
    root = Path('/proc') / str(pid)
    raw = (root / 'stat').read_text()
    return dict(pid=pid, starttime_ticks=int(raw[raw.rfind(')') + 2:].split()[19]),
                proc_stat=raw, proc_status=(root / 'status').read_text(),
                executable=os.readlink(root / 'exe'),
                cmdline=(root / 'cmdline').read_bytes().hex())


def validate_events(events):
    identities = [v for v in events if v['event'] == 'identity']
    identity, = identities
    assert identity['uid'] == identity['euid'] > 0
    assert identity['gid'] == identity['egid'] > 0
    control, = [v for v in events if v['event'] == 'kernel_control']
    assert control['passed'] is True and control['seconds'] <= 1
    assert [s['phase'] for s in control['steps']] == ['before_send', 'unread', 'partial_read', 'complete_read']
    values = [s['allocation'] for s in control['steps']]
    assert values[0] == values[3] == 0 and values[1] > 0 and values[2] > 0
    assert control['received_sha256'] == control['payload_sha256']
    ready, = [v for v in events if v['event'] == 'ready']
    hello, get_id = bytes.fromhex(ready['hello']), bytes.fromhex(ready['get_id'])
    assert len(hello) == len(get_id) == 128
    assert hashlib.sha256(hello).hexdigest() == ready['hello_sha256']
    assert hashlib.sha256(get_id).hexdigest() == ready['get_id_sha256']
    result, = [v for v in events if v['event'] == 'result']
    assert result['result'] == 'PASS' and result['cases'] == 127
    assert all(result[k] == ready[k] for k in ('observer', 'owned', 'bus_id'))
    cases = [v for v in events if v['event'] == 'case']
    validate_cases(cases)
    connections = [v for v in events if v['event'] == 'connection']
    assert len(connections) == 128
    for case in cases:
        connected, = [v for v in connections if v['role'] == 'source-' + str(case['split'])]
        assert connected['connection'] == case['connection']
        assert case['connection']['pid'] == identity['pid']
        assert case['connection']['starttime_ticks'] == identity['starttime_ticks']
        validate_barrier(case['barrier'], case['connection'], case['prefix_trace'], control['ioctl'], control['kernel'])
        validate_completion(case['receipts'], case['source'], ready['bus_id'])
        sends = [v for v in events if v['event'] == 'wire' and v['direction'] == 'send'
                 and v['role'] == connected['role']]
        assert all(v['outcome'] == 'sent' for v in sends)
        assert [v['hex'] for v in sends] == [
            (b'\0AUTH EXTERNAL ' + str(identity['uid']).encode().hex().encode() + b'\r\n').hex(),
            (b'BEGIN\r\n' + hello[:case['split']]).hex(),
            (hello[case['split']:] + get_id).hex()]
        assert case['source'] != ready['observer']
        assert case['source_pending'] is False and case['received_fds'] == 0
        assert case['internal_accounting'] == case['source_parser_buffer'] == 'UNSUPPORTED'
        assert case['ownership_disappearance_seconds'] <= 1
        assert all(case['after_close_health'][k] == ready[k] for k in ('observer', 'owned', 'bus_id'))
        assert all(case['barrier']['health'][k] == ready[k] for k in ('observer', 'owned', 'bus_id'))
    return dict(result='PASS', cases=127, observer=ready['observer'], owned=ready['owned'],
                bus_id=ready['bus_id'], hello_sha256=ready['hello_sha256'],
                get_id_sha256=ready['get_id_sha256'], internal_accounting='UNSUPPORTED',
                source_parser_buffer='UNSUPPORTED', native_frames_per_read='UNSUPPORTED',
                full_PRO01='INCOMPLETE', M1='INCOMPLETE', level='L0', product_qualified=False)


def worker(directory):
    inputs = json.loads((directory / 'inputs.json').read_text())
    check_inputs(inputs)
    socket_parent = Path(inputs['socket_parent'])
    parent_info = socket_parent.lstat()
    assert stat.S_ISDIR(parent_info.st_mode) and stat.S_IMODE(parent_info.st_mode) == 0o700
    assert parent_info.st_uid == os.getuid()
    assert dict(device=parent_info.st_dev, inode=parent_info.st_ino) == inputs['socket_parent_identity']
    endpoint = socket_parent / 'bus'
    config = directory / 'reference.conf'
    uid = os.getuid()
    # No includes, default host config, service directories or FD negotiation.
    xml = ('<busconfig><type>system</type><listen>unix:path=' + str(endpoint) + '</listen>'
           '<auth>EXTERNAL</auth><policy context="default"><deny user="*"/>'
           '<allow user="' + str(uid) + '"/><deny own="*"/>'
           '<deny send_destination="*"/><deny receive_sender="*"/></policy>'
           '<policy user="' + str(uid) + '">'
           '<allow own="org.foundation.HelloSplitObserver"/>'
           '<allow send_destination="org.freedesktop.DBus"/>'
           '<allow receive_sender="org.freedesktop.DBus"/></policy></busconfig>')
    config.write_text(xml)
    config.chmod(0o600)
    report = dict(status='running', backend='reference', endpoint=str(endpoint),
                  configuration=dict(path=str(config), sha256=sha(config), bytes=xml),
                  commands=[], failures=[], cleanup=[])
    daemon = actor = None
    socket_identity = None
    began = time.monotonic()
    logs = []
    def persist():
        save(directory / 'worker.json', report)
    persist()
    try:
        argv = [inputs['dbus_daemon'], '--nofork', '--nopidfile', '--config-file=' + str(config)]
        report['commands'].append(argv)
        log = (directory / 'daemon.log').open('xb')
        logs.append(log)
        daemon = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                  env=clean_env())
        limit = time.monotonic() + 10
        while not endpoint.exists():
            assert daemon.poll() is None, 'reference exited during startup'
            assert time.monotonic() < limit, 'reference startup10s deadline'
            time.sleep(0.01)
        info = endpoint.lstat()
        assert stat.S_ISSOCK(info.st_mode) and socket_parent.stat().st_mode & 0o777 == 0o700
        socket_identity = dict(device=info.st_dev, inode=info.st_ino)
        report['daemon'] = process_identity(daemon.pid)
        assert sha(Path('/proc') / str(daemon.pid) / 'exe') == inputs['dbus_sha256']
        assert report['daemon']['executable'] == str(Path(inputs['dbus_daemon']).resolve())
        lines = [line for line in Path('/proc/net/unix').read_text().splitlines()[1:]
                 if line.split()[-1] == str(endpoint)]
        line, = lines
        inode = int(line.split()[6])
        links = {p.name: os.readlink(p) for p in (Path('/proc') / str(daemon.pid) / 'fd').iterdir()}
        assert 'socket:[' + str(inode) + ']' in links.values()
        report['socket'] = dict(**socket_identity, kernel_inode=inode, net_unix_line=line,
                                daemon_fd_links=links)
        argv = [sys.executable, '-B', str(HERE / 'actor.py'), str(endpoint),
                inputs['fixtures_dir'], str(daemon.pid)]
        report['commands'].append(argv)
        raw = (directory / 'actor.jsonl').open('xb')
        errors = (directory / 'actor.stderr').open('xb')
        logs.extend([raw, errors])
        actor = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=raw, stderr=errors, env=clean_env())
        report['actor'] = process_identity(actor.pid)
        persist()
        code = actor.wait(timeout=45)
        report['actor_returncode'] = code
        assert code == 0, 'actor failed; preserve raw output without retry'
        assert daemon.poll() is None
        events = [json.loads(line) for line in (directory / 'actor.jsonl').read_text().splitlines()]
        report['semantic_result'] = validate_events(events)
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', failure=repr(error))
    finally:
        cleanup_started = time.monotonic()
        for role, process in (('actor', actor), ('reference', daemon)):
            if process is None:
                continue
            try:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=max(0.001, cleanup_started + 5 - time.monotonic()))
                report['cleanup'].append(dict(role=role, returncode=code,
                                              pid_absent=not Path('/proc', str(process.pid)).exists()))
            except Exception as error:
                report['failures'].append(dict(role=role, cleanup_error=repr(error)))
        if os.path.lexists(endpoint):
            info = endpoint.lstat()
            if socket_identity == dict(device=info.st_dev, inode=info.st_ino) and stat.S_ISSOCK(info.st_mode):
                endpoint.unlink()
            else:
                report['failures'].append('socket identity changed; did not unlink')
        report['socket_removed'] = not os.path.lexists(endpoint)
        try:
            info = socket_parent.lstat()
            assert stat.S_ISDIR(info.st_mode)
            assert dict(device=info.st_dev, inode=info.st_ino) == inputs['socket_parent_identity']
            socket_parent.rmdir()
            report['socket_parent_removed'] = True
        except Exception as error:
            report['socket_parent_removed'] = False
            report['failures'].append(dict(socket_parent_cleanup_error=repr(error)))
        report['cleanup_seconds'] = time.monotonic() - cleanup_started
        report['seconds'] = time.monotonic() - began
        for log in logs:
            log.close()
        try:
            check_inputs(inputs)
            assert sha(config) == report['configuration']['sha256']
            assert not report['failures'] and report['socket_removed']
            assert report['cleanup_seconds'] <= 5 and all(v['pid_absent'] for v in report['cleanup'])
        except Exception as error:
            report['failures'].append(repr(error))
        if report['failures']:
            report['status'] = 'failed'
        persist()
    return 0 if report['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--socket-parent', type=Path, required=True)
    parser.add_argument('--dbus-daemon', type=Path, required=True)
    parser.add_argument('--dbus-sha256', required=True)
    parser.add_argument('--fixtures-dir', type=Path, required=True)
    parser.add_argument('--host-lifecycle', type=Path, required=True)
    args = parser.parse_args()
    assert not sys.flags.optimize and sys.platform == 'linux'
    assert os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    assert all(p.is_absolute() for p in (args.output, args.socket_parent, args.dbus_daemon,
                                        args.fixtures_dir, args.host_lifecycle))
    assert len(os.fsencode(str(args.socket_parent / 'bus'))) < 108, 'AF_UNIX pathname exceeds107 bytes'
    assert len(args.dbus_sha256) == 64 and sha(args.dbus_daemon) == args.dbus_sha256
    assert not os.path.lexists(args.output)
    args.output.mkdir(mode=0o700)
    args.output.chmod(0o700)
    # Bind unchanged imports, this extension, the interpreter and existing lifecycle.
    paths = [args.dbus_daemon, args.host_lifecycle, Path(sys.executable).resolve(),
             args.fixtures_dir / 'peer_hello_split_boundaries_actor.py',
             args.fixtures_dir / 'transport_actor.py', *[HERE / name for name in ('actor.py', 'run.py', 'test_fixture.py')]]
    inputs = dict(dbus_daemon=str(args.dbus_daemon), dbus_sha256=args.dbus_sha256,
                  fixtures_dir=str(args.fixtures_dir), host_lifecycle=str(args.host_lifecycle),
                  pins={str(p): sha(p) for p in paths}, clean_environment=clean_env(),
                  python_version=sys.version, kernel=os.uname().release,
                  uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid())
    assert not os.path.lexists(args.socket_parent)
    args.socket_parent.mkdir(mode=0o700)
    args.socket_parent.chmod(0o700)
    info = args.socket_parent.lstat()
    inputs.update(socket_parent=str(args.socket_parent),
                  socket_parent_identity=dict(device=info.st_dev, inode=info.st_ino))
    save(args.output / 'inputs.json', inputs)
    spec = importlib.util.spec_from_file_location('pro01_existing_host_lifecycle', args.host_lifecycle)
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    before, errors = lifecycle.snapshot()
    assert not errors, errors
    baseline_groups = {row['pgid'] for row in before.values()}
    started = time.monotonic()
    with (args.output / 'worker.stdout').open('xb') as stdout, (args.output / 'worker.stderr').open('xb') as stderr:
        child = subprocess.Popen([sys.executable, '-B', str(HERE / 'run.py'), '--worker', str(args.output)],
                                 stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 env=clean_env(), start_new_session=True)
        outcome = lifecycle.complete(child, started, baseline_groups, lambda: check_inputs(inputs),
                                     lambda value: save(args.output / 'lifecycle.json', value))
    passed = outcome['returncode'] == 0 and outcome['graceful_success'] is True
    report = dict(status='PASS' if passed else 'FAIL', child_returncode=outcome['returncode'],
                  lifecycle_graceful_success=outcome['graceful_success'], full_PRO01='INCOMPLETE',
                  M1='INCOMPLETE', level='L0', product_qualified=False)
    save(args.output / 'result.json', report)
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        raise SystemExit(worker(Path(sys.argv[2])))
    raise SystemExit(main())
