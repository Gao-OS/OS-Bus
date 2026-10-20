"""One explicitly selected private PRO02 unknown-header reference observation.

Use absolute --output NEW_DIR --socket-parent NEW_DIR --dbus-daemon PINNED_FILE
--actor FILE --host-lifecycle FILE --input-pins JSON. Pins must exactly cover
required_pins(); the supplied pins file is then pinned in saved inputs.json.
This observation cannot qualify the complete PRO02 row or foundation.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


SHARED_RUNNER = Path(__file__).resolve().parents[1] / "pro01_whole_stream/run_reference.py"
_spec = importlib.util.spec_from_file_location("pro02_shared_reference", SHARED_RUNNER)
_shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_shared)
sha = _shared.sha
save = _shared.save
clean_env = _shared.clean_env
check_inputs = _shared.check_inputs
load_module = _shared.load_module
process_identity = _shared.process_identity
reference_config = _shared.reference_config
validate_transcript = _shared.validate_transcript
ActorOutput = _shared.ActorOutput


def required_pins(args):
    return [Path(__file__).resolve(), SHARED_RUNNER, Path(sys.executable).resolve(), args.dbus_daemon,
            args.host_lifecycle, args.actor, args.actor.parent / "peer_hello_split_boundaries_actor.py",
            args.actor.parent / "transport_actor.py"]



def case_outcome(executed, success):
    assert type(executed) is int and executed in (0, 1) and type(success) is bool
    passed = executed == 1 and success
    return dict(status="PASS" if passed else "FAIL" if executed else "BLOCKED",
                selected=1, executed=executed, passed=int(passed),
                failed=int(executed == 1 and not passed), blocked=int(executed == 0))


def worker(directory):
    inputs = json.loads((directory / 'inputs.json').read_text())
    check_inputs(inputs)
    parent = Path(inputs['socket_parent'])
    endpoint = parent / 'bus'
    info = parent.lstat()
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
    assert dict(device=info.st_dev, inode=info.st_ino) == inputs['socket_parent_identity']
    config = directory / 'reference.conf'
    config.write_text(reference_config(endpoint, os.getuid()))
    config.chmod(0o600)
    report = dict(status='running', backend='reference', selected=1, executed=0, passed=0, failed=0, blocked=0,
                  endpoint=str(endpoint),
                  configuration=dict(path=str(config), sha256=sha(config)), commands=[], cleanup=[], failures=[])
    daemon = actor = reader = None
    socket_identity = None
    logs, events = [], []
    began = time.monotonic()
    try:
        sys.path.insert(0, str(Path(inputs['actor']).parent))
        shared = load_module('unknown_header_actor', inputs['actor'])
        stdout, stderr = [(directory / ('daemon.' + name)).open('xb') for name in ('stdout', 'stderr')]
        logs.extend([stdout, stderr])
        argv = [inputs['dbus_daemon'], '--nofork', '--nopidfile', '--config-file=' + str(config)]
        report['commands'].append(argv)
        daemon = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=clean_env())
        deadline = time.monotonic() + 10
        while not endpoint.exists():
            assert daemon.poll() is None and time.monotonic() < deadline, 'reference startup10s deadline'
            time.sleep(0.01)
        info = endpoint.lstat()
        assert stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
        socket_identity = dict(device=info.st_dev, inode=info.st_ino)
        endpoint.chmod(0o600)
        assert stat.S_IMODE(endpoint.stat().st_mode) == 0o600
        report['daemon'] = process_identity(daemon.pid)
        assert sha(Path('/proc', str(daemon.pid), 'exe')) == inputs['pins'][inputs['dbus_daemon']]
        line, = [line for line in Path('/proc/net/unix').read_text().splitlines()[1:]
                 if line.split()[-1] == str(endpoint)]
        inode = int(line.split()[6])
        links = {p.name: os.readlink(p) for p in Path('/proc', str(daemon.pid), 'fd').iterdir()}
        assert 'socket:[' + str(inode) + ']' in links.values()
        report['socket'] = dict(**socket_identity, mode=0o600, uid=info.st_uid,
                                kernel_inode=inode, net_unix_line=line, daemon_fd_links=links)
        raw, errors = [(directory / ('actor.' + name)).open('xb') for name in ('jsonl', 'stderr')]
        logs.extend([raw, errors])
        argv = [sys.executable, '-S', '-B', inputs['actor'], str(endpoint)]
        report['commands'].append(argv)
        actor_deadline = time.monotonic() + 45
        actor = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
                                 env=clean_env(), bufsize=0)
        report['executed'] = 1
        report['actor'] = process_identity(actor.pid)
        assert sha(Path('/proc', str(actor.pid), 'exe')) == inputs['pins'][str(Path(sys.executable).resolve())]
        reader = ActorOutput(actor, raw, actor_deadline)
        save(directory / 'worker.json', report)
        for expected, command in [('ready', 'open'), ('opened', 'send'), ('completed', 'close'),
                                  ('closed', 'stop'), ('result', None)]:
            events.append(reader.event(expected))
            save(directory / 'events.json', events)
            if command is not None:
                report.setdefault('actor_commands', []).append(dict(command=command, monotonic=time.monotonic()))
                actor.stdin.write((command + '\n').encode())
                actor.stdin.flush()
        actor.stdin.close()
        report['actor_returncode'] = actor.wait(timeout=max(0.001, min(3, actor_deadline - time.monotonic())))
        reader.drain()
        assert report['actor_returncode'] == 0 and not reader.buffer
        assert not (directory / 'actor.stderr').read_bytes() and daemon.poll() is None
        validate_transcript(events, shared.validate_run, report['actor'], daemon.pid, os.getuid(), os.getgid())
        report.update(status='passed', passed=1,
                      reference_internal_accounting='UNSUPPORTED', reference_native_receive_extents='UNSUPPORTED')
    except Exception as error:
        report.update(status='failed', failure=repr(error))
    finally:
        cleanup_started = time.monotonic()
        for role, process in [('actor', actor), ('reference', daemon)]:
            if process is None:
                continue
            try:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=max(0.001, cleanup_started + 5 - time.monotonic()))
                report['cleanup'].append(dict(role=role, returncode=code,
                                              pid_absent=not Path('/proc', str(process.pid)).exists()))
            except Exception as error:
                report['failures'].append(dict(role=role, error=repr(error)))
        if reader is not None:
            reader.drain()
            reader.selector.close()
            actor.stdout.close()
            if not actor.stdin.closed:
                actor.stdin.close()
        if os.path.lexists(endpoint):
            info = endpoint.lstat()
            if stat.S_ISSOCK(info.st_mode) and socket_identity == dict(device=info.st_dev, inode=info.st_ino):
                endpoint.unlink()
            else:
                report['failures'].append('socket identity changed; did not unlink')
        try:
            info = parent.lstat()
            assert dict(device=info.st_dev, inode=info.st_ino) == inputs['socket_parent_identity']
            parent.rmdir()
        except Exception as error:
            report['failures'].append(dict(socket_parent_cleanup_error=repr(error)))
        report.update(socket_removed=not os.path.lexists(endpoint), socket_parent_removed=not os.path.lexists(parent),
                      cleanup_seconds=time.monotonic() - cleanup_started, seconds=time.monotonic() - began)
        for log in logs:
            log.close()
        try:
            check_inputs(inputs)
            assert sha(config) == report['configuration']['sha256']
            assert report['socket_removed'] and report['socket_parent_removed'] and report['cleanup_seconds'] <= 5
            assert all(row['pid_absent'] for row in report['cleanup'])
        except Exception as error:
            report['failures'].append(repr(error))
        if report['failures']:
            report['status'] = 'failed'
        report.update(case_outcome(report['executed'], report['status'] == 'passed'))
        save(directory / 'worker.json', report)
    return 0 if report['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'socket-parent', 'dbus-daemon', 'actor', 'host-lifecycle', 'input-pins'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert not sys.flags.optimize and sys.platform == 'linux'
    assert os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    assert all(path.is_absolute() for path in vars(args).values())
    assert len(os.fsencode(args.socket_parent / 'bus')) < 108
    assert not os.path.lexists(args.output) and not os.path.lexists(args.socket_parent)
    assert not args.output.is_relative_to(args.socket_parent) and not args.socket_parent.is_relative_to(args.output)
    inputs = json.loads(args.input_pins.read_text())
    required = required_pins(args)
    assert set(inputs['pins']) == {str(path) for path in required}, 'runtime pins must match exact source set'
    check_inputs(inputs)
    inputs['pins'][str(args.input_pins)] = sha(args.input_pins)
    lifecycle = load_module('unknown_header_existing_lifecycle', args.host_lifecycle)
    before, errors = lifecycle.snapshot()
    assert not errors, errors
    groups = {row['pgid'] for row in before.values()}
    args.output.mkdir(mode=0o700)
    args.socket_parent.mkdir(mode=0o700)
    info = args.socket_parent.lstat()
    inputs.update(socket_parent=str(args.socket_parent),
                  socket_parent_identity=dict(device=info.st_dev, inode=info.st_ino),
                  dbus_daemon=str(args.dbus_daemon), actor=str(args.actor),
                  runner=process_identity(os.getpid()), environment=clean_env(),
                  python_version=sys.version, kernel=os.uname().release)
    save(args.output / 'inputs.json', inputs)
    started = time.monotonic()
    with (args.output / 'worker.stdout').open('xb') as stdout, (args.output / 'worker.stderr').open('xb') as stderr:
        child = subprocess.Popen([sys.executable, '-S', '-B', str(Path(__file__).resolve()), '--worker', str(args.output)],
                                 stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                 env=clean_env(), start_new_session=True)
        outcome = lifecycle.complete(child, started, groups, lambda: check_inputs(inputs),
                                     lambda value: save(args.output / 'lifecycle.json', value))
    worker_report = json.loads((args.output / 'worker.json').read_text()) if (args.output / 'worker.json').exists() else {}
    passed = (outcome['returncode'] == 0 and outcome['graceful_success'] is True
              and worker_report.get('status') == 'PASS')
    report = case_outcome(worker_report.get('executed', 0), passed)
    report.update(child_returncode=outcome['returncode'],
                  lifecycle_graceful_success=outcome['graceful_success'], full_row_qualified=False,
                  current_paired_qualified=False, required_row_promotions=0, readiness='L0', product_qualified=False)
    save(args.output / 'result.json', report)
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        raise SystemExit(worker(Path(sys.argv[2])))
    raise SystemExit(main())
