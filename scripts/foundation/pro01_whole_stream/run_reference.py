"""One private reference C observation; execution requires root selection."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time
from xml.sax.saxutils import escape


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
        assert Path(path).is_absolute() and sha(path) == digest, 'changed pinned input: ' + path


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def process_identity(pid):
    root = Path('/proc') / str(pid)
    raw = (root / 'stat').read_text()
    return dict(pid=pid, starttime_ticks=int(raw[raw.rfind(')') + 2:].split()[19]),
                proc_stat=raw, proc_status=(root / 'status').read_text(),
                executable=os.readlink(root / 'exe'), cmdline=(root / 'cmdline').read_bytes().hex())


def reference_config(endpoint, uid):
    return ('<busconfig><type>system</type><listen>unix:path=' + escape(str(endpoint)) + '</listen>'
            '<auth>EXTERNAL</auth><policy context="default"><deny user="*"/>'
            '<allow user="' + str(uid) + '"/><deny own="*"/>'
            '<deny send_destination="*"/><deny receive_sender="*"/></policy>'
            '<policy user="' + str(uid) + '"><allow send_destination="org.freedesktop.DBus"/>'
            '<allow receive_sender="org.freedesktop.DBus"/></policy></busconfig>')


def validate_transcript(events, oracle, process, daemon_pid, uid, gid):
    assert [row['event'] for row in events] == ['ready', 'opened', 'completed', 'closed', 'result']
    ready, opened, completed, closed, result = events
    oracle(events)
    for row in (ready, completed):
        identity = row['identity']
        assert all(identity[key] == process[key] for key in ('pid', 'starttime_ticks'))
        assert identity['uid'] == identity['euid'] == uid
        assert identity['gid'] == identity['egid'] == gid
    for row in (opened, completed):
        assert all(row['connection'][key] == process[key] for key in ('pid', 'starttime_ticks'))
        assert row['peer_credentials'] == [daemon_pid, uid, gid]
    assert opened['connection'] == completed['connection']
    assert completed['source'] != ready['observer']
    assert closed['source'] == completed['source']
    for row in (completed, closed, result):
        assert all(row[key] == ready[key] for key in ('observer', 'bus_id'))
    assert result['result'] == 'PASS' and type(result['cases']) is int and result['cases'] == 1


class ActorOutput:
    def __init__(self, process, raw, deadline):
        self.process, self.raw, self.deadline = process, raw, deadline
        self.buffer = b''
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ)

    def event(self, expected):
        deadline = min(self.deadline, time.monotonic() + 3)
        while b'\n' not in self.buffer:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and self.selector.select(remaining), 'actor I/O3s deadline: ' + expected
            chunk = os.read(self.process.stdout.fileno(), 65536)
            assert chunk, 'actor exited before ' + expected
            self.raw.write(chunk)
            self.raw.flush()
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b'\n', 1)
        row = json.loads(line)
        assert row['event'] == expected, 'unexpected actor event before ' + expected
        return row

    def drain(self):
        os.set_blocking(self.process.stdout.fileno(), False)
        while True:
            try:
                chunk = os.read(self.process.stdout.fileno(), 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            self.raw.write(chunk)
            self.buffer += chunk
        self.raw.flush()


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
    report = dict(status='running', backend='reference', endpoint=str(endpoint),
                  configuration=dict(path=str(config), sha256=sha(config)), commands=[], cleanup=[], failures=[])
    daemon = actor = reader = None
    socket_identity = None
    logs, events = [], []
    began = time.monotonic()
    try:
        sys.path.insert(0, str(Path(inputs['actor']).parent))
        shared = load_module('whole_stream_actor', inputs['actor'])
        assert len(shared.build_stream(os.getuid())) == 288
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
        report['actor'] = process_identity(actor.pid)
        reader = ActorOutput(actor, raw, actor_deadline)
        save(directory / 'worker.json', report)
        for expected, command in [('ready', None), ('opened', 'send'), ('completed', 'close'),
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
        assert events[2]['stream'] == shared.build_stream(os.getuid()).hex()
        report.update(status='passed', selected=1, executed=1, passed=1,
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
        save(directory / 'worker.json', report)
    return 0 if report['status'] == 'passed' else 1


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
    required = [Path(__file__).resolve(), Path(sys.executable).resolve(), args.dbus_daemon,
                args.host_lifecycle, args.actor, args.actor.parent / 'peer_hello_split_boundaries_actor.py',
                args.actor.parent / 'transport_actor.py']
    assert all(str(path) in inputs['pins'] for path in required), 'missing required runtime pin'
    check_inputs(inputs)
    inputs['pins'][str(args.input_pins)] = sha(args.input_pins)
    lifecycle = load_module('whole_stream_existing_lifecycle', args.host_lifecycle)
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
    passed = outcome['returncode'] == 0 and outcome['graceful_success'] is True
    report = dict(status='PASS' if passed else 'FAIL', selected=1, child_returncode=outcome['returncode'],
                  lifecycle_graceful_success=outcome['graceful_success'], full_row_qualified=False,
                  current_paired_qualified=False, required_row_promotions=0, readiness='L0', product_qualified=False)
    save(args.output / 'result.json', report)
    print(json.dumps(report, sort_keys=True))
    return 0 if passed else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        raise SystemExit(worker(Path(sys.argv[2])))
    raise SystemExit(main())
