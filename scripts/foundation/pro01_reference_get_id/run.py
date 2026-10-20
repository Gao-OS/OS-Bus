"""Explicit private reference-only runner; no build, host-bus discovery or Gao run."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import time

from actor import (BEGIN, GET_ID_SHA256, OBSERVER, auth_command, binary_frames, role, validate_barrier, validate_cases,
                   validate_completion, validate_ok)
from apps.gao_bus.test.fixtures.transport_actor import frame

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


def fields(row):
    return {int(key): value for key, value in row['fields'].items()}


def string(value):
    raw = value.encode()
    return (struct.pack('<I', len(raw)) + raw + b'\0').hex()


def validate_reply(row, serial, destination, body, signature):
    header = fields(row)
    assert row['type'] == 2 and header.get(5) == serial
    assert header.get(6) == destination and header.get(7) == 'org.freedesktop.DBus'
    assert header.get(8) == signature and header.get(9, 0) == 0
    assert row['body'] == body


def validate_health(health, ready):
    assert all(health[key] == ready[key] for key in ('observer', 'owned', 'bus_id'))
    assert health['started'] <= health['finished']
    first, second = health['receipts']
    serial = fields(first)[5]
    validate_reply(first, serial, ready['observer'], string(ready['observer']), 's')
    validate_reply(second, serial + 1, ready['observer'], ready['bus_id'], 's')


def validate_wire_receipt(row):
    """Bind existing parsed receipts to raw flags/order with the unchanged encoder."""
    raw = bytes.fromhex(row['wire_hex'])
    assert binary_frames(raw) == [raw]
    header_size = struct.unpack_from('<I', raw, 12)[0]
    header = raw[16:16 + header_size]
    values, ordered, offset = fields(row), [], 0
    signatures = {1: 'o', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 's', 8: 'g', 9: 'u'}
    while offset < header_size:
        offset += -offset % 8
        assert offset + 4 <= header_size
        code = header[offset]
        assert code in signatures, 'header outside ordinary reference corpus'
        signature = signatures[code]
        assert header[offset:offset + 4] == bytes([code, 1]) + signature.encode() + b'\0'
        assert code in values and code not in [item[0] for item in ordered]
        value = values[code]
        ordered.append((code, signature, value))
        offset += 4
        if signature in ('s', 'o'):
            offset += 5 + len(value.encode())
        elif signature == 'g':
            offset += 2 + len(value.encode())
        else:
            offset += 4
    assert offset == header_size and len(ordered) == len(values)
    assert raw == frame(row['type'], row['serial'], ordered, bytes.fromhex(row['body']), flags=raw[2])
    return raw


def validate_wire_stream(events, name, ok, receipts, auth_completed_before):
    received = [row for row in events if row['event'] == 'wire' and row['role'] == name
                and row['direction'] == 'receive']
    assert received, 'missing successful receive evidence for ' + name
    for row in received:
        assert row.get('error') is None and row['hex'] and row['requested'] > 0
        assert row['flags'] == 0 and row['controls'] == []
        assert row['monotonic'] <= row['completed']
    auth_rows = [row for row in received if row['monotonic'] < auth_completed_before]
    assert auth_rows and all(row['completed'] <= auth_completed_before for row in auth_rows)
    assert b''.join(bytes.fromhex(row['hex']) for row in auth_rows) == ok
    raw = b''.join(bytes.fromhex(row['hex']) for row in received)
    assert raw == ok + b''.join(validate_wire_receipt(row) for row in receipts)


def validate_events(events):
    identities = [v for v in events if v['event'] == 'identity']
    identity, = identities
    assert identity['uid'] == identity['euid'] > 0
    assert identity['gid'] == identity['egid'] > 0
    assert identity['pid'] > 0 and identity['starttime_ticks'] > 0
    auth = auth_command(identity['uid'])
    control, = [v for v in events if v['event'] == 'kernel_control']
    assert control['passed'] is True and control['seconds'] <= 1
    assert [s['phase'] for s in control['steps']] == ['before_send', 'unread', 'partial_read', 'complete_read']
    values = [s['allocation'] for s in control['steps']]
    assert values[0] == values[3] == 0 and values[1] > 0 and values[2] > 0
    assert control['received_sha256'] == control['payload_sha256']
    ready, = [v for v in events if v['event'] == 'ready']
    assert ready['owned'] == OBSERVER and ready['observer'].startswith(':')
    assert ready['auth'] == auth.hex() and ready['begin'] == BEGIN.hex()
    validate_ok(bytes.fromhex(ready['ok']))
    hello, get_id = bytes.fromhex(ready['hello']), bytes.fromhex(ready['get_id'])
    assert len(hello) == len(get_id) == 128
    assert hashlib.sha256(hello).hexdigest() == ready['hello_sha256']
    assert hashlib.sha256(get_id).hexdigest() == ready['get_id_sha256']
    assert ready['get_id_sha256'] == GET_ID_SHA256
    successor = get_id[:8] + struct.pack('<I', 3) + get_id[12:]
    assert ready['get_id_successor'] == successor.hex()
    result, = [v for v in events if v['event'] == 'result']
    assert result['result'] == 'PASS' and result['cases'] == 127 and result['connections'] == 128
    assert all(result[k] == ready[k] for k in ('observer', 'owned', 'bus_id'))
    assert all(result[key] == 'UNSUPPORTED' for key in (
        'internal_accounting', 'source_parser_buffer', 'native_frames_per_read'))
    validate_completion(ready['registration'], ready['observer'], ready['bus_id'])
    ownership = ready['ownership']
    owned_reply, = [row for row in ownership if row['type'] == 2]
    owned_signal, = [row for row in ownership if row['type'] == 4]
    assert len(ownership) == 2
    validate_reply(owned_reply, 3, ready['observer'], struct.pack('<I', 1).hex(), 'u')
    validate_acquired(owned_signal, ready['owned'], ready['observer'])
    validate_health(result['final_health'], ready)
    cases = [v for v in events if v['event'] == 'case']
    validate_cases(cases)
    connections = [v for v in events if v['event'] == 'connection']
    assert len(connections) == 128
    assert [row['role'] for row in connections] == ['observer'] + [
        role(case['split']) for case in cases]
    observer_connection = connections[0]
    daemon_pid, daemon_uid, daemon_gid = observer_connection['peer_credentials']
    assert daemon_pid > 0 and daemon_uid == identity['uid'] and daemon_gid == identity['gid']
    for connected in connections:
        assert connected['connection']['pid'] == identity['pid']
        assert connected['connection']['starttime_ticks'] == identity['starttime_ticks']
        assert connected['peer_credentials'] == [daemon_pid, identity['uid'], identity['gid']]
        assert connected['endpoint'] == observer_connection['endpoint']
    authenticated = [row for row in events if row['event'] == 'authenticated']
    assert [row['role'] for row in authenticated] == [row['role'] for row in connections]
    assert all(row['auth'] == ready['ok'] for row in authenticated)
    source_names = [case['source'] for case in cases]
    assert len(set(source_names)) == 127
    observer_receipts = ready['registration'] + ready['ownership']
    for case in cases:
        connected, = [v for v in connections if v['role'] == role(case['split'])]
        assert connected['connection'] == case['connection']
        assert case['connection']['pid'] == identity['pid']
        assert case['connection']['starttime_ticks'] == identity['starttime_ticks']
        validate_barrier(case['barrier'], case['connection'], case['prefix_trace'], control['ioctl'], control['kernel'])
        registered_reply, acquired = case['registration']
        validate_reply(registered_reply, 1, case['source'], string(case['source']), 's')
        validate_acquired(acquired, case['source'], case['source'])
        assert len(case['receipts']) == 2
        for row, request_serial in zip(case['receipts'], (2, 3)):
            validate_reply(row, request_serial, case['source'], ready['bus_id'], 's')
        sends = [v for v in events if v['event'] == 'wire' and v['direction'] == 'send'
                 and v['role'] == connected['role']]
        assert all(v['outcome'] == 'sent' for v in sends)
        split = case['split']
        expected = [auth, BEGIN + hello, get_id[:split], get_id[split:] + successor]
        assert [row['hex'] for row in sends] == [data.hex() for data in expected]
        prefix_sends = [row for row in case['prefix_trace'] if row['direction'] == 'send']
        expected_prefix = expected[:3]
        assert [row['hex'] for row in prefix_sends] == [data.hex() for data in expected_prefix]
        assert [{key: value for key, value in row.items() if key != 'event'}
                for row in sends[:len(expected_prefix)]] == prefix_sends
        source_wire = [row for row in events if row['event'] == 'wire' and row['role'] == connected['role']]
        held_wire = [{key: value for key, value in row.items() if key != 'event'}
                     for row in source_wire if row['monotonic'] < case['barrier']['finished']]
        assert held_wire == case['prefix_trace']
        assert not any(row['direction'] == 'receive' and row['completed'] >= prefix_sends[-1]['completed']
                       for row in held_wire)
        assert all(row['monotonic'] >= case['barrier']['finished'] for row in sends[len(expected_prefix):])
        auth_boundary = sends[1]['monotonic']
        validate_wire_stream(events, connected['role'], bytes.fromhex(ready['ok']),
                             case['registration'] + case['receipts'], auth_boundary)
        before_prefix = [row for row in source_wire if row['direction'] == 'receive'
                         and row['monotonic'] < sends[2]['monotonic']]
        assert all(row['completed'] <= sends[2]['monotonic'] for row in before_prefix)
        assert b''.join(bytes.fromhex(row['hex']) for row in before_prefix) == (
            bytes.fromhex(ready['ok']) + b''.join(validate_wire_receipt(row) for row in case['registration']))
        held_health = case['barrier']['health']
        assert held_health['source'] == case['source']
        validate_reply(held_health['source_owner'], held_health['source_owner_serial'],
                       ready['observer'], string(case['source']), 's')
        held_receives = [row for row in events if row['event'] == 'wire' and row['role'] == 'observer'
                         and row['direction'] == 'receive'
                         and held_health['started'] <= row['monotonic'] <= held_health['finished']]
        assert all(row['completed'] <= held_health['finished'] for row in held_receives)
        assert b''.join(bytes.fromhex(row['hex']) for row in held_receives) == b''.join(
            validate_wire_receipt(row) for row in held_health['receipts'] + [held_health['source_owner']])
        validate_reply(case['owner'], case['owner_serial'], ready['observer'], string(case['source']), 's')
        validate_reply(case['uid'], case['uid_serial'], ready['observer'], struct.pack('<I', identity['uid']).hex(), 'u')
        validate_reply(case['pid'], case['pid_serial'], ready['observer'], struct.pack('<I', identity['pid']).hex(), 'u')
        assert case['source'] != ready['observer']
        assert case['source_pending'] is False and case['received_fds'] == 0
        assert case['internal_accounting'] == case['source_parser_buffer'] == 'UNSUPPORTED'
        assert 0 <= case['ownership_disappearance_seconds'] <= 1
        gone = case['ownership_disappearance']
        assert gone and len(gone) == len(case['disappearance_serials'])
        for row, request_serial in zip(gone[:-1], case['disappearance_serials'][:-1]):
            validate_reply(row, request_serial, ready['observer'], string(case['source']), 's')
        last = fields(gone[-1])
        assert gone[-1]['type'] == 3 and last.get(5) == case['disappearance_serials'][-1]
        assert last.get(4) == 'org.freedesktop.DBus.Error.NameHasNoOwner'
        assert last.get(6) == ready['observer'] and last.get(7) == 'org.freedesktop.DBus'
        assert last.get(9, 0) == 0
        validate_health(case['after_close_health'], ready)
        validate_health(case['barrier']['health'], ready)
        observer_receipts += (held_health['receipts'] + [held_health['source_owner'], case['owner'], case['uid'], case['pid']]
                              + case['after_close_health']['receipts'] + gone)
    observer_receipts += result['final_health']['receipts']
    observer_sends = [row for row in events if row['event'] == 'wire' and row['role'] == 'observer'
                      and row['direction'] == 'send']
    assert len(observer_sends) >= 2
    assert [row['hex'] for row in observer_sends[:2]] == [auth.hex(), (BEGIN + hello + get_id).hex()]
    validate_wire_stream(events, 'observer', bytes.fromhex(ready['ok']), observer_receipts,
                         observer_sends[1]['monotonic'])
    return dict(result='PASS', cases=127, connections=128,
                observer=ready['observer'], owned=ready['owned'],
                bus_id=ready['bus_id'], hello_sha256=ready['hello_sha256'],
                get_id_sha256=ready['get_id_sha256'], internal_accounting='UNSUPPORTED',
                source_parser_buffer='UNSUPPORTED', native_frames_per_read='UNSUPPORTED',
                full_PRO01='INCOMPLETE', M1='INCOMPLETE', level='L0', product_qualified=False)


def validate_acquired(row, name, destination):
    header = fields(row)
    assert row['type'] == 4 and header.get(1) == '/org/freedesktop/DBus'
    assert header.get(2) == header.get(7) == 'org.freedesktop.DBus'
    assert header.get(3) == 'NameAcquired' and header.get(8) == 's'
    assert header.get(6) == destination and header.get(9, 0) == 0
    assert row['body'] == string(name)


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
           '<allow own="org.foundation.GetIdSplitObserver"/>'
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
        endpoint.chmod(0o600)
        info = endpoint.lstat()
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
        report['daemon'] = process_identity(daemon.pid)
        assert sha(Path('/proc') / str(daemon.pid) / 'exe') == inputs['dbus_sha256']
        assert report['daemon']['executable'] == str(Path(inputs['dbus_daemon']).resolve())
        lines = [line for line in Path('/proc/net/unix').read_text().splitlines()[1:]
                 if line.split()[-1] == str(endpoint)]
        line, = lines
        inode = int(line.split()[6])
        links = {p.name: os.readlink(p) for p in (Path('/proc') / str(daemon.pid) / 'fd').iterdir()}
        assert 'socket:[' + str(inode) + ']' in links.values()
        report['socket'] = dict(**socket_identity, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                                kernel_inode=inode, net_unix_line=line,
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
        connections = [row for row in events if row['event'] == 'connection']
        assert all(row['peer_credentials'] == [daemon.pid, os.getuid(), os.getgid()] for row in connections)
        actor_identity, = [row for row in events if row['event'] == 'identity']
        assert actor_identity['pid'] == actor.pid
        assert actor_identity['starttime_ticks'] == report['actor']['starttime_ticks']
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
            assert not report['failures'] and report['socket_removed'] and report['socket_parent_removed']
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
    auth_command(os.getuid())
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
             args.fixtures_dir / 'peer_get_id_split_boundaries_actor.py',
             args.fixtures_dir / 'transport_actor.py',
             HERE.parent / 'pro01_reference_hello' / 'actor.py',
             HERE.parent / 'pro01_reference_auth_begin' / 'actor.py',
             *[HERE / name for name in ('actor.py', 'run.py', 'test_fixture.py')]]
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
    spec = importlib.util.spec_from_file_location('pro01_get_id_existing_host_lifecycle', args.host_lifecycle)
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
