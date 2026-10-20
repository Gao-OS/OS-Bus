"""Explicit private D286 runner. Root authorizes execution after two reviews."""
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

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from scripts.foundation.pro01_reference_fd_splits import actor

HERE = Path(__file__).resolve().parent
DBUS = Path('/nix/store/pb9dhpk6qxjybb8p7prvs18ls2vxk51a-dbus-1.14.10/bin/dbus-daemon')
DBUS_SHA256 = 'e98a7397e16b01a3cae65f14e6d38195fc73b313887174d6e5e0bd98de418a9a'
PYTHON = Path('/nix/store/xqnbm0vgqcq9b1b54c80qj9s0qhbwa08-python3-3.13.15/bin/python3.13')
PYTHON_SHA256 = '56f78bdc0ad95ef4c2723243bbffb99a64fbef8b190916eecf8b1660137adfca'
LIFECYCLE = ROOT / 'test/reports/foundation/continuation-20261011-full-goal/environment/p08-next-action1/host_lifecycle.py'
LIFECYCLE_SHA256 = '7166b65ebc1e4bf623a8aaac1f2046be7c6d27c2dcad8f029af60e480f1be495'
VECTORS = ROOT / 'test/reports/foundation/resume-20261019/pro01-reference-fd-splits1/VECTORS.json'
VECTORS_SHA256 = '07dbacc89025c0ea31cc944a2f82bf5c01026196a95ad8039afe29529edd399e'
INPUT_PINS = ROOT / 'test/reports/foundation/continuation-20261011-full-goal/environment/m1-pro01-complete1/source-design1/INPUT_PINS1.json'
INPUT_PINS_SHA256 = '5038a804165ed4020e3600710cee3f801bdec4a636540acb3e8bffae46b96451'


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
                executable=os.readlink(root / 'exe'), cmdline=(root / 'cmdline').read_bytes().hex())


def string(value):
    return actor.wire.string(value).hex()


def validate_reply(row, serial, destination, body, signature):
    header = actor.fields(row)
    assert row['type'] == 2 and header.get(5) == serial
    assert header.get(6) == destination and header.get(7) == 'org.freedesktop.DBus'
    assert header.get(8) == signature and header.get(9, 0) == 0
    assert row['body'] == body


def validate_acquired(row, name, destination):
    header = actor.fields(row)
    assert row['type'] == 4 and header.get(1) == '/org/freedesktop/DBus'
    assert header.get(2) == header.get(7) == 'org.freedesktop.DBus'
    assert header.get(3) == 'NameAcquired' and header.get(8) == 's'
    assert header.get(6) == destination and header.get(9, 0) == 0
    assert row['body'] == string(name)


def health_rows(health, name, bus_id, owned=None):
    assert health['started'] <= health['finished']
    if owned is None:
        assert health['name'] == name and health['bus_id'] == bus_id
        validate_fence(health['fence'])
    else:
        assert health['observer'] == name and health['owned'] == owned and health['bus_id'] == bus_id
    first, second = health['receipts']
    serial = actor.fields(first)[5]
    validate_reply(first, serial, name, string(name), 's')
    validate_reply(second, serial + 1, name, bus_id, 's')
    rows = [first, second]
    calls = [actor.wire.call('GetNameOwner', serial, 's', actor.wire.string(owned or name)),
             actor.wire.call('GetId', serial + 1)]
    if 'owner' in health:
        query = health['owner']
        assert query['member'] == 'GetNameOwner'
        validate_reply(query['receipt'], query['serial'], name, string(query['name']), 's')
        rows.append(query['receipt'])
        calls.append(query_call(query))
    return rows, calls


def query_call(query):
    return actor.wire.call(query['member'], query['serial'], 's', actor.wire.string(query['name']))


def validate_credentials(queries, name, identity, observer, uid):
    assert [q['member'] for q in queries] == ['GetNameOwner', 'GetConnectionUnixUser', 'GetConnectionUnixProcessID']
    expected = [(string(name), 's'), (struct.pack('<I', uid).hex(), 'u'),
                (struct.pack('<I', identity['pid']).hex(), 'u')]
    for query, (body, signature) in zip(queries, expected):
        assert query['name'] == name
        validate_reply(query['receipt'], query['serial'], observer, body, signature)
    return [q['receipt'] for q in queries], [query_call(q) for q in queries]


def validate_fence(fence, identity=None):
    assert fence['pending'] is False and fence['started'] <= fence['finished']
    if identity is not None:
        assert fence['connection'] == identity


def validate_launch_order(events, successful):
    """Check saved exec/OPEN/retirement evidence without opening any resources."""
    expected = [actor.role(0), 'target'] + [actor.role(i) for i in range(1, 286)]
    launched, requested, gated, connected, registered, opened, stopped, cases, retired = {}, {}, {}, {}, {}, {}, {}, {}, {}
    pending = None
    cleanup = None

    def identity(row, name):
        assert all(row[key] == launched[name][key] for key in ('pid', 'starttime_ticks'))

    for row in events:
        event, name = row['event'], row.get('role')
        if event == 'role_launch':
            assert len(launched) < len(expected) and name == expected[len(launched)]
            assert pending is None, 'more than one pending exec'
            assert row['pid'] > 0 and row['starttime_ticks'] > 0
            assert row['started'] <= row['completed'] and row['deadline'] == row['completed'] + 3
            assert (row['pid'], row['starttime_ticks']) not in {
                (value['pid'], value['starttime_ticks']) for value in launched.values()}
            if name == 'target':
                assert actor.role(0) in opened
            elif name != actor.role(0):
                previous = actor.role(int(name.split('-')[1]) - 1)
                assert 'target' in opened and previous in opened and previous not in retired
            launched[name] = row
            pending = name
        elif event in ('role_open_request', 'role_open_gate'):
            assert name in launched and name not in stopped
            identity(row, name)
            launch = launched[name]
            assert row['command'] == 'open' and row['deadline'] == launch['deadline']
            if event == 'role_open_request':
                assert name == pending and name not in requested
                assert launch['completed'] <= row['requested'] <= launch['deadline']
                if name.startswith('source-') and name != actor.role(0):
                    previous = actor.role(int(name.split('-')[1]) - 1)
                    assert previous in retired
                    assert retired[previous]['finished'] <= row['requested']
                requested[name] = row
            else:
                assert name == pending and name in requested and name not in gated
                assert requested[name]['requested'] <= row['accepted'] <= launch['deadline']
                assert row['client_created'] is False and row['resource_fds'] == 0
                gated[name] = row
                pending = None
        elif event in ('identity', 'connection', 'registered', 'wire', 'receipt') and name != 'observer':
            assert name in gated and name not in stopped, 'child activity before OPEN gate'
            if event == 'identity':
                identity(row, name)
            elif event in ('connection', 'registered'):
                identity(row['connection'], name)
                rows = connected if event == 'connection' else registered
                assert name not in rows
                if event == 'registered':
                    assert name in connected and row['connection'] == connected[name]['connection']
                rows[name] = row
        elif event == 'role_process':
            assert name in registered and name not in opened and name not in stopped
            identity(row, name)
            assert row['deadline'] == launched[name]['deadline']
            assert gated[name]['accepted'] <= row['opened_completed'] <= row['deadline']
            opened[name] = row
        elif event == 'role_shutdown':
            assert name in launched and name not in stopped
            identity(row, name)
            assert row['pid_absent'] is True and row.get('failure') is None
            assert row['started'] <= row['finished'] <= row['deadline']
            assert 0 <= row['seconds'] <= 5 and row['seconds'] == row['finished'] - row['started']
            if row['normal']:
                assert name in opened and row['returncode'] == 0
                assert row['stdout_tail'] == row['stderr_tail'] == ''
                assert row['deadline'] == row['started'] + 5
            else:
                assert cleanup is not None and row['deadline'] == cleanup['deadline']
                assert cleanup['started'] <= row['started']
            stopped[name] = row
            if pending == name:
                pending = None
        elif event == 'case':
            name = row['source_role']
            assert row['index'] == len(cases) and name == actor.role(row['index'])
            assert name in stopped and stopped[name]['normal'] is True and name not in cases
            identity(row['connection'], name)
            assert stopped[name]['finished'] <= row['after_health']['finished']
            assert stopped[name]['finished'] <= row['target_health']['finished']
            cases[name] = row
        elif event == 'case_retired':
            assert name in cases and name not in retired and row['index'] == cases[name]['index']
            identity(row, name)
            assert max(cases[name]['after_health']['finished'], cases[name]['target_health']['finished']) <= row['finished']
            retired[name] = row
        elif event == 'failure_cleanup':
            assert cleanup is None and row['deadline'] == row['started'] + 5
            cleanup = row
    assert set(stopped) == set(launched), 'launched child missing cleanup'
    if successful:
        assert list(launched) == list(opened) == expected
        assert list(retired) == [actor.role(i) for i in range(286)]
        assert pending is None and cleanup is None
        assert all(row['normal'] is True for row in stopped.values())
    else:
        assert not launched or cleanup is not None or all(row['normal'] for row in stopped.values())
    return dict(launched=len(launched), opened=len(opened), retired=len(retired))


def validate_events(events):
    """Exhaustive finite census plus raw per-role send/receive/resource accounting."""
    validate_launch_order(events, successful=True)
    literals, = [e for e in events if e['event'] == 'literals']
    assert literals['vectors'] == [v.hex() for v in actor.vectors()]
    assert literals['sha256'] == [actor.FIRST_SHA256, actor.SECOND_SHA256, actor.TAIL_SHA256]
    control, = [e for e in events if e['event'] == 'kernel_control']
    assert control['passed'] is True and 0 <= control['seconds'] <= 1
    assert [v['phase'] for v in control['steps']] == ['before_send', 'unread', 'partial_read', 'complete_read']
    allocations = [v['allocation'] for v in control['steps']]
    assert allocations[0] == allocations[3] == 0 and allocations[1] > 0 and allocations[2] > 0
    assert control['received_sha256'] == control['payload_sha256']
    cases = [e for e in events if e['event'] == 'case']
    actor.validate_cases(cases)
    result, = [e for e in events if e['event'] == 'result']
    for key, value in dict(result='PASS', cases=286, connections=288, fd_frames=572,
                           usable_resources=1144, non_fd_tails=286).items():
        assert result[key] == value
    assert all(result[key] == 'UNSUPPORTED' for key in ('internal_accounting', 'source_parser_buffer', 'native_frames_per_read'))
    roles = ['observer', actor.role(0), 'target'] + [actor.role(i) for i in range(1, 286)]
    identities = [e for e in events if e['event'] == 'identity']
    connections = [e for e in events if e['event'] == 'connection']
    registered = [e for e in events if e['event'] == 'registered']
    assert all([e['role'] for e in rows] == roles for rows in (identities, connections, registered))
    assert len({e['pid'] for e in identities}) == 288
    assert len({(e['connection']['pid'], e['connection']['starttime_ticks'], e['connection']['inode']) for e in connections}) == 288
    uid, gid = identities[0]['uid'], identities[0]['gid']
    daemon_pid = connections[0]['peer_credentials'][0]
    by_role = {}
    for identity, connected, registration in zip(identities, connections, registered):
        name = identity['role']
        assert identity['uid'] == identity['euid'] == uid > 0
        assert identity['gid'] == identity['egid'] == gid > 0
        assert identity['pid'] > 0 and identity['starttime_ticks'] > 0
        assert connected['connection']['pid'] == identity['pid']
        assert connected['connection']['starttime_ticks'] == identity['starttime_ticks']
        assert connected['peer_credentials'] == [daemon_pid, uid, gid]
        assert connected['endpoint'] == connections[0]['endpoint']
        assert registration['connection'] == connected['connection']
        actor.validate_ok(bytes.fromhex(registration['auth']), bytes.fromhex(registered[0]['auth']))
        assert registration['agree'] == (b'' if name == 'observer' else actor.AGREE).hex()
        actor.reference.validate_completion(registration['registration'], registration['name'], registration['bus_id'])
        by_role[name] = dict(identity=identity, connection=connected['connection'], registration=registration)
    assert len({e['name'] for e in registered}) == 288
    assert [e['name'] for e in registered] == [':1.' + str(i) for i in range(288)]
    ready, = [e for e in events if e['event'] == 'ready']
    assert ready['observer'] == ':1.0' and ready['target'] == actor.TARGET and ready['owned'] == actor.OBSERVER
    bus_id = ready['bus_id']
    assert all(r['bus_id'] == bus_id for r in registered)
    observer_receipts = list(registered[0]['registration'])
    owned_reply, = [r for r in ready['ownership'] if r['type'] == 2]
    owned_signal, = [r for r in ready['ownership'] if r['type'] == 4]
    assert len(ready['ownership']) == 2
    validate_reply(owned_reply, 3, ':1.0', struct.pack('<I', 1).hex(), 'u')
    validate_acquired(owned_signal, actor.OBSERVER, ':1.0')
    observer_receipts += ready['ownership']
    request = actor.wire.string(actor.OBSERVER)
    observer_calls = [actor.wire.call('RequestName', 3, 'su', request + b'\0' * (-len(request) % 4) + actor.wire.u32(0))]
    for name in ('observer', 'target'):
        info = by_role[name]
        rows, calls = validate_credentials(ready['credentials'][name], info['registration']['name'],
                                           info['identity'], ':1.0', uid)
        observer_receipts += rows
        observer_calls += calls
    target_receipts = list(by_role['target']['registration']['registration'])
    target_calls = []
    target_connection = by_role['target']['connection']
    for index, case in enumerate(cases):
        assert case['index'] == index and case['source_role'] == actor.role(index)
        info = by_role[case['source_role']]
        assert case['source'] == info['registration']['name']
        assert case['connection'] == info['connection']
        rows, calls = validate_credentials(case['credentials'], case['source'], info['identity'], ':1.0', uid)
        observer_receipts += rows
        observer_calls += calls
        for health in (case['before_health'], case['barrier']['health']):
            assert health['owner']['name'] == case['source']
            rows, calls = health_rows(health, ':1.0', bus_id, actor.OBSERVER)
            observer_receipts += rows
            observer_calls += calls
        prefix = case['prefix']
        actor.validate_placement(prefix['prefix_sends'], case['mode'], case['split'], prefix['bundle']['identities'])
        assert prefix['bundle'] == case['bundles'][0]
        assert prefix['deadline'] == prefix['prefix_sends'][-1]['completed'] + 1
        baseline = case['baseline_snapshot']
        assert baseline['fds'] == case['baseline']
        assert case['before_health']['finished'] <= baseline['started'] <= baseline['finished']
        assert case['target_before']['finished'] <= baseline['started']
        assert baseline['finished'] <= prefix['prefix_sends'][0]['monotonic']
        actor.validate_hold(case['barrier'], info['connection'], prefix['prefix_trace'],
                            control['ioctl'], control['kernel'], case['baseline'], prefix['bundle']['identities'])
        for fence in case['barrier']['fences']:
            validate_fence(fence, target_connection)
        trace = [e for e in events if e['event'] == 'wire' and e['role'] == case['source_role']]
        held = [{k:v for k,v in row.items() if k != 'event'} for row in trace
                if row['monotonic'] < case['barrier']['finished']]
        assert held == prefix['prefix_trace']
        prelude = bytes.fromhex(info['registration']['auth'] + info['registration']['agree'])
        actor.validate_stream(held, prelude, info['registration']['registration'])
        held_health = case['barrier']['health']
        held_rows, _ = health_rows(held_health, ':1.0', bus_id, actor.OBSERVER)
        held_reads = [e for e in events if e['event'] == 'wire' and e['role'] == 'observer'
                      and e['direction'] == 'receive' and held_health['started'] <= e['monotonic'] <= held_health['finished']]
        assert all(row['completed'] <= held_health['finished'] for row in held_reads)
        actor.validate_stream(held_reads, b'', held_rows)
        sends = [r for r in trace if r['direction'] == 'send']
        setup = actor.auth_command(uid), actor.NEGOTIATE, actor.BEGIN + actor.hello.HELLO + actor.hello.GET_ID
        chunks = [(data, []) for data in setup]
        chunks += [(data, case['bundles'][0]['identities'] if rights else [])
                   for data, rights in actor.placement(case['mode'], case['split'])]
        chunks += [(actor.FIRST[case['split']:], []), (actor.SECOND, case['bundles'][1]['identities']), (actor.TAIL, [])]
        actor.validate_chunks(sends, chunks)
        prefix_sends = [r for r in held if r['direction'] == 'send']
        assert prefix_sends[-len(prefix['prefix_sends']):] == prefix['prefix_sends']
        assert all(r['monotonic'] >= case['barrier']['finished'] for r in sends[len(prefix_sends):])
        actor.validate_receipts(case['receipts'], case['source'], case['bundles'])
        validate_fence(case['target_fence'], target_connection)
        held_end = case['barrier']['finished']
        target_reads = [e for e in events if e['event'] == 'wire' and e['role'] == 'target'
                        and e['direction'] == 'receive'
                        and case['target_before']['finished'] <= e['monotonic'] <= case['target_fence']['finished']]
        assert all(held_end <= row['monotonic'] <= row['completed'] <= case['target_fence']['started'] for row in target_reads)
        actor.validate_stream(target_reads, b'', case['receipts'])
        for bundle in case['bundles']:
            assert len(set(bundle['identities'])) == len(bundle['payloads']) == 2
            assert all(bytes.fromhex(p) for p in bundle['payloads'])
        assert case['final_fds'] == case['baseline']
        settled = case['settlement']
        assert case['target_fence']['finished'] <= settled['started'] <= settled['finished'] <= settled['started'] + 1.5
        for phase in ('restored', 'after_reclaim'):
            snapshot = settled[phase]
            assert snapshot['fds'] == case['baseline']
            assert settled['started'] <= snapshot['started'] <= snapshot['finished'] <= settled['finished']
        assert case['source_pending'] is case['target_pending'] is False
        validate_fence(case['reclaim']['fence'], info['connection'])
        checks = case['reclaim']['checks']
        assert len(checks) == 4
        assert [c['identity'] for c in checks] == [v for b in case['bundles'] for v in b['identities']]
        assert len({c['writer'] for c in checks}) == 4
        assert all(c['outcome'] == 'BrokenPipeError' and c['started'] <= c['finished'] for c in checks)
        assert all(settled['started'] <= c['started'] <= c['finished'] <= settled['after_reclaim']['started'] for c in checks)
        assert case['internal_accounting'] == case['source_parser_buffer'] == 'UNSUPPORTED'
        gone = case['disappearance']
        assert gone and 0 <= case['disappearance_seconds'] <= 1.5
        for q in gone[:-1]:
            assert q['name'] == case['source'] and q['member'] == 'GetNameOwner'
            validate_reply(q['receipt'], q['serial'], ':1.0', string(case['source']), 's')
        last = gone[-1]
        assert last['name'] == case['source'] and last['member'] == 'GetNameOwner'
        header = actor.fields(last['receipt'])
        assert last['receipt']['type'] == 3 and header.get(5) == last['serial']
        assert header.get(4) == 'org.freedesktop.DBus.Error.NameHasNoOwner'
        assert header.get(6) == ':1.0' and header.get(7) == 'org.freedesktop.DBus' and header.get(9, 0) == 0
        observer_receipts += [q['receipt'] for q in gone]
        observer_calls += [query_call(q) for q in gone]
        rows, calls = health_rows(case['after_health'], ':1.0', bus_id, actor.OBSERVER)
        observer_receipts += rows
        observer_calls += calls
        for key in ('target_before', 'target_health'):
            rows, calls = health_rows(case[key], actor.TARGET, bus_id)
            assert case[key]['fence']['connection'] == target_connection
            target_receipts += rows
            target_calls += calls
            if key == 'target_before':
                target_receipts += case['receipts']
    rows, calls = health_rows(result['final_health'], ':1.0', bus_id, actor.OBSERVER)
    observer_receipts += rows
    observer_calls += calls
    rows, calls = health_rows(result['target_health'], actor.TARGET, bus_id)
    target_receipts += rows
    target_calls += calls
    expected_receipts = {name: list(info['registration']['registration']) for name, info in by_role.items()}
    expected_receipts.update(observer=observer_receipts, target=target_receipts)
    for name in roles:
        trace = [e for e in events if e['event'] == 'wire' and e['role'] == name]
        info = by_role[name]
        observed = [e['receipt'] for e in events if e['event'] == 'receipt' and e['role'] == name]
        assert observed == expected_receipts[name]
        prelude = bytes.fromhex(info['registration']['auth'] + info['registration']['agree'])
        actor.validate_stream(trace, prelude, expected_receipts[name])
        if name in ('observer', 'target'):
            setup = [(actor.auth_command(uid), [])]
            if name == 'target': setup.append((actor.NEGOTIATE, []))
            setup.append((actor.BEGIN + actor.hello.HELLO + actor.hello.GET_ID, []))
            setup += [(c, []) for c in (observer_calls if name == 'observer' else target_calls)]
            actor.validate_chunks([e for e in trace if e['direction'] == 'send'], setup)
    shutdowns = [e for e in events if e['event'] == 'role_shutdown']
    processes = [e for e in events if e['event'] == 'role_process']
    assert [e['role'] for e in processes] == roles[1:]
    assert len({e['executable'] for e in processes}) == 1
    for row in processes:
        assert all(row[k] == by_role[row['role']]['identity'][k] for k in ('pid', 'starttime_ticks'))
        assert Path(row['executable']) == PYTHON
    assert [e['role'] for e in shutdowns] == [actor.role(i) for i in range(286)] + ['target']
    for row in shutdowns:
        assert row['pid'] == by_role[row['role']]['identity']['pid']
        assert row['returncode'] == 0 and row['pid_absent'] is row['normal'] is True
        assert row.get('failure') is None
        assert row['stdout_tail'] == row['stderr_tail'] == '' and row['seconds'] <= 5
    assert not any(e['event'] == 'role_stderr' for e in events)
    assert all(e['event'] != 'wire' or e['role'] in by_role for e in events)
    return dict(result='PASS', cases=286, connections=288, fd_frames=572, usable_resources=1144,
                non_fd_tails=286, full_PRO01='INCOMPLETE', M1='INCOMPLETE', level='L0',
                product_qualified=False, internal_accounting='UNSUPPORTED',
                source_parser_buffer='UNSUPPORTED', native_frames_per_read='UNSUPPORTED')


def validate_cleanup(report):
    assert report['status'] == 'passed' and report['actor_returncode'] == 0
    assert report['failures'] == [] and report['socket_removed'] is report['socket_parent_removed'] is True
    assert 0 <= report['cleanup_seconds'] <= 5
    assert [r['role'] for r in report['cleanup']] == ['actor', 'reference']
    assert all(r['pid_absent'] is True for r in report['cleanup'])
    assert report['cleanup'][0]['returncode'] == 0


def configuration(endpoint, uid):
    return ('<busconfig><type>system</type><listen>unix:path=' + str(endpoint) + '</listen>'
            '<auth>EXTERNAL</auth><policy context="default"><deny user="*"/>'
            '<allow user="' + str(uid) + '"/><deny own="*"/>'
            '<deny send_destination="*"/><deny receive_sender="*"/></policy>'
            '<policy user="' + str(uid) + '"><allow own="' + actor.OBSERVER + '"/>'
            '<allow send_destination="org.freedesktop.DBus"/>'
            '<allow receive_sender="org.freedesktop.DBus"/>'
            '<allow send_destination=":1.2" send_type="signal" send_path="/foundation" '
            'send_interface="org.foundation.Transport" send_member="Resource"/>'
            '<allow receive_type="signal" receive_path="/foundation" '
            'receive_interface="org.foundation.Transport" receive_member="Resource"/>'
            '</policy></busconfig>')


def worker(directory):
    inputs = json.loads((directory / 'inputs.json').read_text())
    check_inputs(inputs)
    socket_parent = Path(inputs['socket_parent'])
    parent_info = socket_parent.lstat()
    assert stat.S_ISDIR(parent_info.st_mode) and stat.S_IMODE(parent_info.st_mode) == 0o700
    assert parent_info.st_uid == os.getuid()
    assert dict(device=parent_info.st_dev, inode=parent_info.st_ino) == inputs['socket_parent_identity']
    endpoint, config = socket_parent / 'bus', directory / 'reference.conf'
    xml = configuration(endpoint, os.getuid())
    config.write_text(xml)
    config.chmod(0o600)
    report = dict(status='running', backend='reference', endpoint=str(endpoint),
                  configuration=dict(path=str(config), sha256=sha(config), bytes=xml),
                  commands=[], failures=[], cleanup=[])
    daemon = child = None
    socket_identity = None
    logs = []
    began = time.monotonic()
    def persist(): save(directory / 'worker.json', report)
    persist()
    try:
        argv = [inputs['dbus_daemon'], '--nofork', '--nopidfile', '--config-file=' + str(config)]
        report['commands'].append(argv)
        log = (directory / 'daemon.log').open('xb')
        logs.append(log)
        daemon = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=clean_env())
        limit = time.monotonic() + 10
        while not endpoint.exists():
            assert daemon.poll() is None, 'reference exited during startup'
            assert time.monotonic() < limit, 'reference startup10s deadline'
            time.sleep(.01)
        info = endpoint.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        socket_identity = dict(device=info.st_dev, inode=info.st_ino)
        endpoint.chmod(0o600)
        info = endpoint.lstat()
        assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid()
        report['daemon'] = process_identity(daemon.pid)
        assert sha(Path('/proc', str(daemon.pid), 'exe')) == DBUS_SHA256
        assert report['daemon']['executable'] == str(DBUS.resolve())
        lines = [line for line in Path('/proc/net/unix').read_text().splitlines()[1:]
                 if line.split()[-1] == str(endpoint)]
        line, = lines
        inode = int(line.split()[6])
        links = actor.fd_donor.inventory(str(daemon.pid))
        assert 'socket:[' + str(inode) + ']' in links.values()
        report['socket'] = dict(**socket_identity, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                                kernel_inode=inode, net_unix_line=line, daemon_fd_links=links)
        argv = [str(PYTHON), '-B', str(HERE / 'actor.py'), str(endpoint), inputs['fixtures_dir'], str(daemon.pid)]
        report['commands'].append(argv)
        raw, errors = (directory / 'actor.jsonl').open('xb'), (directory / 'actor.stderr').open('xb')
        logs.extend([raw, errors])
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=raw, stderr=errors, env=clean_env())
        report['actor'] = process_identity(child.pid)
        persist()
        report['actor_returncode'] = child.wait(timeout=45)
        assert report['actor_returncode'] == 0, 'actor failed; preserve raw output without retry'
        assert daemon.poll() is None
        events = [json.loads(line) for line in (directory / 'actor.jsonl').read_text().splitlines()]
        report['semantic_result'] = validate_events(events)
        identities = [e for e in events if e['event'] == 'identity']
        assert identities[0]['pid'] == child.pid
        assert identities[0]['starttime_ticks'] == report['actor']['starttime_ticks']
        assert all(e['peer_credentials'] == [daemon.pid, os.getuid(), os.getgid()]
                   for e in events if e['event'] == 'connection')
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', failure=repr(error))
    finally:
        cleanup_started = time.monotonic()
        for name, process in (('actor', child), ('reference', daemon)):
            if process is None: continue
            try:
                if process.poll() is None: process.send_signal(signal.SIGTERM)
                code = process.wait(timeout=max(.001, cleanup_started + 5 - time.monotonic()))
                report['cleanup'].append(dict(role=name, returncode=code,
                                              pid_absent=not Path('/proc', str(process.pid)).exists()))
            except Exception as error:
                report['failures'].append(dict(role=name, cleanup_error=repr(error)))
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
        for log in logs: log.close()
        if report['status'] != 'passed' and (directory / 'actor.jsonl').exists():
            try:
                events = [json.loads(line) for line in (directory / 'actor.jsonl').read_text().splitlines()]
                if any(row['event'] == 'role_launch' for row in events):
                    report['failed_launch_cleanup'] = validate_launch_order(events, successful=False)
            except Exception as error:
                report['failures'].append(dict(failed_launch_cleanup_error=repr(error)))
        try:
            check_inputs(inputs)
            assert sha(config) == report['configuration']['sha256']
            validate_cleanup(report)
        except Exception as error:
            report['failures'].append(repr(error))
        if report['failures']: report['status'] = 'failed'
        persist()
    return 0 if report['status'] == 'passed' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--socket-parent', type=Path, required=True)
    parser.add_argument('--dbus-daemon', type=Path, default=DBUS)
    parser.add_argument('--dbus-sha256', default=DBUS_SHA256)
    parser.add_argument('--fixtures-dir', type=Path, default=actor.FIXTURES)
    parser.add_argument('--host-lifecycle', type=Path, default=LIFECYCLE)
    args = parser.parse_args()
    assert not sys.flags.optimize and sys.platform == 'linux'
    assert os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0
    assert args.dbus_daemon == DBUS and args.dbus_sha256 == sha(DBUS) == DBUS_SHA256
    assert Path(sys.executable).resolve() == PYTHON.resolve() and sha(PYTHON) == PYTHON_SHA256
    assert args.fixtures_dir == actor.FIXTURES and args.host_lifecycle == LIFECYCLE
    assert sha(LIFECYCLE) == LIFECYCLE_SHA256 and sha(VECTORS) == VECTORS_SHA256
    assert sha(INPUT_PINS) == INPUT_PINS_SHA256
    assert all(p.is_absolute() for p in (args.output, args.socket_parent))
    assert len(os.fsencode(str(args.socket_parent / 'bus'))) < 108
    assert not os.path.lexists(args.output) and not os.path.lexists(args.socket_parent)
    values = json.loads(VECTORS.read_text())['vectors']
    assert [values[k]['hex'] for k in ('first_serial10', 'second_serial11', 'tail_serial12')] == [v.hex() for v in actor.vectors()]
    args.output.mkdir(mode=0o700)
    args.output.chmod(0o700)
    paths = [DBUS, PYTHON, LIFECYCLE, VECTORS, INPUT_PINS,
             *[actor.FIXTURES / name for name in ('transport_actor.py', 'peer_hello_split_boundaries_actor.py',
                                                 'peer_fd_split_boundaries_actor.py')],
             *[HERE.parent / name / 'actor.py' for name in ('pro01_reference_auth_begin', 'pro01_reference_hello',
                                                           'pro01_reference_get_id')],
             *[HERE / name for name in ('actor.py', 'run.py', 'test_fixture.py')]]
    inputs = dict(dbus_daemon=str(DBUS), dbus_sha256=DBUS_SHA256, fixtures_dir=str(actor.FIXTURES),
                  host_lifecycle=str(LIFECYCLE), pins={str(p):sha(p) for p in paths},
                  clean_environment=clean_env(), python_version=sys.version, kernel=os.uname().release,
                  uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
                  vectors=[v.hex() for v in actor.vectors()])
    args.socket_parent.mkdir(mode=0o700)
    args.socket_parent.chmod(0o700)
    info = args.socket_parent.lstat()
    inputs.update(socket_parent=str(args.socket_parent), socket_parent_identity=dict(device=info.st_dev, inode=info.st_ino))
    save(args.output / 'inputs.json', inputs)
    spec = importlib.util.spec_from_file_location('pro01_fd_splits_existing_host_lifecycle', LIFECYCLE)
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    before, errors = lifecycle.snapshot()
    assert not errors, errors
    baseline_groups = {row['pgid'] for row in before.values()}
    started = time.monotonic()
    with (args.output / 'worker.stdout').open('xb') as stdout, (args.output / 'worker.stderr').open('xb') as stderr:
        child = subprocess.Popen([str(PYTHON), '-B', str(HERE / 'run.py'), '--worker', str(args.output)],
                                 stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=clean_env(), start_new_session=True)
        outcome = lifecycle.complete(child, started, baseline_groups, lambda:check_inputs(inputs),
                                     lambda value:save(args.output / 'lifecycle.json', value))
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
