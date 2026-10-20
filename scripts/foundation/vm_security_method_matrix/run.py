"""Ten SEC-14 method regressions on the unchanged disposable security harness."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / 'vm_security'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = load('method_matrix_recorded_client', HERE / 'actor.py')
modules, search_path = sys.modules.copy(), sys.path[:]
try:
    sys.modules['actor'] = wire.original
    sys.path.insert(0, str(SHARED))
    shared = load('method_matrix_security_harness', SHARED / 'run.py')
finally:
    for name in set(sys.modules) - set(modules):
        del sys.modules[name]
    sys.modules.update(modules)
    sys.path[:] = search_path

BUS = shared.BUS
OBSERVER = 'org.foundation.Observer'
OWNED = 'org.foundation.Service.MethodMatrix'
RULE = "type='signal',interface='org.foundation.MethodMatrix'"
SOCKET = '/run/osbus-security/method-matrix/bus'
WORKLOAD = json.loads((HERE / 'workload.json').read_text())
EXPECTED_IDS = [
    'SEC-14.request-name-signature', 'SEC-14.release-name-signature',
    'SEC-14.get-name-owner-signature', 'SEC-14.name-has-owner-signature',
    'SEC-14.add-match-signature', 'SEC-14.remove-match-signature',
    'SEC-14.properties-get-signature', 'SEC-14.list-names-signature',
    'SEC-14.list-names-interface', 'SEC-14.properties-get-path',
]
EXPECTED_CASES = [dict(id=identifier, member=member, signature=signature, body=body,
    error=BUS + '.Error.' + error, interface=interface, path=path)
    for identifier, (member, signature, body, error, interface, path) in zip(EXPECTED_IDS, [
        ('RequestName', 's', ['org.foundation.Forbidden'], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('ReleaseName', '', [], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('GetNameOwner', 'u', [1], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('NameHasOwner', '', [], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('AddMatch', 'u', [1], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('RemoveMatch', '', [], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('Get', '', [], 'InvalidArgs', BUS + '.Properties', '/org/freedesktop/DBus'),
        ('ListNames', 'u', [1], 'InvalidArgs', BUS, '/org/freedesktop/DBus'),
        ('ListNames', '', [], 'UnknownInterface', 'org.foundation.Wrong', '/org/freedesktop/DBus'),
        ('Get', '', [], 'UnknownInterface', BUS + '.Properties', '/wrong'),
    ])]
assert WORKLOAD['cases'] == EXPECTED_CASES
SELECTED = [row['id'] for row in WORKLOAD['cases']]
assert WORKLOAD['inherited_security_selection'] == shared.SELECTED
assert WORKLOAD['healthy_probe_ms'] == 1000 and WORKLOAD['quiescence_ms'] == 2000
assert WORKLOAD['socket'] == SOCKET and WORKLOAD['authority_timeout_seconds'] == 60
assert WORKLOAD['guest_timeout_seconds'] == 120 and WORKLOAD['host_timeout_seconds'] == 900


def counts(outcomes):
    statuses = [row['status'] for row in outcomes.values()]
    assert all(value in ('passed', 'failed', 'blocked', 'running') for value in statuses)
    return dict(selected=len(SELECTED), executed=sum(value in ('passed', 'failed') for value in statuses),
        passed=statuses.count('passed'), failed=statuses.count('failed'),
        blocked=statuses.count('blocked') + statuses.count('running'), skipped=0)


def request(member, signature='', body=(), **options):
    return dict(member=member, signature=signature, body=list(body),
        interface=options.get('interface', BUS), path=options.get('path', '/org/freedesktop/DBus'))


def exchange(value, expected, error=None):
    assert set(value) == {'request_serial', 'request_hex', 'reply'}
    serial = value['request_serial']
    assert type(serial) is int and 0 < serial <= 0xFFFFFFFF
    raw = bytes.fromhex(value['request_hex'])
    assert raw == wire.packet(serial, **expected), 'wrong raw method request'
    decoded = wire.decode_frame(raw)
    assert decoded['serial'] == serial and decoded['type'] == 1 and decoded['flags'] == 0
    reply = wire.decode_frame(bytes.fromhex(value['reply']['frame_hex']))
    assert reply == value['reply'], 'raw reply and decoded evidence differ'
    assert type(reply['reply_serial']) is int and reply['reply_serial'] == serial, 'uncorrelated reply'
    assert reply['sender'] == BUS and reply['type'] == (3 if error else 2)
    assert reply['error'] == error
    if error:
        assert reply['signature'] == 's' and len(reply['body']) == 1 and type(reply['body'][0]) is str
    return reply


def normal(state):
    assert set(state) == {'event', 'router', 'peers', 'names', 'queues', 'usage', 'policy'}
    assert state['event'] == 'snapshot'
    usage = state['usage']
    assert type(usage['reservations']) is int and usage['reservations'] >= 0
    credit_maps = [usage['global']] + [row['counts'] for key in ('peers', 'uids') for row in usage[key]]
    assert all(type(value) is int and value >= 0 for counters in credit_maps for value in counters.values())
    result = copy.deepcopy(state)
    result['names'].sort()
    result['peers'].sort(key=lambda row: row['peer'])
    for peer in result['peers']:
        peer['names'].sort()
    result['queues'].sort(key=lambda row: row['name'])
    result['usage']['peers'].sort(key=lambda row: row['peer'])
    result['usage']['uids'].sort(key=lambda row: row['uid'])
    return result


def quiet(metrics):
    state = metrics['snapshot']
    credit_maps = [state['usage']['global']] + [row['counts']
        for key in ('peers', 'uids') for row in state['usage'][key]]
    return (metrics['policy_queue'] == metrics['router_queue'] == 0 and state['usage']['reservations'] == 0
        and state['usage']['global']['connections'] == len(state['peers'])
        and all(value == 0 for counters in credit_maps for key, value in counters.items() if key != 'connections'))


def settled(value):
    assert set(value) == {'state', 'samples', 'attempts', 'elapsed_ms'}
    assert type(value['attempts']) is int and 2 <= value['attempts'] == len(value['samples']) <= 128
    assert type(value['elapsed_ms']) in (int, float) and 0 <= value['elapsed_ms'] <= WORKLOAD['quiescence_ms']
    assert all(sample['event'] == 'metrics' for sample in value['samples'])
    assert quiet(value['samples'][-2]) and quiet(value['samples'][-1])
    state = normal(value['state'])
    assert normal(value['samples'][-2]['snapshot']) == normal(value['samples'][-1]['snapshot']) == state
    return state


def identity_binding(state, identities):
    assert set(identities) == {'observer', 'test'} and len(state['peers']) == 2
    peers = {}
    for role, uid in [('observer', 1100), ('test', 1101)]:
        identity = identities[role]
        assert type(identity['pid']) is type(identity['uid']) is type(identity['gid']) is int
        assert identity['pid'] > 1 and identity['uid'] == uid and identity['gid'] >= 0
        assert identity['unique'].startswith(':')
        lines = identity['proc_status'].splitlines()
        assert int(next(line for line in lines if line.startswith('Pid:')).split()[1]) == identity['pid']
        for key, number in [('Uid:', uid), ('Gid:', identity['gid'])]:
            assert [int(item) for item in next(line for line in lines if line.startswith(key)).split()[1:]] == [number] * 4
        matching = [peer for peer in state['peers'] if peer['name'] == identity['unique']]
        assert len(matching) == 1
        peer = matching[0]
        assert all(type(peer['credentials'][key]) is int and peer['credentials'][key] == identity[key] for key in ('pid', 'uid', 'gid'))
        peers[role] = peer
    assert peers['observer']['peer'] != peers['test']['peer']
    assert OBSERVER in peers['observer']['names'] and OBSERVER in state['names']
    assert all(type(peer['capabilities']) is int and peer['capabilities'] == 0 for peer in peers.values())
    return peers


def followup_plan(case):
    if case['member'] in ('RequestName', 'ReleaseName'):
        return [request('RequestName', 'su', [OWNED, 0]), request('GetNameOwner', 's', [OWNED]),
            request('ReleaseName', 's', [OWNED]), request('NameHasOwner', 's', [OWNED])]
    if case['member'] in ('AddMatch', 'RemoveMatch'):
        return [request('AddMatch', 's', [RULE]), request('RemoveMatch', 's', [RULE])]
    if case['member'] == 'GetNameOwner':
        return [request('GetNameOwner', 's', [OBSERVER])]
    if case['member'] == 'NameHasOwner':
        return [request('NameHasOwner', 's', [OBSERVER])]
    if case['member'] == 'Get':
        return [request('Get', 'ss', [BUS, 'Features'], interface=BUS + '.Properties')]
    assert case['member'] == 'ListNames'
    return [request('ListNames'), request('ListNames', path='/wrong')]


def followup_reply(reply, method, identities, baseline):
    member = method['member']
    if member in ('RequestName', 'ReleaseName'):
        assert reply['signature'] == 'u' and reply['body'] == [1] and type(reply['body'][0]) is int
    elif member == 'GetNameOwner':
        role = 'test' if method['body'] == [OWNED] else 'observer'
        assert reply['signature'] == 's' and reply['body'] == [identities[role]['unique']]
    elif member == 'NameHasOwner':
        assert reply['signature'] == 'b' and reply['body'] == [method['body'] == [OBSERVER]] and type(reply['body'][0]) is bool
    elif member in ('AddMatch', 'RemoveMatch'):
        assert reply['signature'] == '' and reply['body'] == []
    elif member == 'Get':
        assert reply['signature'] == 'v' and reply['body'] == [dict(signature='as', value=[])]
    else:
        assert member == 'ListNames' and reply['signature'] == 'as' and len(reply['body']) == 1
        names = reply['body'][0]
        assert len(names) == len(set(names)) and {BUS, OBSERVER, *(row['unique'] for row in identities.values())} <= set(names)
        assert set(names) == set(baseline['names']), 'ListNames differs from settled authority state'


def validate_case(index, evidence, serial):
    assert set(evidence) == {'index', 'case', 'invalid', 'before', 'after_error', 'identities_before',
        'identities_after', 'followups', 'effects', 'retired', 'probe'}
    case = WORKLOAD['cases'][index]
    assert type(evidence['index']) is int and evidence['index'] == index and evidence['case'] == case
    method = {key: case[key] for key in ('member', 'signature', 'body', 'interface', 'path')}
    exchange(evidence['invalid'], method, case['error'])
    assert evidence['invalid']['request_serial'] == serial
    before = settled(evidence['before'])
    assert settled(evidence['after_error']) == settled(evidence['retired']) == before, 'method rejection/effects changed baseline'
    peers = identity_binding(before, evidence['identities_before'])
    identity_binding(settled(evidence['after_error']), evidence['identities_after'])
    assert all({key: evidence['identities_before'][role][key] for key in ('pid', 'uid', 'gid', 'unique')}
        == {key: evidence['identities_after'][role][key] for key in ('pid', 'uid', 'gid', 'unique')} for role in ('observer', 'test'))
    assert all(peer['match_rules'] is False for peer in peers.values()) and OWNED not in before['names']
    assert 'org.foundation.Forbidden' not in before['names']
    plan = followup_plan(case)
    assert len(evidence['followups']) == len(plan)
    for offset, (value, expected) in enumerate(zip(evidence['followups'], plan), 1):
        assert value['request_serial'] == serial + offset
        followup_reply(exchange(value, expected), expected, evidence['identities_after'], before)
    expected_effects = [0] if case['member'] in ('RequestName', 'ReleaseName', 'AddMatch', 'RemoveMatch') else []
    assert [effect['after_step'] for effect in evidence['effects']] == expected_effects
    for effect in evidence['effects']:
        assert type(effect['after_step']) is int
        state = settled(effect['observation'])
        live = identity_binding(state, evidence['identities_after'])['test']
        if case['member'] in ('RequestName', 'ReleaseName'):
            assert OWNED in state['names'] and OWNED in live['names']
            queue = [row for row in state['queues'] if row['name'] == OWNED]
            assert len(queue) == 1 and queue[0]['owner'] == live['peer'] and queue[0]['unique'] == live['name'] and queue[0]['queue'] == []
        else:
            assert live['match_rules'] is True
    probe = evidence['probe']
    assert type(probe['elapsed_ms']) in (int, float) and 0 <= probe['elapsed_ms'] <= WORKLOAD['healthy_probe_ms']
    assert len(probe['calls']) == 2
    result = exchange(probe['calls'][0], request('GetNameOwner', 's', [OBSERVER]))
    followup_reply(result, request('GetNameOwner', 's', [OBSERVER]), evidence['identities_after'], before)
    result = exchange(probe['calls'][1], request('GetId'))
    assert result['signature'] == 's' and len(result['body']) == 1 and result['body'][0]
    assert probe['calls'][1]['request_serial'] == probe['calls'][0]['request_serial'] + 1
    return serial + len(plan) + 1


def validate_shutdown(report):
    assert report['shutdown_errors'] == [] and report['socket_removed'] is True
    assert len(report['owned']) == len(report['shutdown']) == 3
    assert len({row['pid'] for row in report['owned']}) == 3
    for owned, row in zip(report['owned'], report['shutdown']):
        assert all(type(owned[key]) is int and owned[key] > 1 for key in ('pid', 'pgid', 'sid'))
        assert owned['pid'] == owned['pgid'] == owned['sid'] == row['pid']
        assert row['command'] == owned['command'] and row['method'] == 'eof'
        assert type(row['returncode']) is int and row['returncode'] == 0
        assert row['pid_absent'] is row['group_absent'] is True
    assert report['actor_pids_absent'] == {'observer': True, 'test': True}


def complete(report):
    assert {'selected', 'execution_order', 'outcomes', 'counts', 'shutdown_errors',
        'socket_removed', 'owned', 'shutdown', 'actor_pids_absent'} <= set(report), 'missing required evidence'
    assert type(report['outcomes']) is dict and type(report['counts']) is dict
    assert all(type(value) is int for value in report['counts'].values())
    assert report['selected'] == SELECTED and report['execution_order'] == SELECTED
    assert set(report['outcomes']) == set(SELECTED)
    assert report['counts'] == counts(report['outcomes']) == dict(selected=10, executed=10, passed=10, failed=0, blocked=0, skipped=0)
    serial, observer_serial, previous = 2, 3, None
    for index, identifier in enumerate(SELECTED):
        row = report['outcomes'][identifier]
        assert set(row) == {'status', 'evidence'} and row['status'] == 'passed'
        serial = validate_case(index, row['evidence'], serial)
        assert [call['request_serial'] for call in row['evidence']['probe']['calls']] == [observer_serial, observer_serial + 1]
        observer_serial += 2
        current = settled(row['evidence']['before'])
        if previous is not None:
            assert current == previous, 'cross-case Router/peer/name/credit/policy drift'
        previous = current
    validate_shutdown(report)


def validate_candidate(candidate, manifest):
    assert manifest['version'] == 1 and manifest['not_a_release'] is True
    assert stat.S_ISDIR(candidate.lstat().st_mode), 'candidate must be a real directory'
    assert set(manifest['files']) == set(manifest['file_modes'])
    verified = {}
    for name, expected_hash in manifest['files'].items():
        relative = Path(name)
        assert relative.parts and not relative.is_absolute() and '..' not in relative.parts
        path = candidate
        for index, part in enumerate(relative.parts):
            path = path / part
            metadata = path.lstat()
            assert (stat.S_ISREG(metadata.st_mode) if index == len(relative.parts) - 1
                else stat.S_ISDIR(metadata.st_mode)), 'candidate file type or symlink mismatch'
        source_mode = manifest['file_modes'][name]
        assert type(source_mode) is int and source_mode in (0o644, 0o755), 'incompatible trusted source mode'
        expected_mode = 0o555 if source_mode & 0o111 else 0o444
        frozen_mode = stat.S_IMODE(metadata.st_mode)
        assert frozen_mode == expected_mode, 'candidate Nix readonly mode mismatch'
        actual_hash = shared.sha(path)
        assert actual_hash == expected_hash, 'candidate bytes differ from trusted manifest'
        verified[name] = dict(source_mode=source_mode, expected_frozen_mode=expected_mode,
            frozen_mode=frozen_mode, sha256=actual_hash, file_type='regular')
    return dict(mode_contract='Nix readonly: 0444 data, 0555 executable from trusted source mode', files=verified)


def main(candidate, evidence):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-security/method-matrix'
    for directory in (evidence.parent, evidence):
        assert directory.stat().st_uid == 0 and stat.S_IMODE(directory.stat().st_mode) == 0o755 and not directory.is_symlink()
    assert not Path(SOCKET).exists() and not (evidence / 'qualification.json').exists()
    manifest = json.loads((candidate / 'candidate.json').read_text())
    candidate_validation = validate_candidate(candidate, manifest)
    policy = evidence / 'policy.exs'
    shutil.copyfile(SHARED / 'policy.exs', policy)
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    daemon_command = command + [str(SHARED / 'daemon.exs'), SOCKET, str(policy)]
    report = dict(profile=WORKLOAD['profile'], workload=WORKLOAD, selected=SELECTED,
        outcomes={key: dict(status='blocked', reason='not_executed') for key in SELECTED}, execution_order=[],
        candidate_manifest_sha256=shared.sha(candidate / 'candidate.json'), candidate=manifest,
        candidate_validation=candidate_validation,
        fixture_sha256={str(path): shared.sha(path) for path in (
            HERE / 'actor.py', HERE / 'run.py', HERE / 'workload.json', HERE / 'test_fixture.py', HERE / 'README.md', HERE / 'test.nix',
            SHARED / 'actor.py', SHARED / 'run.py', SHARED / 'daemon.exs', SHARED / 'policy.exs', SHARED / 'state.ex', SHARED / 'workload.json')},
        configuration=policy.read_text(), config_sha256=shared.sha(policy), tools={tool: str(Path(shutil.which(tool)).resolve()) for tool in ('elixir', 'erl', 'python3', 'runuser')},
        owned=[], actors={}, daemon=None, snapshots=[], result='incomplete', product_qualified=False, readiness='L0',
        scope='Ten independent SEC-14 subcases only; original21 unchanged; full goal incomplete')
    channels = []
    daemon = None

    def persist():
        report['counts'] = counts(report['outcomes'])
        temporary = evidence / 'qualification.json.tmp'
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        temporary.replace(evidence / 'qualification.json')

    def own(worker):
        channels.append(worker)
        report['owned'].append(dict(command=worker.command, pid=worker.process.pid,
            pgid=os.getpgid(worker.process.pid), sid=os.getsid(worker.process.pid)))
        persist()
        return worker

    def call(worker, method, timeout=3):
        worker.begin(op='call', **method)
        response = worker.read(timeout=timeout)
        assert response['ok'], response
        return response['result']

    def identities():
        value = copy.deepcopy(report['actors'])
        for row in value.values():
            row['proc_status'] = Path(f"/proc/{row['pid']}/status").read_text()
        return value

    def settle(expected=None):
        start = time.monotonic()
        deadline = start + WORKLOAD['quiescence_ms'] / 1000
        samples, previous = [], None
        while len(samples) < 128 and time.monotonic() < deadline:
            daemon.process.stdin.write(b'metrics\n')
            daemon.process.stdin.flush()
            metrics = daemon.read(timeout=max(deadline - time.monotonic(), 0.001))
            samples.append(metrics)
            report['snapshots'].append(metrics)
            state = normal(metrics['snapshot'])
            now = time.monotonic()
            if now <= deadline and quiet(metrics) and state == previous and (expected is None or state == expected):
                return dict(state=metrics['snapshot'], samples=samples, attempts=len(samples), elapsed_ms=(now - start) * 1000)
            previous = state if quiet(metrics) else None
        raise AssertionError(('method-matrix quiescence deadline', samples))

    persist()
    try:
        daemon = own(shared.Channel(daemon_command, evidence / 'daemon.log', 'FIXTURE '))
        report['daemon'] = daemon.read()
        assert report['daemon']['event'] == 'ready' and int(report['daemon']['pid']) == daemon.process.pid
        assert report['daemon']['identity']['uid'] == 0 and stat.S_IMODE(Path(SOCKET).stat().st_mode) == 0o666
        report['daemon_proc_status'] = Path(f'/proc/{daemon.process.pid}/status').read_text()
        report['runtime_configuration'] = report['daemon']['configuration']
        workers = {}
        for role, user, uid in [('observer', 'foundationA', 1100), ('test', 'foundationB', 1101)]:
            worker = own(shared.Actor(['runuser', '-u', user, '--', 'python3', str(HERE / 'actor.py'), SOCKET], evidence / (role + '.log')))
            identity = worker.read()
            assert type(identity['uid']) is int and identity['uid'] == uid
            registration = worker.request(op='register')
            assert registration['type'] == 2 and registration['signature'] == 's' and registration['body'][0].startswith(':')
            identity['unique'] = registration['body'][0]
            report['actors'][role] = identity
            report[role + '_registration'] = registration
            workers[role] = worker
        observer, test = workers['observer'], workers['test']
        acquired = call(observer, request('RequestName', 'su', [OBSERVER, 0]))
        assert exchange(acquired, request('RequestName', 'su', [OBSERVER, 0]))['body'] == [1]
        report['observer_ownership'] = acquired
        baseline = settled(settle())
        identity_binding(baseline, identities())
        for index, case in enumerate(WORKLOAD['cases']):
            identifier = case['id']
            report['outcomes'][identifier] = dict(status='running')
            report['execution_order'].append(identifier)
            details = dict(index=index, case=case, before=settle(baseline), identities_before=identities(), followups=[], effects=[])
            report['outcomes'][identifier]['evidence'] = details
            persist()
            try:
                identity_binding(settled(details['before']), details['identities_before'])
                invalid = {key: case[key] for key in ('member', 'signature', 'body', 'interface', 'path')}
                details['invalid'] = call(test, invalid)
                exchange(details['invalid'], invalid, case['error'])
                details['after_error'] = settle(baseline)
                details['identities_after'] = identities()
                identity_binding(settled(details['after_error']), details['identities_after'])
                start = time.monotonic()
                deadline = start + WORKLOAD['healthy_probe_ms'] / 1000
                probes = []
                for method in (request('GetNameOwner', 's', [OBSERVER]), request('GetId')):
                    remaining = deadline - time.monotonic()
                    assert remaining > 0
                    probes.append(call(observer, method, timeout=remaining))
                details['probe'] = dict(calls=probes, elapsed_ms=(time.monotonic() - start) * 1000)
                for step, method in enumerate(followup_plan(case)):
                    value = call(test, method)
                    details['followups'].append(value)
                    followup_reply(exchange(value, method), method, details['identities_after'], baseline)
                    if step == 0 and method['member'] in ('RequestName', 'AddMatch'):
                        details['effects'].append(dict(after_step=step, observation=settle()))
                details['retired'] = settle(baseline)
                validate_case(index, details, details['invalid']['request_serial'])
                report['outcomes'][identifier] = dict(status='passed', evidence=details)
            except Exception as error:
                report['outcomes'][identifier].update(status='failed', reason=repr(error))
                report['result'] = 'failed'
                persist()
                raise
            persist()
    finally:
        report['shutdown'], errors = [], []
        # Original daemon quit stops the application; it emits no FIXTURE reply.
        # Always attempt bounded EOF/group reaping, even if writing quit fails.
        for worker in channels[1:] + channels[:1]:
            if worker is daemon:
                try:
                    worker.process.stdin.write(b'quit\n')
                    worker.process.stdin.flush()
                except Exception as error:
                    errors.append(repr(error))
            try:
                row = worker.stop()
                row['pid_absent'] = not Path(f"/proc/{row['pid']}").exists()
                try:
                    os.killpg(row['pid'], 0)
                except ProcessLookupError:
                    row['group_absent'] = True
                else:
                    row['group_absent'] = False
                report['shutdown'].append(row)
            except Exception as error:
                errors.append(repr(error))
        by_pid = {row['pid']: row for row in report['shutdown']}
        report['shutdown'] = [by_pid[row['pid']] for row in report['owned'] if row['pid'] in by_pid]
        report['shutdown_errors'] = errors
        report['actor_pids_absent'] = {role: not Path(f"/proc/{row['pid']}").exists() for role, row in report['actors'].items()}
        report['socket_removed'] = not Path(SOCKET).exists() and not Path(SOCKET).is_symlink()
        persist()
    complete(report)
    report['result'] = 'passed_selected_scope'
    persist()
    print(json.dumps(dict(result=report['result'], counts=report['counts'], evidence=str(evidence), product_qualified=False, readiness='L0'), sort_keys=True))


if __name__ == '__main__':
    assert len(sys.argv) == 3
    main(*(Path(argument) for argument in sys.argv[1:]))
