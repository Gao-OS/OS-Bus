"""Narrow frozen-candidate quota qualification in a disposable Linux guest."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from actor import WORKLOAD, packet, resource
from channel import Actor, Channel

FIXTURES = Path(__file__).resolve().parent
RECIPIENTS = ('A1', 'A2', 'B1')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def external(pid):
    root = Path('/proc') / str(pid)
    targets = []
    for entry in (root / 'fd').iterdir():
        try:
            targets.append(os.readlink(entry))
        except FileNotFoundError:
            pass
    lines = (root / 'status').read_text().splitlines()
    values = {line.split(':', 1)[0]: line.split(':', 1)[1].split() for line in lines if ':' in line}
    return {'pid': int(values['Pid'][0]), 'uids': list(map(int, values['Uid'])),
            'gids': list(map(int, values['Gid'])), 'fds': len(targets),
            'memfds': sorted(x for x in targets if '/memfd:' in x), 'targets': sorted(targets)}


def identities(state, actors):
    assert len(state['peers']) == 5, 'wrong client count'
    assert len({a['pid'] for a in actors.values()}) == 5, 'clients are not independent processes'
    assert len({a['name'] for a in actors.values()}) == 5, 'clients are not independent connections'
    result = {}
    for role, actor in actors.items():
        row, = [p for p in state['peers'] if p['name'] == actor['name']]
        assert not row.get('departed') and row['negotiated'], 'untrusted or departed peer'
        credentials = row['credentials']
        assert credentials == {k: actor[k] for k in ('pid', 'uid', 'gid')}, 'trusted credentials mismatch'
        assert actor['uid'] == WORKLOAD['roles'][role], 'wrong workload UID'
        assert actor['external']['pid'] == actor['pid']
        assert actor['external']['uids'] == [actor['uid']] * 4, 'kernel UID mismatch'
        assert actor['external']['gids'] == [actor['gid']] * 4, 'kernel GID mismatch'
        result[role] = row['peer']
    return result


def assert_native(state):
    assert state['usage']['xml']['queues'] is None and state['usage']['xml']['limits'] is None, 'XML accounting changes oracle'
    for scope, changes in WORKLOAD['limits'].items():
        for key, expected in changes.items():
            assert state['usage']['limits'][scope][key] == expected, ('changed capacity', scope, key)
    assert state['pending'] == 0, 'failed candidate pending entry committed'
    assert all(not p.get('departed') for p in state['peers']), 'unexpected peer departure'


def assert_phase(state, active_roles, actors, baseline_fds, frozen=None):
    assert_native(state)
    global_counts = state['usage']['global']
    assert global_counts['egress_fds'] == len(active_roles), 'wrong global FD state'
    assert global_counts['ingress_fds'] == 0, 'source ingress FD reservation survived routing'
    assert state['usage']['uids']['1100']['egress_fds'] == sum(r.startswith('A') for r in active_roles), 'wrong UID1100 state'
    assert state['usage']['uids']['1101']['egress_fds'] == sum(r == 'B1' for r in active_roles), 'wrong UID1101 state'
    outputs = {}
    for role in active_roles:
        peer, = [p for p in state['peers'] if p['name'] == actors[role]['name']]
        out = peer['output']
        assert out and out['blocked'] and out['rights_sent'], 'actual partial writer absent'
        assert 0 < out['offset'] < out['bytes'] and peer['queue'] == 0, 'wrong queued writer shape'
        assert out['fds'] == 1 and state['usage']['peers'][peer['peer']]['egress_fds'] == 1
        expected_serial = next(r['serial'] for r in WORKLOAD['admissions'] if r['role'] == role)
        expected = packet(expected_serial, actors[role]['name'], WORKLOAD['accepted_payload_bytes'], actors['source']['name'])
        assert (out['serial'], out['sender'], out['type'], out['member']) == (expected_serial, actors['source']['name'], 'signal', 'Hold')
        assert out['bytes'] == len(expected) and out['sha256'] == hashlib.sha256(expected).hexdigest(), 'Peer encoded bytes mismatch'
        assert state['now_ms'] < out['deadline'], 'health/capacity evidence after expiry'
        counts = state['usage']['peers'][peer['peer']]
        assert counts['egress_messages'] == 1 and counts['egress_bytes'] == len(expected)
        if frozen:
            assert out == frozen[role], 'original writer changed during health'
        outputs[role] = out
    empty = dict.fromkeys(global_counts, 0)
    expected_global, expected_uids, expected_peers = empty.copy(), {}, {}
    for peer in state['peers']:
        role, = [role for role, actor in actors.items() if actor['name'] == peer['name']]
        counts = {**empty, 'connections': 1}
        if role in outputs:
            counts.update(egress_fds=1, egress_messages=1, egress_bytes=outputs[role]['bytes'])
        else:
            assert peer['output'] is None and peer['queue'] == 0, 'nonactive peer output leaked'
        expected_peers[peer['peer']] = counts
        uid_counts = expected_uids.setdefault(str(actors[role]['uid']), empty.copy())
        for key, value in counts.items():
            uid_counts[key] += value
            expected_global[key] += value
    assert global_counts == expected_global, 'global byte/message/transient credit mismatch'
    assert state['usage']['uids'] == expected_uids, 'UID byte/message/transient credit mismatch'
    assert state['usage']['peers'] == expected_peers, 'peer byte/message/transient credit mismatch'
    assert state['usage']['reservations'] == len(active_roles), 'hidden reservation leak'
    assert state['external']['fds'] == baseline_fds + 2 * len(state['peers']) + len(active_roles), 'phase daemon FD inventory mismatch'
    expected_memfds = sorted('/memfd:quota-%d (deleted)' % outputs[role]['serial'] for role in active_roles)
    assert state['external']['memfds'] == expected_memfds, 'phase accepted/rejected resource inventory mismatch'
    for scope, counts in [('global', global_counts)] + [('uid', c) for c in state['usage']['uids'].values()] + [('peer', c) for c in state['usage']['peers'].values()]:
        for metric, count in counts.items():
            if metric in state['usage']['limits'][scope]:
                assert 0 <= count <= state['usage']['limits'][scope][metric], 'finite cap exceeded'
    return outputs


def assert_denial_unchanged(before, after):
    assert before['usage'] == after['usage'], 'denial changed accounting'
    assert before['external'] == after['external'], 'denial retained or changed kernel resources'
    for key in ('names', 'matches', 'capabilities', 'pending', 'authorities'):
        assert before[key] == after[key], ('denial changed authority', key)
    def selected(state):
        return {peer['name']: {key: peer[key] for key in ('peer', 'name', 'credentials',
                 'negotiated', 'queue', 'buffer_bytes', 'output')} for peer in state['peers']}
    assert selected(before) == selected(after), 'denial changed existing writer/peer state'


def audit_trace(trace, warmups, active, denied, actors, peer_map):
    rows = [row for row in trace['rows'] if row['member'] == 'Hold']
    expected = [(peer_map[r['role']], actors['source']['name'], r['serial']) for r in active]
    warm_expected = [(r['peer'], r['sender'], r['serial']) for r in warmups]
    actual = [(r['target'], r['sender'], r['serial']) for r in rows]
    assert sorted(actual) == sorted(warm_expected + expected), 'missing, extra or denied admission'
    assert all(row['type'] == 'signal' for row in rows), 'denied call enqueued'
    # Existing collector does not hash hay bodies. Byte evidence lives in Peer/wire.
    assert len(trace['failures']) == len(denied), 'unexpected control/output enqueue rejection'
    for failure, attempt in zip(trace['failures'], denied):
        expected_bytes = len(packet(attempt['serial'], actors[attempt['role']]['name'], WORKLOAD['denied_payload_bytes'], actors['source']['name'], True))
        assert failure == {'target': peer_map[attempt['role']], 'bytes': expected_bytes,
                           'fds': 1, 'scope': attempt['scope'], 'metric': attempt['metric']}, 'wrong quota denial disposition'
    assert trace['peak_queue'] <= WORKLOAD['trace_queue_max'] and trace['seen'] <= WORKLOAD['trace_rows_max']


def assert_empty(state):
    assert_native(state)
    assert not state['peers'] and not state['usage']['peers'] and not state['usage']['uids']
    assert state['usage']['reservations'] == 0 and all(v == 0 for v in state['usage']['global'].values()), 'credits leaked'
    assert state['pending'] == 0 and state['matches'] == 0 and state['capabilities'] == 0, 'authority leaked'


def assert_denial_headroom(before, attempt, actors, peer_map):
    role = attempt['role']
    uid = str(actors[role]['uid'])
    size = len(packet(attempt['serial'], actors[role]['name'], WORKLOAD['denied_payload_bytes'], actors['source']['name'], True))
    for scope, counts in [('peer', before['usage']['peers'][peer_map[role]]),
                          ('uid', before['usage']['uids'][uid]), ('global', before['usage']['global'])]:
        limits = before['usage']['limits'][scope]
        assert counts['egress_bytes'] + size <= limits['egress_bytes'], 'byte limit confounds FD denial'
        assert counts['egress_messages'] + 1 <= limits['egress_messages'], 'message limit confounds FD denial'
        if scope == attempt['scope']:
            assert counts['egress_fds'] == limits['egress_fds'], 'selected FD limit not full'
        else:
            assert counts['egress_fds'] + 1 <= limits['egress_fds'], 'other FD limit confounds denial'


def assert_recovery(baseline, final, actor_baseline, actor_final):
    assert_empty(baseline)
    assert_empty(final)
    for key in ('authorities', 'names', 'matches', 'capabilities', 'usage', 'pending'):
        assert baseline[key] == final[key], ('baseline recovery mismatch', key)
    assert final['external']['fds'] == baseline['external']['fds'], 'daemon FD leak'
    assert final['external']['memfds'] == baseline['external']['memfds'] == [], 'daemon memfd leak'
    assert set(actor_baseline) == set(actor_final) == set(WORKLOAD['roles'])
    for role in actor_baseline:
        assert actor_final[role]['fds'] == actor_baseline[role]['fds'], ('actor FD leak', role)
        assert actor_final[role]['memfds'] == actor_baseline[role]['memfds'] == [], ('actor memfd leak', role)


def assert_report(report):
    assert report['candidate_hashes_after'] and report['helpers_hashes_after'], 'frozen inputs changed'
    assert report['counts'] == WORKLOAD['counts'], 'incomplete workload counts'
    assert len(report['cleanup']) == 6 and all(r['returncode'] == 0 and r['method'] == 'eof' for r in report['cleanup']), 'unsuccessful graceful shutdown'
    peer_map = identities(report['phases'][0], report['identities'])
    assert peer_map == report['peer_map']
    assert len(report['phases']) == len(report['attempts']) == 5 and len(report['trace']) == 6
    active, admitted, denied = [], [], []
    baseline_fds = report['baseline']['external']['fds']
    ordered = [WORKLOAD['admissions'][0], WORKLOAD['admissions'][1], WORKLOAD['denials'][0], WORKLOAD['admissions'][2], WORKLOAD['denials'][1]]
    for index, attempt in enumerate(ordered):
        actual = report['attempts'][index]
        assert all(actual[key] == value for key, value in attempt.items()), 'wrong attempted workload'
        if 'scope' in attempt:
            assert actual['error'] == 'org.freedesktop.DBus.Error.LimitsExceeded' and actual['reply_serial'] == attempt['serial']
            denied.append(attempt)
            assert_denial_headroom(report['phases'][index - 1], attempt, report['identities'], peer_map)
            assert_denial_unchanged(report['phases'][index - 1], report['phases'][index])
        else:
            active.append(attempt['role'])
            admitted.append(attempt)
        assert_phase(report['phases'][index], active, report['identities'], baseline_fds)
        assert report['phases'][index]['authorities'] == report['baseline']['authorities'], 'authority reset'
        assert len(report['phases'][index]['peers']) == 5, 'unexpected departure'
        audit_trace(report['trace'][index], report['warmups'], admitted, denied, report['identities'], peer_map)
    assert report['frozen'] == assert_phase(report['before_health'], RECIPIENTS, report['identities'], baseline_fds)
    assert_phase(report['after_health'], RECIPIENTS, report['identities'], baseline_fds, report['frozen'])
    assert len(report['after_health']['peers']) == 5 and report['after_health']['authorities'] == report['baseline']['authorities']
    audit_trace(report['trace'][-1], report['warmups'], admitted, denied, report['identities'], peer_map)
    audit_trace(report['final_trace'], report['warmups'], admitted, denied, report['identities'], peer_map)
    assert report['source_health']['latency_ms'] <= WORKLOAD['healthy_ms'] and report['source_health']['fds'] == 0
    assert report['observer_health']['latency_ms'] <= WORKLOAD['healthy_ms'] and report['observer_health']['fds'] == 0
    for key in ('source_health', 'observer_health', 'observer_recovery_health'):
        assert report[key]['sender'] == 'org.freedesktop.DBus' and report[key]['serial'] == report[key]['reply_serial']
        assert report[key]['fds'] == 0
    assert report['health_elapsed_ms'] <= WORKLOAD['healthy_ms'], 'absolute full-capacity health deadline'
    assert report['observer_recovery_health']['latency_ms'] <= WORKLOAD['healthy_ms']
    assert len(report['kills']) == len(report['expiries']) == 2
    assert [r['name'] for r in report['kills']] == [report['identities'][r]['name'] for r in ('source', 'A1')]
    assert [r['name'] for r in report['expiries']] == [report['identities'][r]['name'] for r in ('A2', 'B1')]
    for row in report['kills']:
        assert row['monitor'] == 'DOWN:killed' and row['kill_ms'] < row['guard_deadline']
        assert row['observed_ms'] == row['received_ms'] <= row['consumed_ms'], 'kill recorded/consumed timestamp mismatch'
        assert row['received_ms'] >= row['kill_ms'], 'kill DOWN predates kill'
        assert row['observed_ms'] <= row['kill_ms'] + WORKLOAD['cleanup_ms']
        assert row['guard_deadline'] == report['frozen']['A1']['deadline'], 'kill guard deadline changed'
    for row in report['expiries']:
        assert row['monitor'] == 'DOWN:normal'
        assert row['observed_ms'] == row['received_ms'] <= row['consumed_ms'], 'expiry recorded/consumed timestamp mismatch'
        assert row['deadline'] <= row['observed_ms'] <= row['deadline'] + WORKLOAD['cleanup_ms']
    for role, row in zip(('A2', 'B1'), report['expiries']):
        assert row['deadline'] == report['frozen'][role]['deadline'], 'expiry deadline changed'
    assert_phase(report['after_kills'], ('A2', 'B1'), report['identities'], baseline_fds, report['frozen'])
    assert len(report['after_kills']['peers']) == 3 and report['after_kills']['authorities'] == report['baseline']['authorities']
    assert report['after_kills']['now_ms'] <= min(r['kill_ms'] for r in report['kills']) + WORKLOAD['cleanup_ms'], 'killed authority cleanup deadline'
    assert set(report['partial']) == set(RECIPIENTS)
    for role, row in report['partial'].items():
        frozen = report['frozen'][role]
        assert row['partial'] and row['eof'] and row['fds'] == 1
        assert row['serial'] == frozen['serial'] and row['sender'] == frozen['sender']
        assert row['target'] == report['identities'][role]['name']
        assert row['wire_bytes'] == frozen['offset'] and row['encoded_bytes'] == frozen['bytes']
        assert row['encoded_sha256'] == frozen['sha256'] and row['resource'] == resource(frozen['serial']).decode()
        expected = packet(frozen['serial'], row['target'], WORKLOAD['accepted_payload_bytes'], frozen['sender'])
        assert row['prefix_sha256'] == hashlib.sha256(expected[:frozen['offset']]).hexdigest(), 'partial prefix hash mismatch'
        assert row['resource_target'] == '/memfd:quota-%d (deleted)' % frozen['serial']
        assert not row['after_close']['memfds'], 'recipient resource leaked after use'
    assert_recovery(report['baseline'], report['final'], report['actor_baseline'], report['actor_final'])
    watcher = report['watcher_shutdown']
    ready_watcher = report['ready']['watcher']
    assert ready_watcher['registered'] == ready_watcher['waiting'] == 0 and ready_watcher['rows'] == []
    assert watcher['event'] == 'watcher_stopped' and watcher['monitor'] == 'DOWN:normal'
    assert watcher['registered'] == 4 and watcher['waiting'] == 0 and len(watcher['rows']) == 4
    assert watcher['max_watches'] == 4 and watcher['max_queries'] == 32 and watcher['queries'] <= 32
    assert watcher['watcher'] == ready_watcher['watcher'] and watcher['clock'] == 'BEAM monotonic receipt of DOWN'
    assert len(report['watches']) == 4 and len({r['monitor_ref'] for r in watcher['rows']}) == 4
    watched = {r['name']: r for r in report['watches']}
    assert set(watched) == {report['identities'][r]['name'] for r in ('source', 'A1', 'A2', 'B1')}
    for row in report['kills'] + report['expiries']:
        down = row['down']
        registration = watched[row['name']]
        assert down in watcher['rows'], 'missing independent DOWN record'
        assert down['name'] == row['name'] and down['peer'] == row['peer'] == registration['peer']
        assert down['monitor_ref'] == registration['monitor_ref']
        assert down['received_ms'] == row['received_ms'] and down['reason'] == row['monitor'].split(':', 1)[1]
        assert down['registered_ms'] == registration['registered_ms'] <= report['phases'][0]['now_ms']
        assert down['registered_ms'] <= down['received_ms']


def main(candidate, evidence, helpers, collector):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-fd-quotas'
    manifest_path = candidate / 'candidate.json'
    assert sha(manifest_path) == WORKLOAD['candidate_manifest_sha256']
    manifest = json.loads(manifest_path.read_text())
    assert manifest['not_a_release'] is True and len(manifest['files']) == WORKLOAD['candidate_artifacts']
    def candidate_ok():
        return sha(manifest_path) == WORKLOAD['candidate_manifest_sha256'] and all(sha(candidate / p) == h for p, h in manifest['files'].items())
    assert candidate_ok()
    helper_hashes = {str(helpers / f): sha(helpers / f) for f in ('transport.py', 'channel.py')}
    helper_hashes[str(collector)] = sha(collector)
    report = {'result': 'running', 'not_a_release': True, 'workload': WORKLOAD,
              'manifest': manifest, 'helpers_before': helper_hashes, 'cleanup': [],
              'trace': [], 'phases': [], 'kills': [], 'expiries': [], 'partial': {}, 'watches': []}
    def save():
        (evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(FIXTURES / 'daemon.exs'), str(evidence / 'bus'), str(collector)]
    actors, daemon = {}, None
    started = time.monotonic()
    try:
        daemon = Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        ready = daemon.read()
        assert ready['config_file'] is None and ready['profile'] == 'system'
        assert ready['resource_limits'] == WORKLOAD['limits'] and ready['send_timeout_ms'] == WORKLOAD['writer_ms']
        report['ready'] = ready
        def sample(op='inspect'):
            state = daemon.write(op)
            state['external'] = external(int(state['pid']))
            return state
        for role, uid in WORKLOAD['roles'].items():
            cmd = ['python3', '-B', str(FIXTURES / 'actor.py'), str(evidence / 'bus'), role]
            if uid:
                cmd = ['runuser', '-u', 'foundationA' if uid == 1100 else 'foundationB', '--'] + cmd
            actor = Actor(cmd, evidence / ('actor-%s.log' % role))
            actors[role] = actor
            actor.identity = actor.finish()
        def connect_all():
            for actor in actors.values():
                actor.identity.update(actor.request(op='connect'))
                actor.identity['external'] = external(actor.identity['pid'])
            current = {role: a.identity.copy() for role, a in actors.items()}
            peer_map = identities(sample(), current)
            return current, peer_map
        warm_identities, warm_peers = connect_all()
        warmups = []
        for index, role in enumerate((*RECIPIENTS, 'observer')):
            serial = 901 + index
            actors[role].begin(op='warm', serial=serial, sender=actors['source'].identity['name'])
            actors['source'].request(op='send', serial=serial, target=actors[role].identity['name'])
            result = actors[role].finish()
            assert result['used'] and result['fds'] == 1
            warmups.append({'peer': warm_peers[role], 'sender': warm_identities['source']['name'], 'serial': serial})
        actors['source'].request(op='barrier')
        report['warm_trace'] = daemon.write('trace')
        audit_trace(report['warm_trace'], warmups, [], [], warm_identities, warm_peers)
        report['warmups'] = warmups
        for actor in actors.values():
            actor.request(op='close')
        report['baseline'] = sample('metrics')
        assert_empty(report['baseline'])
        report['actor_baseline'] = {role: external(a.identity['pid']) for role, a in actors.items()}
        current, peer_map = connect_all()
        baseline_fds = report['baseline']['external']['fds']
        report['identities'], report['peer_map'] = current, peer_map
        for role in ('source', *RECIPIENTS):
            report['watches'].append(daemon.write('watch ' + current[role]['name']))
        for role in RECIPIENTS:
            daemon.write('stall ' + current[role]['name'])
        admissions, denials, active = [], [], []
        for attempt in [WORKLOAD['admissions'][0], WORKLOAD['admissions'][1], WORKLOAD['denials'][0], WORKLOAD['admissions'][2], WORKLOAD['denials'][1]]:
            denied = 'scope' in attempt
            if denied:
                assert_denial_headroom(report['phases'][-1], attempt, current, peer_map)
            result = actors['source'].request(op='send', serial=attempt['serial'], target=current[attempt['role']]['name'], denied=denied)
            report.setdefault('attempts', []).append({**attempt, **result})
            actors['source'].request(op='barrier')
            if denied:
                denials.append(attempt)
            else:
                admissions.append(attempt)
                active.append(attempt['role'])
                daemon.write('blocked ' + current[attempt['role']]['name'])
            trace = daemon.write('trace')
            audit_trace(trace, warmups, admissions, denials, current, peer_map)
            report['trace'].append(trace)
            state = sample()
            assert_phase(state, active, current, baseline_fds)
            if denied:
                assert_denial_unchanged(report['phases'][-1], state)
            assert state['authorities'] == report['baseline']['authorities'], 'authority reset'
            assert len(state['peers']) == 5, 'unexpected departure'
            report['phases'].append(state)
            save()
        before = sample()
        frozen = assert_phase(before, RECIPIENTS, current, baseline_fds)
        report['before_health'], report['frozen'] = before, frozen
        health_started = time.monotonic()
        health_deadline = health_started + WORKLOAD['healthy_ms'] / 1000
        # Independent client processes issue concurrent real zero-FD diagnostics.
        actors['source'].begin(op='health')
        actors['observer'].begin(op='health')
        for role in ('source', 'observer'):
            reply = actors[role].read(timeout=max(health_deadline - time.monotonic(), .001))
            assert reply['ok'], reply
            report[role + '_health'] = reply['result']
        report['health_elapsed_ms'] = (time.monotonic() - health_started) * 1000
        assert report['health_elapsed_ms'] <= WORKLOAD['healthy_ms']
        after = sample()
        assert_phase(after, RECIPIENTS, current, baseline_fds, frozen)
        assert after['authorities'] == before['authorities'] and len(after['peers']) == 5
        report['after_health'] = after
        actors['source'].request(op='barrier')
        trace = daemon.write('trace')
        audit_trace(trace, warmups, admissions, denials, current, peer_map)
        report['trace'].append(trace)
        for role in ('source', 'A1'):
            report['kills'].append(daemon.write('kill %s %s' % (current[role]['name'], current['A1']['name'])))
            # A1 guard watch is deleted only by the second kill.
        actors['source'].request(op='eof')
        cleanup_deadline = min(row['kill_ms'] for row in report['kills']) + WORKLOAD['cleanup_ms']
        report['after_kills'] = sample('departed %s %s %d' % (current['source']['name'], current['A1']['name'], cleanup_deadline))
        assert_phase(report['after_kills'], ('A2', 'B1'), current, baseline_fds, frozen)
        assert len(report['after_kills']['peers']) == 3
        for role in ('A2', 'B1'):
            report['expiries'].append(daemon.write('expiry ' + current[role]['name']))
        for role in RECIPIENTS:
            report['partial'][role] = actors[role].request(op='partial', serial=frozen[role]['serial'], sender=current['source']['name'], offset=frozen[role]['offset'])
        report['observer_recovery_health'] = actors['observer'].request(op='health')
        for actor in actors.values():
            actor.request(op='close')
        report['final'] = sample('metrics')
        report['actor_final'] = {role: external(a.identity['pid']) for role, a in actors.items()}
        assert_recovery(report['baseline'], report['final'], report['actor_baseline'], report['actor_final'])
        report['final_trace'] = daemon.write('trace')
        audit_trace(report['final_trace'], warmups, admissions, denials, current, peer_map)
        report['counts'] = {**WORKLOAD['counts'], 'admitted': len(admissions), 'denied': len(denials),
                            'killed': len(report['kills']), 'expired': len(report['expiries']),
                            'attempted': len(report['attempts']), 'warmup_admissions': len(warmups)}
        report['result'] = 'passed_scoped_egress_fd_quotas'
    except Exception as error:
        report.update(result='failed', error=repr(error))
        raise
    finally:
        for actor in actors.values():
            report['cleanup'].append(actor.stop())
        if daemon:
            report['cleanup'].append(daemon.stop())
            for line in (evidence / 'daemon.log').read_text().splitlines():
                if line.startswith('FIXTURE '):
                    event = json.loads(line[len('FIXTURE '):])
                    if event.get('event') == 'watcher_stopped':
                        report['watcher_shutdown'] = event
        report['elapsed_seconds'] = time.monotonic() - started
        report['candidate_hashes_after'] = candidate_ok()
        report['helpers_hashes_after'] = all(sha(Path(p)) == h for p, h in helper_hashes.items())
        try:
            assert_report(report)
        except Exception as error:
            report.update(result='failed', completion_error=repr(error))
        save()
    assert report['result'] == 'passed_scoped_egress_fd_quotas', report.get('completion_error')
    print(json.dumps({'result': report['result'], 'counts': report['counts'], 'not_a_release': True}))


if __name__ == '__main__':
    main(*(Path(arg) for arg in sys.argv[1:]))
