"""Narrow frozen-candidate FD09 proof in a disposable Linux guest."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from actor import WORKLOAD, packet, payload, resource
from channel import Actor, Channel

FIXTURES = Path(__file__).resolve().parent
ROLES = ('source', 'observer', 'fast', 'slow')
METRICS = ('connections', 'authenticating', 'ingress_messages', 'ingress_bytes',
           'ingress_fds', 'egress_messages', 'egress_bytes', 'egress_fds',
           'frame_bytes', 'frame_fds', 'activation_messages', 'activation_bytes',
           'activation_fds')
AUTHORITIES = ('GaoBus.Supervisor', 'GaoBus.Ids', 'GaoBus.NameRegistry',
               'GaoBus.MatchRules', 'GaoBus.Policy', 'GaoBus.Policy.Capability',
               'GaoBus.Limits', 'GaoBus.Router', 'GaoBus.Listener')
BUS = 'org.freedesktop.DBus'


def digest(value):
    return hashlib.sha256(value).hexdigest()


def sha(path):
    return digest(path.read_bytes())


def memfd(serial):
    return '/memfd:fanout-%d (deleted)' % serial


def external(pid):
    root = Path('/proc') / str(pid)
    targets = []
    for entry in (root / 'fd').iterdir():
        try:
            targets.append(os.readlink(entry))
        except FileNotFoundError:
            pass
    values = {line.split(':', 1)[0]: line.split(':', 1)[1].split()
              for line in (root / 'status').read_text().splitlines() if ':' in line}
    return {'pid': int(values['Pid'][0]), 'uids': list(map(int, values['Uid'])),
            'gids': list(map(int, values['Gid'])), 'fds': len(targets),
            'memfds': sorted(x for x in targets if '/memfd:' in x), 'targets': sorted(targets)}


def identities(state, actors):
    assert set(actors) == set(ROLES) and len(state['peers']) == 4, 'wrong actor/peer set'
    assert len({a['pid'] for a in actors.values()}) == 4, 'clients share a process'
    assert len({a['name'] for a in actors.values()}) == 4, 'clients share a connection'
    mapping = {}
    for role, actor in actors.items():
        assert actor['uid'] == WORKLOAD['roles'][role], 'wrong role UID'
        assert actor['external']['pid'] == actor['pid'], 'stale actor PID'
        assert actor['external']['uids'] == [actor['uid']] * 4, 'kernel UID mismatch'
        assert actor['external']['gids'] == [actor['gid']] * 4, 'kernel GID mismatch'
        peer, = [p for p in state['peers'] if p['name'] == actor['name']]
        assert peer['negotiated'] and not peer.get('departed'), 'unnegotiated/departed actor'
        assert peer['credentials'] == {k: actor[k] for k in ('pid', 'uid', 'gid')}, 'trusted identity mismatch'
        mapping[role] = peer['peer']
    assert len(set(mapping.values())) == 4, 'duplicate Peer identity'
    return mapping


def assert_actor_fds(row, baseline, sockets=1, held=False):
    assert row['fds'] == baseline['fds'] + sockets + int(held), 'actor FD inventory mismatch'
    assert row['memfds'] == ([memfd(101)] if held else []), 'actor memfd inventory mismatch'


def assert_proc_identity(row, pid, uid, gid):
    assert row['pid'] == int(pid), 'external inventory belongs to another process'
    assert row['uids'] == [uid] * 4, 'external inventory UID mismatch'
    assert row['gids'] == [gid] * 4, 'external inventory GID mismatch'


def assert_inventory_identities(state, report):
    assert state['pid'] == report['ready']['pid'], 'snapshot belongs to another daemon'
    assert_proc_identity(state['external'], report['ready']['pid'], 0, 0)
    assert set(state['actors']) == set(ROLES)
    for role, row in state['actors'].items():
        actor = report['identities'][role]
        assert_proc_identity(row, actor['pid'], actor['uid'], actor['gid'])


def assert_state(state, present, pending, held, report, subscribed=True):
    baseline, actors = report['baseline'], report['identities']
    assert_inventory_identities(state, report)
    assert state['authorities'] == baseline['authorities'], 'authority restarted'
    assert set(state['authorities']) == set(AUTHORITIES), 'missing authority identity'
    assert state['usage']['xml']['queues'] is None and state['usage']['xml']['limits'] is None
    assert state['usage']['limits'] == baseline['usage']['limits'], 'capacity changed'
    for scope, limits in WORKLOAD['limits'].items():
        assert all(state['usage']['limits'][scope][key] == value for key, value in limits.items())
    assert set(state['usage']['global']) == set(METRICS), 'missing accounting metric'
    assert {p['name'] for p in state['peers']} == {actors[r]['name'] for r in present}
    assert len(state['peers']) == len(present), 'duplicate/stale Peer row'
    assert state['names'] == sorted([BUS] + [actors[r]['name'] for r in present]), 'name disposition mismatch'
    assert state['matches'] == (sum(r in ('fast', 'slow') for r in present) if subscribed else 0)
    assert state['pending'] == state['capabilities'] == 0, 'unexpected authority state'
    expected_global, expected_uids, expected_peers = dict.fromkeys(METRICS, 0), {}, {}
    for role in present:
        actor = actors[role]
        peer, = [p for p in state['peers'] if p['name'] == actor['name']]
        assert peer['peer'] == report['peer_map'][role] and not peer.get('departed')
        assert peer['credentials'] == {k: actor[k] for k in ('pid', 'uid', 'gid')} and peer['negotiated']
        assert peer['queue'] == peer['buffer_bytes'] == 0, 'queued/input work survived'
        counts = {**dict.fromkeys(METRICS, 0), 'connections': 1}
        if pending and role == 'slow':
            out = peer['output']
            assert out == report['frozen'], 'original slow writer changed'
            assert out['blocked'] and out['rights_sent'] and 0 < out['offset'] < out['bytes']
            assert state['now_ms'] < out['deadline'], 'phase after original writer deadline'
            counts.update(egress_messages=1, egress_fds=1, egress_bytes=out['bytes'])
        else:
            assert peer['output'] is None, 'unexpected output'
        expected_peers[peer['peer']] = counts
        uid = expected_uids.setdefault(str(actor['uid']), dict.fromkeys(METRICS, 0))
        for key, value in counts.items():
            expected_global[key] += value
            uid[key] += value
    assert state['usage']['global'] == expected_global, 'global accounting mismatch'
    assert state['usage']['uids'] == expected_uids, 'UID accounting mismatch'
    assert state['usage']['peers'] == expected_peers, 'Peer accounting mismatch'
    assert state['usage']['reservations'] == int(pending), 'reservation leak'
    assert state['external']['fds'] == baseline['external']['fds'] + 2 * len(present) + int(pending)
    assert state['external']['memfds'] == ([memfd(101)] if pending else []), 'daemon resource disposition mismatch'
    assert set(state['actors']) == set(ROLES)
    for role in ROLES:
        assert_actor_fds(state['actors'][role], report['actor_baseline'][role], held=held and role == 'fast')


def assert_resource(row, serial=101):
    assert row['fds'] == 1 and row['resource'] == resource(serial).decode()
    assert row['resource_sha256'] == digest(resource(serial)), 'resource data mismatch'
    assert row['resource_target'] == memfd(serial), 'wrong resource identity'


def assert_full(row, serial, sender, target=None):
    expected = packet(serial, target, WORKLOAD['accepted_payload_bytes'], sender)
    assert (row['serial'], row['sender'], row['target']) == (serial, sender, target)
    assert row['wire_bytes'] == row['encoded_bytes'] == len(expected), 'full-frame size mismatch'
    assert row['encoded_sha256'] == row['wire_sha256'] == digest(expected), 'full-frame data mismatch'
    body = (0).to_bytes(4, 'little') + WORKLOAD['accepted_payload_bytes'].to_bytes(4, 'little') + payload(serial, WORKLOAD['accepted_payload_bytes'])
    assert row['body_sha256'] == digest(body) and row['used'] is True, 'body not independently used'
    assert_resource(row, serial)


def assert_trace(trace, report, broadcast=True):
    expected = [(r['peer'], r['sender'], r['serial']) for r in report['warmups']]
    if broadcast:
        expected += [(report['peer_map'][r], report['identities']['source']['name'], 101) for r in ('fast', 'slow')]
    assert len(trace['rows']) == len(expected), 'extra/missing admission'
    assert sorted((r['target'], r['sender'], r['serial']) for r in trace['rows']) == sorted(expected), 'admission target/identity mismatch'
    assert all(r['member'] == 'Hold' and r['type'] == 'signal' for r in trace['rows'])
    assert trace['failures'] == [], 'unexpected enqueue rejection'
    assert trace['peak_queue'] <= WORKLOAD['trace_queue_max'] and trace['seen'] <= WORKLOAD['trace_rows_max']


def assert_health(row):
    assert 0 <= row['latency_ms'] <= WORKLOAD['healthy_ms'] and row['fds'] == 0
    assert row['serial'] == row['reply_serial'] and row['sender'] == BUS and row['strict_fence'] is True
    assert row.get('extra_messages', 0) == 0, 'unexpected fence messages'


def assert_report(report):
    assert report['candidate_hashes_after'] is True and report['helpers_hashes_after'] is True
    assert report['counts'] == WORKLOAD['counts'], 'incomplete workload'
    ready = report['ready']
    assert ready['config_file'] is None and ready['profile'] == 'system'
    assert ready['resource_limits'] == WORKLOAD['limits'] and ready['send_timeout_ms'] == WORKLOAD['writer_ms']
    assert identities(report['phases']['connected'], report['identities']) == report['peer_map']
    assert set(report['warm_identities']) == set(report['warm_peer_map']) == set(ROLES)
    assert len(set(report['warm_peer_map'].values())) == 4 and len({a['name'] for a in report['warm_identities'].values()}) == 4
    for role in ROLES:
        old, current = report['warm_identities'][role], report['identities'][role]
        assert all(old[k] == current[k] for k in ('pid', 'uid', 'gid')) and old['name'] != current['name']
        for inventory in ('actor_baseline', 'actor_final'):
            assert_proc_identity(report[inventory][role], current['pid'], current['uid'], current['gid'])
        assert report['actor_baseline'][role]['memfds'] == []
        assert_actor_fds(report['actor_final'][role], report['actor_baseline'][role], sockets=0)
    sender = report['identities']['source']['name']
    assert report['broadcast']['serial'] == 101 and report['broadcast']['target'] is None
    assert report['broadcast']['payload_bytes'] == WORKLOAD['accepted_payload_bytes'] and report['broadcast']['source_closed'] is True
    assert_actor_fds(report['broadcast']['after_send'], report['actor_baseline']['source'])
    assert set(report['subscriptions']) == {'fast', 'slow'}
    for role, row in report['subscriptions'].items():
        assert row == {'subscribed': True, 'rule': WORKLOAD['match_rule'], 'name': report['identities'][role]['name']}
    assert report['stall'] == {'event': 'stalled', 'name': report['identities']['slow']['name'],
                              'peer': report['peer_map']['slow'], 'sndbuf': WORKLOAD['sndbuf']}
    assert report['source_eof'] == {'eof': True}
    assert [(r['role'], r['serial']) for r in report['warmups']] == list(zip(('fast', 'slow', 'observer'), (901, 902, 903)))
    for warm in report['warmups']:
        role = warm['role']
        assert warm['peer'] == report['warm_peer_map'][role] and warm['sender'] == report['warm_identities']['source']['name']
        assert_full(warm['result'], warm['serial'], warm['sender'], report['warm_identities'][role]['name'])
        assert warm['result']['held_fd'] is False and warm['result']['after_close']['memfds'] == []
        assert_actor_fds(warm['result']['after_close'], report['actor_baseline'][role])
    for trace, broadcast in [(report['warm_trace'], False), (report['trace'], True), (report['final_trace'], True)]:
        assert_trace(trace, report, broadcast)
    expected = packet(101, None, WORKLOAD['accepted_payload_bytes'], sender)
    frozen = report['frozen']
    assert (frozen['serial'], frozen['sender'], frozen['type'], frozen['member']) == (101, sender, 'signal', 'Hold')
    assert frozen['bytes'] == len(expected) and frozen['sha256'] == digest(expected) and frozen['fds'] == 1
    phases = report['phases']
    assert set(phases) == {'connected', 'blocked', 'after_health', 'after_source', 'after_slow', 'released'}
    ordered = [report['baseline']['now_ms']] + [phases[key]['now_ms'] for key in
               ('connected', 'blocked', 'after_health', 'after_source', 'after_slow', 'released')] + [report['final']['now_ms']]
    assert all(before <= after for before, after in zip(ordered, ordered[1:])), 'inventory phases are out of order'
    assert_state(phases['connected'], ROLES, False, False, report, subscribed=False)
    for key in ('blocked', 'after_health'):
        assert_state(phases[key], ROLES, True, True, report)
    assert_state(phases['after_source'], ('fast', 'slow', 'observer'), True, True, report)
    assert_state(phases['after_slow'], ('fast', 'observer'), False, True, report)
    assert_state(phases['released'], ('fast', 'observer'), False, False, report)
    assert_full(report['full'], 101, sender)
    assert report['full']['held_fd'] is True and isinstance(report['full']['fd_identity'], str) and report['full']['fd_identity']
    assert report['full']['fd_identity'] == report['broadcast']['fd_identity'], 'full recipient received another resource object'
    assert_actor_fds(report['full']['after_receive'], report['actor_baseline']['fast'], held=True)
    assert len(report['retained']) == 2
    for stage, row in zip(('after_source', 'after_slow'), report['retained']):
        assert row['stage'] == stage and row['serial'] == 101 and row['held_fd'] is True
        assert row['fd_identity'] == report['full']['fd_identity'], 'retained FD replaced'
        assert_resource(row)
        assert_actor_fds(row['fd_state'], report['actor_baseline']['fast'], held=True)
    release = report['release']
    assert release['held_fd'] is False and release['fd_identity'] == report['full']['fd_identity']
    assert_actor_fds(release['fd_state'], report['actor_baseline']['fast'])
    partial = report['partial']
    assert (partial['serial'], partial['sender'], partial['target']) == (101, sender, None)
    assert partial['partial'] is True and partial['eof'] is True and partial['wire_bytes'] == frozen['offset']
    header_size = int.from_bytes(expected[12:16], 'little')
    body_at = 16 + header_size + (-header_size % 8)
    assert body_at + 8 < partial['wire_bytes'] < len(expected), 'not an incomplete body-bearing prefix'
    assert partial['encoded_bytes'] == len(expected) and partial['encoded_sha256'] == digest(expected)
    assert partial['prefix_sha256'] == digest(expected[:frozen['offset']])
    assert_resource(partial)
    assert partial['fd_identity'] == report['broadcast']['fd_identity'], 'slow recipient received another resource object'
    assert_actor_fds(partial['after_close'], report['actor_baseline']['slow'])
    for key in ('source_health', 'observer_health', 'observer_recovery_health'):
        assert_health(report[key])
    assert 0 <= report['health_elapsed_ms'] <= WORKLOAD['healthy_ms']
    assert set(report['final_fences']) == {'fast', 'observer'}
    for row in report['final_fences'].values():
        assert_health(row)
    assert len(report['kills']) == len(report['watches']) == 2
    assert len({r['monitor_ref'] for r in report['watches']}) == 2
    watched = {r['name']: r for r in report['watches']}
    assert set(watched) == {report['identities'][r]['name'] for r in ('source', 'slow')}
    for role, phase, previous, kill in zip(('source', 'slow'), ('after_source', 'after_slow'), ('after_health', 'after_source'), report['kills']):
        assert kill['name'] == report['identities'][role]['name'] and kill['peer'] == report['peer_map'][role]
        assert kill['monitor'] == 'DOWN:killed' and kill['guard_deadline'] == frozen['deadline']
        assert phases[previous]['now_ms'] <= kill['kill_ms'] < frozen['deadline']
        assert kill['kill_ms'] <= kill['received_ms'] == kill['observed_ms'] <= kill['consumed_ms']
        assert kill['received_ms'] <= kill['kill_ms'] + WORKLOAD['cleanup_ms']
        assert kill['consumed_ms'] <= phases[phase]['now_ms'] <= kill['kill_ms'] + WORKLOAD['cleanup_ms']
        registration = watched[kill['name']]
        assert set(registration) == {'event', 'name', 'peer', 'monitor_ref', 'registered_ms'}
        assert registration['event'] == 'watch'
        assert registration['peer'] == kill['peer'] and registration['registered_ms'] <= phases['blocked']['now_ms']
        assert registration['registered_ms'] <= kill['kill_ms'], 'monitor registered after kill'
        assert kill['down'] == {
            'name': registration['name'], 'peer': registration['peer'],
            'monitor_ref': registration['monitor_ref'], 'registered_ms': registration['registered_ms'],
            'reason': 'killed', 'received_ms': kill['received_ms']}
    watcher, ready_watcher = report['watcher_shutdown'], ready['watcher']
    assert ready_watcher['registered'] == ready_watcher['waiting'] == 0 and ready_watcher['rows'] == []
    assert watcher['event'] == 'watcher_stopped' and watcher['monitor'] == 'DOWN:normal'
    assert watcher['watcher'] == ready_watcher['watcher'] and watcher['registered'] == 2 and watcher['waiting'] == 0
    assert watcher['max_watches'] == 4 and watcher['max_queries'] == 32 and watcher['queries'] <= 32
    assert watcher['clock'] == 'BEAM monotonic receipt of DOWN'
    assert sorted(watcher['rows'], key=lambda r: r['name']) == sorted((k['down'] for k in report['kills']), key=lambda r: r['name'])
    assert report['collector_shutdown'] == {'event': 'collector_stopped', 'monitor': 'DOWN:normal'}
    baseline, final = report['baseline'], report['final']
    for state in (baseline, final):
        assert_inventory_identities(state, report)
        assert state['peers'] == [] and state['usage']['peers'] == state['usage']['uids'] == {}
        assert state['usage']['reservations'] == 0 and state['usage']['global'] == dict.fromkeys(METRICS, 0)
        assert state['names'] == [BUS] and state['matches'] == state['capabilities'] == state['pending'] == 0
        assert state['external']['memfds'] == []
    for key in ('authorities', 'usage', 'names', 'matches', 'capabilities', 'pending'):
        assert baseline[key] == final[key], 'warmed authority/budget mismatch'
    assert final['external']['fds'] == baseline['external']['fds'], 'daemon FD leak'
    cleanup = report['cleanup']
    assert len(cleanup) == 5 and {r['role'] for r in cleanup} == set((*ROLES, 'daemon'))
    assert all(r['method'] == 'eof' and r['returncode'] == 0 for r in cleanup), 'owned child did not exit normally'


def main(candidate, evidence, helpers, quota_dir, collector):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-fd-quotas'
    manifest_path = candidate / 'candidate.json'
    assert sha(manifest_path) == WORKLOAD['candidate_manifest_sha256']
    manifest = json.loads(manifest_path.read_text())
    assert manifest['not_a_release'] is True and len(manifest['files']) == WORKLOAD['candidate_artifacts']
    def candidate_ok():
        return sha(manifest_path) == WORKLOAD['candidate_manifest_sha256'] and all(sha(candidate / p) == h for p, h in manifest['files'].items())
    assert candidate_ok()
    immutable = [helpers / 'transport.py', helpers / 'channel.py', collector,
                 quota_dir / 'daemon.exs', quota_dir / 'actor.py', quota_dir / 'workload.json']
    immutable += [p for p in FIXTURES.iterdir() if p.is_file()]
    helper_hashes = {str(p): sha(p) for p in immutable}
    report = {'result': 'running', 'not_a_release': True, 'workload': WORKLOAD, 'manifest': manifest,
              'helpers_before': helper_hashes, 'cleanup': [], 'warmups': [], 'kills': [],
              'watches': [], 'retained': [], 'phases': {}}
    def save():
        (evidence / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    command = ['elixir', '--erl', '+S 2:2']
    for path in sorted((candidate / 'lib').glob('*/ebin')):
        command += ['-pa', str(path)]
    command += [str(quota_dir / 'daemon.exs'), str(evidence / 'bus'), str(collector)]
    report['commands'] = [command]
    actors, daemon = {}, None
    started = time.monotonic()
    try:
        daemon = Channel(command, evidence / 'daemon.log', 'FIXTURE ')
        report['ready'] = daemon.read()
        for role in ROLES:
            uid = WORKLOAD['roles'][role]
            cmd = ['python3', '-B', str(FIXTURES / 'actor.py'), str(evidence / 'bus'), role, str(quota_dir)]
            if uid:
                cmd = ['runuser', '-u', 'foundationA' if uid == 1100 else 'foundationB', '--'] + cmd
            report['commands'].append(cmd)
            actor = Actor(cmd, evidence / ('actor-%s.log' % role))
            actors[role] = actor
            actor.identity = actor.finish()
        def sample(op='inspect'):
            state = daemon.write(op)
            state['external'] = external(int(state['pid']))
            state['actors'] = {role: external(a.identity['pid']) for role, a in actors.items()}
            return state
        def connect_all():
            for actor in actors.values():
                actor.identity.update(actor.request(op='connect'))
                actor.identity['external'] = external(actor.identity['pid'])
            current = {role: a.identity.copy() for role, a in actors.items()}
            return current, identities(sample(), current)
        warm_ids, warm_peers = connect_all()
        report['warm_identities'], report['warm_peer_map'] = warm_ids, warm_peers
        for role, serial in zip(('fast', 'slow', 'observer'), (901, 902, 903)):
            actors[role].begin(op='warm', serial=serial, sender=warm_ids['source']['name'])
            actors['source'].request(op='send', serial=serial, target=warm_ids[role]['name'])
            result = actors[role].finish()
            report['warmups'].append({'role': role, 'serial': serial, 'sender': warm_ids['source']['name'], 'peer': warm_peers[role], 'result': result})
        actors['source'].request(op='barrier')
        report['warm_trace'] = daemon.write('trace')
        for actor in actors.values():
            actor.request(op='close')
        report['baseline'] = sample('metrics')
        report['actor_baseline'] = report['baseline']['actors']
        current, peer_map = connect_all()
        report['identities'], report['peer_map'] = current, peer_map
        report['phases']['connected'] = sample()
        report['subscriptions'] = {role: actors[role].request(op='subscribe') for role in ('fast', 'slow')}
        for role in ('source', 'slow'):
            report['watches'].append(daemon.write('watch ' + current[role]['name']))
        report['stall'] = daemon.write('stall ' + current['slow']['name'])
        actors['fast'].begin(op='receive_hold', serial=101, sender=current['source']['name'])
        report['broadcast'] = actors['source'].request(op='send', serial=101)
        actors['source'].request(op='barrier')
        report['full'] = actors['fast'].finish()
        blocked = daemon.write('blocked ' + current['slow']['name'])
        report['frozen'] = blocked['row']['output']
        report['trace'] = daemon.write('trace')
        report['phases']['blocked'] = sample()
        assert_state(report['phases']['blocked'], ROLES, True, True, report)
        save()
        health_started = time.monotonic()
        health_deadline = health_started + WORKLOAD['healthy_ms'] / 1000
        actors['source'].begin(op='health')
        actors['observer'].begin(op='health')
        for role in ('source', 'observer'):
            reply = actors[role].read(timeout=max(health_deadline - time.monotonic(), .001))
            assert reply['ok'], reply
            report[role + '_health'] = reply['result']
        report['health_elapsed_ms'] = (time.monotonic() - health_started) * 1000
        assert report['health_elapsed_ms'] <= WORKLOAD['healthy_ms']
        report['phases']['after_health'] = sample()
        assert_state(report['phases']['after_health'], ROLES, True, True, report)
        for role, present, pending, stage in [('source', ('fast', 'slow', 'observer'), True, 'after_source'),
                                               ('slow', ('fast', 'observer'), False, 'after_slow')]:
            cleanup_started = time.monotonic()
            kill = daemon.write('kill %s %s' % (current[role]['name'], current['slow']['name']))
            report['kills'].append(kill)
            while True:
                state = sample()
                try:
                    assert_state(state, present, pending, True, report)
                except AssertionError:
                    assert state['now_ms'] <= kill['kill_ms'] + WORKLOAD['cleanup_ms'] and time.monotonic() - cleanup_started <= WORKLOAD['cleanup_ms'] / 1000, 'exact killed-peer cleanup deadline'
                    continue
                assert state['now_ms'] <= kill['kill_ms'] + WORKLOAD['cleanup_ms'] and time.monotonic() - cleanup_started <= WORKLOAD['cleanup_ms'] / 1000
                report['phases'][stage] = state
                break
            report['retained'].append(actors['fast'].request(op='verify_held', stage=stage))
            if role == 'source':
                report['source_eof'] = actors['source'].request(op='eof')
            save()
        report['partial'] = actors['slow'].request(op='partial', serial=101, sender=current['source']['name'], offset=report['frozen']['offset'])
        report['observer_recovery_health'] = actors['observer'].request(op='health')
        report['release'] = actors['fast'].request(op='release_held')
        report['phases']['released'] = sample()
        report['final_fences'] = {role: actors[role].request(op='barrier') for role in ('fast', 'observer')}
        for actor in actors.values():
            actor.request(op='close')
        report['final'] = sample('metrics')
        report['actor_final'] = report['final']['actors']
        report['final_trace'] = daemon.write('trace')
        report['counts'] = {'warmup': len(report['warmups']), 'broadcast': 1, 'admitted': len(report['final_trace']['rows']) - len(report['warmups']),
                            'full': 1, 'partial': 1, 'killed': len(report['kills']), 'retained_reads': len(report['retained']), 'health': 3}
        report['result'] = 'passed_scoped_fd_fanout'
    except Exception as error:
        report.update(result='failed', error=repr(error))
    finally:
        for role, actor in actors.items():
            try:
                report['cleanup'].append({'role': role, **actor.stop()})
            except Exception as error:
                report['cleanup'].append({'role': role, 'error': repr(error)})
        if daemon:
            try:
                report['cleanup'].append({'role': 'daemon', **daemon.stop()})
                for line in (evidence / 'daemon.log').read_text().splitlines():
                    if line.startswith('FIXTURE '):
                        event = json.loads(line[len('FIXTURE '):])
                        if event.get('event') == 'watcher_stopped':
                            report['watcher_shutdown'] = event
                        elif event.get('event') == 'collector_stopped':
                            report['collector_shutdown'] = event
            except Exception as error:
                report['cleanup'].append({'role': 'daemon', 'error': repr(error)})
        report['elapsed_seconds'] = time.monotonic() - started
        try:
            report['candidate_hashes_after'] = candidate_ok()
            report['helpers_hashes_after'] = all(sha(Path(p)) == h for p, h in helper_hashes.items())
        except Exception as error:
            report.update(candidate_hashes_after=False, helpers_hashes_after=False, integrity_error=repr(error))
        try:
            assert_report(report)
        except Exception as error:
            report.update(result='failed', completion_error=repr(error))
        save()
    assert report['result'] == 'passed_scoped_fd_fanout', report.get('completion_error', report.get('error'))
    print(json.dumps({'result': report['result'], 'counts': report['counts'], 'not_a_release': True}))


if __name__ == '__main__':
    main(*(Path(arg) for arg in sys.argv[1:]))
