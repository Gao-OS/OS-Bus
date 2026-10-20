"""Pure saved-data contract for one valid incomplete-frame Peer death."""
import errno
import stat
import struct

from actor import BUS, WORKLOAD, digest, packet, resource
from transport import call, string

ROLES = ('source', 'observer')
METRICS = ('connections', 'authenticating', 'ingress_messages', 'ingress_bytes',
           'ingress_fds', 'egress_messages', 'egress_bytes', 'egress_fds',
           'frame_bytes', 'frame_fds', 'activation_messages', 'activation_bytes', 'activation_fds')
AUTHORITIES = ('GaoBus.Supervisor', 'GaoBus.Ids', 'GaoBus.NameRegistry', 'GaoBus.MatchRules',
               'GaoBus.Policy', 'GaoBus.Policy.Capability', 'GaoBus.Limits', 'GaoBus.Router', 'GaoBus.Listener')
PASS = 'passed_scoped_sec17_frame_cleanup'


def assert_resource(row, serial):
    assert set(row) == {'dev', 'ino', 'mode', 'size', 'target', 'sha256'}
    assert stat.S_ISREG(row['mode']) and row['ino'] > 0
    assert row['size'] == len(resource(serial)) and row['sha256'] == digest(resource(serial))
    assert row['target'] == '/memfd:sec17-frame-%d (deleted)' % serial


def assert_sent(row, target, serial, partial):
    raw = packet(serial, target)
    body, actual_serial, header = struct.unpack_from('<III', raw, 4)
    body_at = 16 + header + (-header % 8)
    assert body == 4 and actual_serial == serial and raw[body_at:] == b'\0' * 4
    sent = raw[:-1] if partial else raw
    assert len(sent) == body_at + (3 if partial else 4)
    assert row['serial'] == serial and row['target'] == target and row['rights'] == 1
    assert row['packet_hex'] == raw.hex() and row['packet_sha256'] == digest(raw)
    assert row['sent_hex'] == sent.hex() and row['sent_sha256'] == digest(sent) and row['sent_bytes'] == len(sent)
    assert row['suffix_bytes'] == int(partial) and row['suffix_sent'] is False and row['source_closed'] is True
    assert row['fd_state']['memfds'] == []
    assert_resource(row['resource'], serial)


def assert_identity(row, pid, uid, gid):
    assert row['pid'] == int(pid) and row['uids'] == [uid] * 4 and row['gids'] == [gid] * 4
    assert row['fds'] == len(row['targets'])
    assert row['memfds'] == sorted(x for x in row['targets'] if '/memfd:' in x)


def assert_state(state, present, holding, report):
    baseline, actors = report['baseline'], report['identities']
    assert state['event'] == 'snapshot' and state['pid'] == report['ready']['pid']
    assert_identity(state['external'], state['pid'], 0, 0)
    assert set(state['actors']) == set(ROLES)
    for role in ROLES:
        actor = actors[role]
        assert actor['role'] == role and actor['uid'] == WORKLOAD['roles'][role] and actor['gid'] == actor['uid']
        assert_identity(state['actors'][role], actor['pid'], actor['uid'], actor['gid'])
        assert state['actors'][role]['fds'] == baseline['actors'][role]['fds'] + int(bool(present))
        assert state['actors'][role]['memfds'] == [] and state['actors'][role]['resources'] == []
    assert len({a['pid'] for a in actors.values()}) == len({a['name'] for a in actors.values()}) == 2
    assert len(set(report['peer_map'].values())) == 2
    assert set(state['authorities']) == set(AUTHORITIES) and state['authorities'] == baseline['authorities']
    assert state['usage']['limits'] == baseline['usage']['limits']
    for scope, limits in WORKLOAD['limits'].items():
        assert all(state['usage']['limits'][scope][key] == value for key, value in limits.items())
    assert state['usage']['xml']['limits'] is None and state['usage']['xml']['queues'] is None
    assert state['names'] == sorted([BUS] + [actors[r]['name'] for r in present])
    assert state['matches'] == state['capabilities'] == state['pending'] == state['usage']['reservations'] == 0
    assert len(state['peers']) == len(present)
    assert {p['name'] for p in state['peers']} == {actors[r]['name'] for r in present}
    global_counts, uids, peers = dict.fromkeys(METRICS, 0), {}, {}
    for role in present:
        actor = actors[role]
        peer, = [p for p in state['peers'] if p['name'] == actor['name']]
        assert peer['peer'] == report['peer_map'][role] and peer['negotiated'] is True
        assert peer['credentials'] == {k: actor[k] for k in ('pid', 'uid', 'gid')}
        assert peer['queue'] == 0 and peer['output'] is None and peer['frame_timeout_ms'] == WORKLOAD['frame_ms']
        counts = {**dict.fromkeys(METRICS, 0), 'connections': 1}
        if holding and role == 'source':
            size = report['prefix']['sent_bytes']
            assert peer['buffer_bytes'] == size > 0 and peer['incoming_fds'] == 1
            assert isinstance(peer['frame_deadline'], int) and state['now_ms'] < peer['frame_deadline']
            counts.update(frame_bytes=size, frame_fds=1)
        else:
            assert peer['buffer_bytes'] == peer['incoming_fds'] == 0 and peer['frame_deadline'] is None
        peers[peer['peer']] = counts
        uids[str(actor['uid'])] = counts.copy()
        for key, value in counts.items():
            global_counts[key] += value
    assert state['usage']['global'] == global_counts
    assert state['usage']['uids'] == uids and state['usage']['peers'] == peers
    external = state['external']
    assert external['fds'] == baseline['external']['fds'] + 2 * len(present) + int(holding)
    if holding:
        fd, = external['resources']
        assert fd == {k: report['prefix']['resource'][k] for k in ('dev', 'ino', 'mode', 'size', 'target')}
        assert external['memfds'] == [fd['target']]
    else:
        assert external['memfds'] == [] and external['resources'] == []
    if not present:
        assert external == baseline['external'] and state['actors'] == baseline['actors']


def assert_report(report):
    assert report['schema'] == 1 and report['requirement'] == 'SEC-17' and report['subcase'] == 'valid-incomplete-frame-peer-death'
    assert report['result'] == PASS and report['workload'] == WORKLOAD and report['not_a_release'] is True
    assert report['counts'] == WORKLOAD['counts']
    assert report['candidate_hashes_after'] and report['helpers_before'] == report['helpers_after'] and report['helpers_before']
    assert report['ready']['profile'] == 'system' and report['ready']['config_file'] is None
    assert report['ready']['resource_limits'] == WORKLOAD['limits'] and report['ready']['send_timeout_ms'] == WORKLOAD['writer_ms']
    baseline = report['baseline']
    assert baseline['peers'] == [] and baseline['names'] == [BUS]
    assert baseline['matches'] == baseline['capabilities'] == baseline['pending'] == baseline['usage']['reservations'] == 0
    assert baseline['usage']['global'] == dict.fromkeys(METRICS, 0)
    assert baseline['usage']['uids'] == baseline['usage']['peers'] == {}
    assert baseline['external']['memfds'] == [] and baseline['external']['resources'] == []
    for row in baseline['actors'].values():
        assert row['memfds'] == [] and row['resources'] == []
    assert_sent(report['warm_send'], report['warm_identities']['observer']['name'], WORKLOAD['warmup_serial'], False)
    received = report['warm_receive']
    assert received['type'] == 4 and received['serial'] == WORKLOAD['warmup_serial'] and received['rights'] == 1
    assert received['fields'] == {'1': '/foundation', '2': 'org.foundation.Transport', '3': 'Resource',
                                  '6': report['warm_identities']['observer']['name'], '7': report['warm_identities']['source']['name'], '8': 'h', '9': 1}
    assert received['body_hex'] == '00000000' and received['resource'] == report['warm_send']['resource']
    assert report['warm_send']['fd_state']['memfds'] == received['fd_state']['memfds'] == []
    for phase, present, holding in [('connected', ROLES, False), ('held', ROLES, True),
                                     ('reclaimed', ('observer',), False), ('after_health', ('observer',), False), ('final', (), False)]:
        state = report['phases'][phase]
        assert_state(state, present, holding, report)
        attempts = report['attempts'][phase]
        assert attempts and attempts[-1] == state
    assert_sent(report['prefix'], report['identities']['observer']['name'], WORKLOAD['serial'], True)
    source_name = report['identities']['source']['name']
    source_peer = report['peer_map']['source']
    watch, guard, kill = report['watch'], report['frame_guard'], report['kill']
    held_peer, = [p for p in report['phases']['held']['peers'] if p['name'] == source_name]
    assert watch['event'] == 'watch' and watch['name'] == source_name and watch['peer'] == source_peer
    assert guard['event'] == 'frame' and guard['row'] == held_peer
    assert kill['event'] == 'killed' and kill['name'] == source_name and kill['peer'] == source_peer
    assert kill['monitor'] == 'DOWN:killed' and kill['guard_deadline'] == held_peer['frame_deadline']
    down = kill['down']
    assert set(down) == {'name', 'peer', 'monitor_ref', 'reason', 'registered_ms', 'received_ms'}
    assert down == dict(name=source_name, peer=source_peer, monitor_ref=watch['monitor_ref'], reason='killed',
                        registered_ms=watch['registered_ms'], received_ms=kill['received_ms'])
    assert watch['registered_ms'] <= report['phases']['held']['now_ms'] <= guard['now_ms'] <= kill['kill_ms']
    assert kill['kill_ms'] <= kill['observed_ms'] == kill['received_ms'] <= kill['consumed_ms'] <= report['phases']['reclaimed']['now_ms']
    assert kill['consumed_ms'] < kill['guard_deadline'] and report['phases']['reclaimed']['now_ms'] <= kill['kill_ms'] + WORKLOAD['cleanup_ms']
    assert 0 <= report['cleanup_elapsed_ms'] <= WORKLOAD['cleanup_ms']
    health = report['health']
    observer = report['identities']['observer']['name']
    assert health['name'] == health['owner'] == observer and health['serial'] == WORKLOAD['health_serial']
    assert health['sent_hex'] == call('GetNameOwner', WORKLOAD['health_serial'], 's', string(observer)).hex()
    assert health['reply_type'] == 2 and health['rights'] == 0 and health['body_hex'] == string(observer).hex()
    assert health['fields'].get('5') == WORKLOAD['health_serial'] and health['fields'].get('6') == observer
    assert health['fields'].get('7') == BUS and health['fields'].get('8') == 's' and health['fields'].get('9', 0) == 0
    assert set(health['fields']) <= {'5', '6', '7', '8', '9'} and 0 <= health['latency_ms'] <= WORKLOAD['healthy_ms']
    quiescence = health['quiescence']
    assert quiescence['errno'] in (errno.EAGAIN, errno.EWOULDBLOCK)
    assert quiescence == dict(result='would_block', errno=quiescence['errno'], nonblocking=True,
                              recv_calls=1, extra_bytes=0, extra_rights=0, flags=0, eof=False)
    assert 0 <= report['health_elapsed_ms'] <= WORKLOAD['healthy_ms']
    assert report['source_eof'] == dict(eof=True, suffix_sent=False)
    assert report['phase_order'] == ['warmup', 'baseline', 'connected', 'watch', 'prefix', 'held', 'frame_guard',
                                     'kill', 'reclaimed', 'health', 'after_health', 'source_eof', 'close', 'final']
    assert 0 <= report['final_cleanup_elapsed_ms'] <= WORKLOAD['cleanup_ms']
    assert set(report['actor_final']) == set(ROLES)
    for role in ROLES:
        assert report['actor_final'][role] == {k: baseline['actors'][role][k] for k in ('fds', 'memfds')}
    assert report['watcher_shutdown']['event'] == 'watcher_stopped' and report['watcher_shutdown']['monitor'] == 'DOWN:normal'
    assert report['watcher_shutdown']['rows'] == [down] and report['watcher_shutdown']['registered'] == 1 and report['watcher_shutdown']['waiting'] == 0
    assert report['collector_shutdown'] == dict(event='collector_stopped', monitor='DOWN:normal')
    assert sorted(x['role'] for x in report['cleanup']) == ['daemon', 'observer', 'source']
    assert all(x['method'] == 'eof' and x['returncode'] == 0 for x in report['cleanup'])
