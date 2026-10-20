"""Pure synthetic evidence mutations; no daemon, client, descriptors or processes."""
import copy
import stat
import unittest

from actor import BUS, WORKLOAD, digest, packet, resource
from contract import AUTHORITIES, METRICS, PASS, assert_report
from transport import call, string


def valid_evidence():
    identities = {role: dict(role=role, pid=201 + index, uid=uid, gid=uid, name=':1.%d' % (index + 3))
                  for index, (role, uid) in enumerate(WORKLOAD['roles'].items())}
    warm = copy.deepcopy(identities)
    warm['source']['name'], warm['observer']['name'] = ':1.1', ':1.2'
    mapping = dict(source='<0.10.0>', observer='<0.11.0>')
    authorities = {name: '<0.%d.0>' % (i + 20) for i, name in enumerate(AUTHORITIES)}

    def inventory(pid, uid, targets, resources=None):
        return dict(pid=pid, uids=[uid] * 4, gids=[uid] * 4, fds=len(targets),
                    targets=sorted(targets), memfds=sorted(t for t in targets if '/memfd:' in t),
                    resources=resources or [])

    def sent(serial, target, partial):
        raw = packet(serial, target)
        prefix = raw[:-1] if partial else raw
        return dict(serial=serial, target=target, packet_hex=raw.hex(), packet_sha256=digest(raw),
                    sent_hex=prefix.hex(), sent_sha256=digest(prefix), sent_bytes=len(prefix), rights=1,
                    suffix_bytes=int(partial), suffix_sent=False, source_closed=True,
                    resource=dict(dev=1, ino=serial + 1000, mode=stat.S_IFREG | 0o777, size=len(resource(serial)),
                                  target='/memfd:sec17-frame-%d (deleted)' % serial, sha256=digest(resource(serial))),
                    fd_state=dict(fds=4, memfds=[]))

    prefix = sent(WORKLOAD['serial'], identities['observer']['name'], True)

    def state(present, held, now):
        counts, uids, peers, rows = dict.fromkeys(METRICS, 0), {}, {}, []
        for role in present:
            actor = identities[role]
            holding = held and role == 'source'
            usage = {**dict.fromkeys(METRICS, 0), 'connections': 1}
            if holding:
                usage.update(frame_bytes=prefix['sent_bytes'], frame_fds=1)
            peers[mapping[role]] = usage
            uids[str(actor['uid'])] = usage.copy()
            for key, value in usage.items():
                counts[key] += value
            rows.append(dict(peer=mapping[role], name=actor['name'],
                             credentials={k: actor[k] for k in ('pid', 'uid', 'gid')}, negotiated=True,
                             mailbox=0, queue=0, output=None, buffer_bytes=prefix['sent_bytes'] if holding else 0,
                             incoming_fds=int(holding), frame_deadline=5030 if holding else None, frame_timeout_ms=5000))
        targets = ['base-%d' % i for i in range(20)] + ['socket:%s:%d' % (r, i) for r in present for i in range(2)]
        resources = []
        if held:
            targets.append(prefix['resource']['target'])
            resources = [{k: prefix['resource'][k] for k in ('dev', 'ino', 'mode', 'size', 'target')}]
        return dict(event='snapshot', pid='100', now_ms=now, peers=rows, authorities=authorities.copy(),
                    names=sorted([BUS] + [identities[r]['name'] for r in present]), matches=0, capabilities=0, pending=0,
                    usage=dict(global_placeholder=None, uids=uids, peers=peers, reservations=0,
                               limits=copy.deepcopy(WORKLOAD['limits']), xml=dict(limits=None, queues=None)),
                    external=inventory(100, 0, targets, resources),
                    actors={r: inventory(a['pid'], a['uid'], ['stdin', 'stdout', 'stderr'] + (['socket'] if present else []))
                            for r, a in identities.items()}), counts

    def snapshot(present, held, now):
        row, counts = state(present, held, now)
        del row['usage']['global_placeholder']
        row['usage']['global'] = counts
        return row

    baseline = snapshot((), False, 10)
    phases = dict(connected=snapshot(('source', 'observer'), False, 20),
                  held=snapshot(('source', 'observer'), True, 30),
                  reclaimed=snapshot(('observer',), False, 35),
                  after_health=snapshot(('observer',), False, 36), final=snapshot((), False, 40))
    watch = dict(event='watch', name=identities['source']['name'], peer=mapping['source'],
                 monitor_ref='#Ref<0.1>', registered_ms=25)
    down = {k: watch[k] for k in ('name', 'peer', 'monitor_ref', 'registered_ms')}
    down.update(reason='killed', received_ms=33)
    kill = dict(event='killed', name=watch['name'], peer=watch['peer'], monitor='DOWN:killed',
                kill_ms=32, guard_deadline=5030, observed_ms=33, received_ms=33, consumed_ms=34, down=down)
    warm_send = sent(WORKLOAD['warmup_serial'], warm['observer']['name'], False)
    observer = identities['observer']['name']
    health = dict(name=observer, owner=observer, serial=WORKLOAD['health_serial'], latency_ms=2,
                  sent_hex=call('GetNameOwner', WORKLOAD['health_serial'], 's', string(observer)).hex(),
                  reply_type=2, rights=0, body_hex=string(observer).hex(),
                  fields={'5': WORKLOAD['health_serial'], '6': observer, '7': BUS, '8': 's'})
    return dict(schema=1, requirement='SEC-17', subcase='valid-incomplete-frame-peer-death', result=PASS,
                not_a_release=True, workload=copy.deepcopy(WORKLOAD), counts=WORKLOAD['counts'].copy(),
                helpers_before={'frozen': 'same'}, helpers_after={'frozen': 'same'}, candidate_hashes_after=True,
                ready=dict(pid='100', profile='system', config_file=None, resource_limits=copy.deepcopy(WORKLOAD['limits']), send_timeout_ms=5000),
                baseline=baseline, identities=identities, warm_identities=warm, peer_map=mapping,
                warm_send=warm_send, warm_receive=dict(type=4, serial=WORKLOAD['warmup_serial'], rights=1,
                    fields={'1': '/foundation', '2': 'org.foundation.Transport', '3': 'Resource',
                            '6': warm['observer']['name'], '7': warm['source']['name'], '8': 'h', '9': 1},
                    body_hex='00000000', resource=warm_send['resource'].copy(), fd_state=dict(fds=4, memfds=[])),
                prefix=prefix, phases=phases, attempts={k: [copy.deepcopy(v)] for k, v in phases.items()},
                watch=watch, frame_guard=dict(event='frame', row=copy.deepcopy(phases['held']['peers'][0]), now_ms=31), kill=kill,
                cleanup_elapsed_ms=3, health=health, health_elapsed_ms=3, source_eof=dict(eof=True, suffix_sent=False),
                phase_order=['warmup', 'baseline', 'connected', 'watch', 'prefix', 'held', 'frame_guard', 'kill',
                             'reclaimed', 'health', 'after_health', 'source_eof', 'close', 'final'],
                final_cleanup_elapsed_ms=3, actor_final={r: dict(fds=3, memfds=[]) for r in identities},
                watcher_shutdown=dict(event='watcher_stopped', monitor='DOWN:normal', rows=[down.copy()], registered=1, waiting=0),
                collector_shutdown=dict(event='collector_stopped', monitor='DOWN:normal'),
                cleanup=[dict(role=r, method='eof', returncode=0) for r in ('source', 'observer', 'daemon')])


class Oracle(unittest.TestCase):
    def reject(self, mutate):
        evidence = valid_evidence()
        mutate(evidence)
        with self.assertRaises(AssertionError):
            assert_report(evidence)

    def test_valid_evidence(self):
        assert_report(valid_evidence())

    def test_held_frame_bytes_are_nonzero_at_every_scope(self):
        for scope in ('global', 'uids', 'peers'):
            def mutate(e, scope=scope):
                counts = e['phases']['held']['usage'][scope]
                if scope != 'global':
                    counts = counts['1100' if scope == 'uids' else e['peer_map']['source']]
                counts['frame_bytes'] = 0
            self.reject(mutate)

    def test_held_frame_fd_credit(self):
        self.reject(lambda e: e['phases']['held']['usage']['global'].update(frame_fds=0))

    def test_actual_daemon_memfd_object(self):
        self.reject(lambda e: e['phases']['held']['external']['resources'][0].update(ino=999))

    def test_daemon_fd_inventory(self):
        self.reject(lambda e: e['phases']['held']['external'].update(fds=24))

    def test_full_header_and_exact_final_byte_hold(self):
        self.reject(lambda e: e['prefix'].update(sent_bytes=15))

    def test_valid_advertised_count_index_and_wire(self):
        self.reject(lambda e: e['prefix'].update(packet_hex='00'))

    def test_suffix_never_sent(self):
        self.reject(lambda e: e['prefix'].update(suffix_sent=True))

    def test_source_does_not_keep_original_resource(self):
        self.reject(lambda e: e['prefix'].update(source_closed=False))

    def test_watch_ack_precedes_kill(self):
        self.reject(lambda e: e['watch'].update(registered_ms=40))

    def test_real_killed_down(self):
        self.reject(lambda e: e['kill']['down'].update(reason='normal'))

    def test_down_consumed_before_cleanup_and_deadline(self):
        self.reject(lambda e: e['kill'].update(consumed_ms=5031))

    def test_same_original_frame_deadline(self):
        self.reject(lambda e: e['kill'].update(guard_deadline=9999))

    def test_cleanup_bound(self):
        self.reject(lambda e: e.update(cleanup_elapsed_ms=1001))

    def test_frame_accounting_fully_reclaimed(self):
        self.reject(lambda e: e['phases']['reclaimed']['usage']['global'].update(frame_fds=1))

    def test_no_orphan_memfd(self):
        self.reject(lambda e: e['phases']['reclaimed']['external']['memfds'].append(e['prefix']['resource']['target']))

    def test_survivor_kernel_identity(self):
        self.reject(lambda e: e['phases']['after_health']['actors']['observer'].update(uids=[0] * 4))

    def test_survivor_same_peer(self):
        self.reject(lambda e: e['phases']['after_health']['peers'][0].update(peer='<0.999.0>'))

    def test_unique_name_owner_health(self):
        self.reject(lambda e: e['health'].update(owner=':1.999'))

    def test_health_has_no_resource_or_extra_frame(self):
        self.reject(lambda e: e['health'].update(rights=1))

    def test_health_bound(self):
        self.reject(lambda e: e.update(health_elapsed_ms=1001))

    def test_authorities_survive(self):
        self.reject(lambda e: e['phases']['reclaimed']['authorities'].update({'GaoBus.Router': '<0.999.0>'}))

    def test_exact_baseline_and_activation_credits(self):
        self.reject(lambda e: e['phases']['final']['usage']['global'].update(activation_fds=1))

    def test_normal_owned_children_and_watcher_shutdown(self):
        self.reject(lambda e: e['cleanup'][0].update(method='kill'))
        self.reject(lambda e: e['watcher_shutdown'].update(waiting=1))


if __name__ == '__main__':
    unittest.main()
