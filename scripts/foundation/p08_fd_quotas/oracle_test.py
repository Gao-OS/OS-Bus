"""Offline malformed-evidence regressions. No bus, BEAM, VM or traffic."""
import copy
import hashlib
import os
import unittest

from actor import WORKLOAD, packet, resource, validate_partial
from qualify import assert_report

METRICS = ('connections', 'authenticating', 'ingress_messages', 'ingress_bytes',
           'ingress_fds', 'egress_messages', 'egress_bytes', 'egress_fds', 'frame_bytes', 'frame_fds')


def valid_evidence():
    empty = dict.fromkeys(METRICS, 0)
    limits = {scope: {**dict.fromkeys(METRICS, 10000000), **counts} for scope, counts in WORKLOAD['limits'].items()}
    actors = {}
    for index, (role, uid) in enumerate(WORKLOAD['roles'].items()):
        actors[role] = {'name': ':1.%d' % (index + 10), 'pid': 100 + index, 'uid': uid,
                        'gid': uid, 'external': {'pid': 100 + index, 'uids': [uid] * 4, 'gids': [uid] * 4}}
    peer_map = {r: '<0.%d.0>' % a['pid'] for r, a in actors.items()}
    frozen = {}
    for attempt in WORKLOAD['admissions']:
        role, serial = attempt['role'], attempt['serial']
        raw = packet(serial, actors[role]['name'], WORKLOAD['accepted_payload_bytes'], actors['source']['name'])
        frozen[role] = {'serial': serial, 'sender': actors['source']['name'], 'type': 'signal',
                        'member': 'Hold', 'bytes': len(raw), 'offset': 4480, 'deadline': 5100 + serial,
                        'blocked': True, 'rights_sent': True, 'fds': 1,
                        'sha256': hashlib.sha256(raw).hexdigest()}
    def state(active, present=tuple(actors)):
        global_counts = empty.copy()
        global_counts['connections'] = len(present)
        peers, peer_counts, uids = [], {}, {}
        for role in present:
            actor = actors[role]
            counts = empty.copy()
            counts['connections'] = 1
            out = copy.deepcopy(frozen[role]) if role in active else None
            if out:
                counts.update(egress_messages=1, egress_fds=1, egress_bytes=out['bytes'])
            peer_counts[peer_map[role]] = counts
            uid_counts = uids.setdefault(str(actor['uid']), empty.copy())
            for key, value in counts.items():
                uid_counts[key] += value
                if key != 'connections':
                    global_counts[key] += value
            peers.append({'name': actor['name'], 'peer': peer_map[role], 'negotiated': True,
                          'credentials': {k: actor[k] for k in ('pid', 'uid', 'gid')},
                          'output': out, 'queue': 0, 'buffer_bytes': 0})
        return {'peers': peers, 'now_ms': 1100, 'pending': 0, 'names': ['org.freedesktop.DBus'],
                'matches': 0, 'capabilities': 0, 'authorities': {'Router': '<0.1.0>'},
                'external': {'fds': 12 + 2 * len(present) + len(active),
                             'memfds': sorted('/memfd:quota-%d (deleted)' % frozen[r]['serial'] for r in active)},
                'usage': {'global': global_counts,
                'uids': uids, 'peers': peer_counts, 'reservations': len(active), 'limits': limits,
                'xml': {'limits': None, 'queues': None}}}
    warmups = [{'peer': '<0.%d.0>' % (200 + i), 'sender': ':1.1', 'serial': 901 + i} for i in range(4)]
    def trace(admitted, denied):
        rows = [{'target': r['peer'], 'sender': r['sender'], 'serial': r['serial'], 'member': 'Hold', 'type': 'signal'} for r in warmups]
        rows += [{'target': peer_map[r['role']], 'sender': actors['source']['name'], 'serial': r['serial'], 'member': 'Hold', 'type': 'signal'} for r in admitted]
        failures = [{'target': peer_map[r['role']], 'scope': r['scope'], 'metric': r['metric'], 'fds': 1,
                     'bytes': len(packet(r['serial'], actors[r['role']]['name'], WORKLOAD['denied_payload_bytes'], actors['source']['name'], True))} for r in denied]
        return {'rows': rows, 'failures': failures, 'peak_queue': 10, 'seen': len(rows) + len(failures)}
    ordered = [WORKLOAD['admissions'][0], WORKLOAD['admissions'][1], WORKLOAD['denials'][0], WORKLOAD['admissions'][2], WORKLOAD['denials'][1]]
    active, admitted, denied, attempts, phases, traces = [], [], [], [], [], []
    for attempt in ordered:
        row = attempt.copy()
        if 'scope' in row:
            denied.append(attempt)
            row.update(error='org.freedesktop.DBus.Error.LimitsExceeded', reply_serial=row['serial'])
        else:
            active.append(row['role'])
            admitted.append(attempt)
        attempts.append(row)
        phases.append(state(active))
        traces.append(trace(admitted, denied))
    baseline = state([], ())
    health = {'latency_ms': 1, 'fds': 0, 'serial': 10001, 'reply_serial': 10001, 'sender': 'org.freedesktop.DBus'}
    partial = {}
    for role, out in frozen.items():
        raw = packet(out['serial'], actors[role]['name'], WORKLOAD['accepted_payload_bytes'], out['sender'])
        partial[role] = {'serial': out['serial'], 'sender': out['sender'], 'target': actors[role]['name'],
                         'wire_bytes': out['offset'], 'encoded_bytes': out['bytes'],
                         'prefix_sha256': hashlib.sha256(raw[:out['offset']]).hexdigest(),
                         'encoded_sha256': out['sha256'], 'fds': 1, 'partial': True, 'eof': True,
                         'resource': resource(out['serial']).decode(),
                         'resource_target': '/memfd:quota-%d (deleted)' % out['serial'],
                         'after_close': {'memfds': []}}
    evidence = {'candidate_hashes_after': True, 'helpers_hashes_after': True,
            'counts': WORKLOAD['counts'].copy(), 'cleanup': [{'returncode': 0, 'method': 'eof'} for _ in range(6)],
            'identities': actors, 'peer_map': peer_map, 'attempts': attempts, 'phases': phases,
            'trace': traces + [trace(admitted, denied)], 'final_trace': trace(admitted, denied),
            'warmups': warmups, 'baseline': baseline, 'final': copy.deepcopy(baseline),
            'actor_baseline': {r: {'fds': 3, 'memfds': []} for r in actors},
            'actor_final': {r: {'fds': 3, 'memfds': []} for r in actors},
            'before_health': state(active), 'after_health': state(active), 'after_kills': state(['A2', 'B1'], ('observer', 'A2', 'B1')),
            'frozen': frozen, 'source_health': health.copy(), 'observer_health': health.copy(),
            'observer_recovery_health': health.copy(), 'health_elapsed_ms': 2,
            'kills': [{'name': actors[r]['name'], 'monitor': 'DOWN:killed', 'kill_ms': 1200,
                       'observed_ms': 1201, 'guard_deadline': frozen['A1']['deadline']} for r in ('source', 'A1')],
            'expiries': [{'name': actors[r]['name'], 'monitor': 'DOWN:normal', 'deadline': frozen[r]['deadline'],
                         'received_ms': frozen[r]['deadline'] + 5,
                         'observed_ms': frozen[r]['deadline'] + 5,
                         'consumed_ms': frozen[r]['deadline'] + 10} for r in ('A2', 'B1')], 'partial': partial}
    watches = [{'name': actors[r]['name'], 'peer': peer_map[r], 'monitor_ref': 'ref-' + r,
                'registered_ms': 500} for r in ('source', 'A1', 'A2', 'B1')]
    evidence['watches'] = watches
    down_rows = []
    for role, row in zip(('source', 'A1', 'A2', 'B1'), evidence['kills'] + evidence['expiries']):
        registration = next(r for r in watches if r['name'] == actors[role]['name'])
        row.update(peer=peer_map[role], received_ms=row['observed_ms'])
        row.setdefault('consumed_ms', row['received_ms'] + 1)
        down = {**registration, 'reason': row['monitor'].split(':', 1)[1], 'received_ms': row['received_ms']}
        row['down'] = down
        down_rows.append(down)
    evidence['ready'] = {'watcher': {'watcher': '<0.999.0>', 'registered': 0, 'rows': [], 'waiting': 0}}
    evidence['watcher_shutdown'] = {'event': 'watcher_stopped', 'watcher': '<0.999.0>',
        'registered': 4, 'rows': down_rows, 'waiting': 0, 'queries': 10,
        'max_watches': 4, 'max_queries': 32, 'clock': 'BEAM monotonic receipt of DOWN', 'monitor': 'DOWN:normal'}
    return evidence


class EvidenceOracleTest(unittest.TestCase):
    def reject(self, mutate):
        evidence = valid_evidence()
        mutate(evidence)
        with self.assertRaises(AssertionError):
            assert_report(evidence)

    def test_complete_valid_evidence(self):
        assert_report(valid_evidence())

    def test_wrong_denial_scope(self):
        self.reject(lambda e: e['trace'][2]['failures'][0].update(scope='peer'))

    def test_wrong_denial_metric_or_bytes(self):
        for field, value in [('metric', 'egress_bytes'), ('bytes', 1), ('fds', 0)]:
            with self.subTest(field=field):
                self.reject(lambda e: e['final_trace']['failures'][0].update({field: value}))

    def test_unexplained_control_rejection(self):
        self.reject(lambda e: e['final_trace']['failures'].append({'fds': 0, 'bytes': 64}))

    def test_missing_extra_or_denied_admission(self):
        self.reject(lambda e: e['final_trace']['rows'].pop())
        self.reject(lambda e: e['final_trace']['rows'].append(e['final_trace']['rows'][-1].copy()))
        self.reject(lambda e: e['final_trace']['rows'][-1].update(serial=202, type='method_call'))

    def test_failed_uid_identity(self):
        self.reject(lambda e: e['identities']['A2']['external'].update(uids=[1101] * 4))
        self.reject(lambda e: e['phases'][0]['peers'][2]['credentials'].update(uid=0))

    def test_single_process_clients(self):
        self.reject(lambda e: e['identities']['A2'].update(pid=e['identities']['A1']['pid']))

    def test_uid_accounting_required(self):
        self.reject(lambda e: e['phases'][2]['usage']['uids']['1100'].update(egress_fds=1))

    def test_nonpartial_writer(self):
        self.reject(lambda e: e['phases'][0]['peers'][2]['output'].update(offset=0))
        self.reject(lambda e: e['phases'][0]['peers'][2]['output'].update(blocked=False))
        self.reject(lambda e: e['phases'][0]['peers'][2]['output'].update(rights_sent=False))

    def test_changed_original_deadline(self):
        self.reject(lambda e: e['after_health']['peers'][2]['output'].update(deadline=99999))
        self.reject(lambda e: e['expiries'][0].update(deadline=1, observed_ms=1))

    def test_full_fd_capacity_lost_during_health(self):
        self.reject(lambda e: e['after_health']['usage']['global'].update(egress_fds=2))
        self.reject(lambda e: e['after_health'].update(now_ms=10000))

    def test_trusted_sender_and_encoded_size(self):
        self.reject(lambda e: e['phases'][0]['peers'][2]['output'].update(sender=':9.9'))
        self.reject(lambda e: e['phases'][0]['peers'][2]['output'].update(bytes=1))

    def test_pending_or_xml_invalidates_oracle(self):
        self.reject(lambda e: e['phases'][2].update(pending=1))
        self.reject(lambda e: e['phases'][0]['usage']['xml'].update(queues={}))

    def test_health_deadline_and_observed_zero_fds(self):
        self.reject(lambda e: e.update(health_elapsed_ms=1001))
        self.reject(lambda e: e['source_health'].update(fds=1))
        self.reject(lambda e: e['observer_health'].update(sender=':1.1'))

    def test_monitored_cleanup_bounds(self):
        self.reject(lambda e: e['kills'][0].update(monitor='DOWN:normal'))
        self.reject(lambda e: e['kills'][1].update(kill_ms=99999))
        self.reject(lambda e: e['expiries'][0].update(observed_ms=99999))

    def test_denied_resource_not_delivered(self):
        self.reject(lambda e: e['partial']['B1'].update(resource='quota-resource-202'))
        self.reject(lambda e: e['partial']['A1'].update(fds=2))
        self.reject(lambda e: e['partial']['A2']['after_close'].update(memfds=['/memfd:quota-201 (deleted)']))

    def test_partial_eof_required(self):
        self.reject(lambda e: e['partial']['A1'].update(eof=False))
        self.reject(lambda e: e['partial']['A2'].update(wire_bytes=1))
        self.reject(lambda e: e['partial']['B1'].update(prefix_sha256='0' * 64))

    def test_fd_denial_has_other_capacity_headroom(self):
        self.reject(lambda e: e['phases'][1]['usage']['global'].update(egress_fds=3))
        self.reject(lambda e: e['phases'][3]['usage']['uids']['1101'].update(egress_fds=2))
        self.reject(lambda e: e['phases'][1]['usage']['uids']['1100'].update(egress_bytes=1048576))

    def test_non_fd_root_and_global_credits_cannot_leak(self):
        self.reject(lambda e: e['phases'][2]['usage']['uids']['0'].update(egress_messages=1))
        self.reject(lambda e: e['phases'][2]['usage']['global'].update(egress_bytes=1))
        self.reject(lambda e: e['phases'][2]['usage'].update(reservations=3))
        self.reject(lambda e: e['phases'][2]['usage']['peers'][e['peer_map']['source']].update(frame_bytes=1))

    def test_denial_preserves_original_writers(self):
        self.reject(lambda e: e['phases'][2]['peers'][2]['output'].update(deadline=9999))
        self.reject(lambda e: e['phases'][4]['peers'][4]['output'].update(offset=4481))

    def test_phase_exact_fd_inventory_rejects_retained_denied_rights(self):
        self.reject(lambda e: e['phases'][2]['external'].update(fds=25))
        self.reject(lambda e: e['phases'][2]['external']['memfds'].append('/memfd:quota-201 (deleted)'))
        self.reject(lambda e: e['phases'][4]['external']['memfds'].append('/memfd:quota-202 (deleted)'))

    def test_health_and_afterkill_exact_external_inventory(self):
        self.reject(lambda e: e['before_health']['external'].update(fds=26))
        self.reject(lambda e: e['after_health']['external']['memfds'].pop())
        self.reject(lambda e: e['after_kills']['external'].update(fds=21))

    def test_recorded_early_b1_cannot_hide_behind_late_consumption(self):
        def early(evidence):
            row = evidence['expiries'][1]
            at = evidence['frozen']['B1']['deadline'] - 1
            row.update(received_ms=at, observed_ms=at)
            row['down'].update(received_ms=at)
        self.reject(early)

    def test_consumed_time_cannot_replace_recorded_down_time(self):
        self.reject(lambda e: e['expiries'][1].update(observed_ms=e['expiries'][1]['consumed_ms']))

    def test_bounded_independent_watcher_join_and_registration(self):
        self.reject(lambda e: e['watcher_shutdown'].update(monitor='DOWN:killed'))
        self.reject(lambda e: e['watcher_shutdown'].update(queries=33))
        self.reject(lambda e: e['watcher_shutdown']['rows'].pop())
        self.reject(lambda e: e['watches'][0].update(registered_ms=9999))

    def test_exact_empty_fd_and_authority_recovery(self):
        self.reject(lambda e: e['final']['external'].update(fds=13))
        self.reject(lambda e: e['actor_final']['A1'].update(fds=4))
        self.reject(lambda e: e['final']['usage']['global'].update(egress_fds=1))
        self.reject(lambda e: e['final']['authorities'].update(Router='<0.2.0>'))

    def test_incomplete_counts_and_shutdown(self):
        self.reject(lambda e: e['counts'].update(admitted=2))
        self.reject(lambda e: e['cleanup'][0].update(method='kill'))
        self.reject(lambda e: e['cleanup'][1].update(returncode=1))
        self.reject(lambda e: e.update(candidate_hashes_after=False))

    def test_independent_partial_bytes_and_usable_named_memfd(self):
        serial, target, sender = 101, ':1.12', ':1.10'
        expected = packet(serial, target, WORKLOAD['accepted_payload_bytes'], sender)
        fd = os.memfd_create('quota-101', os.MFD_CLOEXEC)
        try:
            os.write(fd, resource(serial))
            result = validate_partial(expected[:4480], [fd], serial, target, sender, 4480)
            self.assertEqual(result['resource'], resource(serial).decode())
            for raw, rights in [(expected, [fd]), (expected[:16], [fd]),
                                (b'X' + expected[1:4480], [fd]), (expected[:4480], []),
                                (expected[:4480], [fd, fd])]:
                with self.subTest(length=len(raw), rights=len(rights)), self.assertRaises(AssertionError):
                    validate_partial(raw, rights, serial, target, sender, len(raw))
            os.pwrite(fd, b'REJECTED', 0)
            with self.assertRaises(AssertionError):
                validate_partial(expected[:4480], [fd], serial, target, sender, 4480)
        finally:
            os.close(fd)


if __name__ == '__main__':
    unittest.main()
