"""Offline evidence mutations; no bus, BEAM, VM, or traffic."""
import copy
import hashlib
import struct
import unittest

from actor import WORKLOAD, packet, payload, resource
from qualify import assert_report

METRICS = ('connections', 'authenticating', 'ingress_messages', 'ingress_bytes',
           'ingress_fds', 'egress_messages', 'egress_bytes', 'egress_fds',
           'frame_bytes', 'frame_fds', 'activation_messages', 'activation_bytes',
           'activation_fds')
ACTIVATION_METRICS = ('activation_messages', 'activation_bytes', 'activation_fds')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def valid_evidence():
    roles = tuple(WORKLOAD['roles'])
    identities = {role: {'name': ':1.%d' % (index + 10), 'pid': 100 + index,
                        'uid': uid, 'gid': uid,
                        'external': {'pid': 100 + index, 'uids': [uid] * 4, 'gids': [uid] * 4}}
                  for index, (role, uid) in enumerate(WORKLOAD['roles'].items())}
    peers = {r: '<0.%d.0>' % a['pid'] for r, a in identities.items()}
    warm_identities = copy.deepcopy(identities)
    for index, actor in enumerate(warm_identities.values()):
        actor['name'] = ':1.%d' % (index + 1)
    warm_peers = {r: '<0.%d.0>' % (200 + i) for i, r in enumerate(roles)}
    serial, sender = 101, identities['source']['name']
    raw = packet(serial, None, WORKLOAD['accepted_payload_bytes'], sender)
    out = {'serial': serial, 'sender': sender, 'type': 'signal', 'member': 'Hold',
           'bytes': len(raw), 'offset': 4480, 'deadline': 6000, 'blocked': True,
           'rights_sent': True, 'fds': 1, 'sha256': digest(raw)}
    limits = {scope: {**dict.fromkeys(METRICS, 10_000_000), **counts}
              for scope, counts in WORKLOAD['limits'].items()}
    actor_baseline = {r: {**identities[r]['external'], 'fds': 3, 'memfds': []} for r in roles}
    target = '/memfd:fanout-101 (deleted)'
    authorities = {name: '<0.%d.0>' % (i + 1) for i, name in enumerate((
        'GaoBus.Supervisor', 'GaoBus.Ids', 'GaoBus.NameRegistry', 'GaoBus.MatchRules',
        'GaoBus.Policy', 'GaoBus.Policy.Capability', 'GaoBus.Limits', 'GaoBus.Router', 'GaoBus.Listener'))}
    def state(present, pending=False, held=True, matches=True, now=1100):
        global_counts = dict.fromkeys(METRICS, 0)
        rows, uid_counts, peer_counts = [], {}, {}
        for role in present:
            actor = identities[role]
            counts = {**dict.fromkeys(METRICS, 0), 'connections': 1}
            current = copy.deepcopy(out) if pending and role == 'slow' else None
            if current:
                counts.update(egress_messages=1, egress_fds=1, egress_bytes=len(raw))
            peer_counts[peers[role]] = counts
            uid = uid_counts.setdefault(str(actor['uid']), dict.fromkeys(METRICS, 0))
            for key, value in counts.items():
                global_counts[key] += value
                uid[key] += value
            rows.append({'name': actor['name'], 'peer': peers[role], 'negotiated': True,
                         'credentials': {k: actor[k] for k in ('pid', 'uid', 'gid')},
                         'output': current, 'queue': 0, 'buffer_bytes': 0, 'mailbox': 0})
        return {'pid': '2000', 'peers': rows, 'now_ms': now, 'names': sorted(['org.freedesktop.DBus'] +
                    [identities[r]['name'] for r in present]), 'pending': 0,
                'matches': sum(r in ('fast', 'slow') for r in present) if matches else 0,
                'capabilities': 0, 'authorities': authorities.copy(),
                'usage': {'global': global_counts, 'uids': uid_counts, 'peers': peer_counts,
                          'reservations': int(pending), 'limits': limits,
                          'xml': {'limits': None, 'queues': None}},
                'external': {'pid': 2000, 'uids': [0] * 4, 'gids': [0] * 4,
                             'fds': 12 + 2 * len(present) + int(pending),
                             'memfds': [target] if pending else []},
                'actors': {r: {**identities[r]['external'], 'fds': 3 + 1 + int(held and r == 'fast'),
                               'memfds': [target] if held and r == 'fast' else []}
                           for r in roles}}
    baseline = state((), held=False, matches=False, now=800)
    baseline['actors'] = copy.deepcopy(actor_baseline)
    final = copy.deepcopy(baseline)
    final['now_ms'] = 1700
    warmups = []
    for role, number in zip(('fast', 'slow', 'observer'), (901, 902, 903)):
        warm_sender, warm_target = warm_identities['source']['name'], warm_identities[role]['name']
        warm_raw = packet(number, warm_target, WORKLOAD['accepted_payload_bytes'], warm_sender)
        body = (0).to_bytes(4, 'little') + WORKLOAD['accepted_payload_bytes'].to_bytes(4, 'little') + payload(number, WORKLOAD['accepted_payload_bytes'])
        warmups.append({'role': role, 'serial': number, 'peer': warm_peers[role],
                       'sender': warm_sender,
                       'result': {'serial': number, 'sender': warm_sender, 'target': warm_target,
                                  'used': True, 'fds': 1, 'held_fd': False,
                                  'wire_bytes': len(warm_raw), 'encoded_bytes': len(warm_raw),
                                  'wire_sha256': digest(warm_raw), 'encoded_sha256': digest(warm_raw),
                                  'body_sha256': digest(body), 'resource': resource(number).decode(),
                                  'resource_sha256': digest(resource(number)),
                                  'resource_target': '/memfd:fanout-%d (deleted)' % number,
                                  'after_close': {'fds': 4, 'memfds': []}}})
    warm_rows = [{'target': r['peer'], 'sender': r['sender'], 'serial': r['serial'],
                  'member': 'Hold', 'type': 'signal'} for r in warmups]
    rows = warm_rows + [{'target': peers[r], 'sender': sender, 'serial': serial,
                         'member': 'Hold', 'type': 'signal'} for r in ('fast', 'slow')]
    trace = {'rows': rows, 'failures': [], 'peak_queue': 4, 'seen': 5}
    common = {'serial': serial, 'sender': sender, 'target': None, 'fds': 1,
              'encoded_bytes': len(raw), 'encoded_sha256': digest(raw),
              'resource': resource(serial).decode(), 'resource_sha256': digest(resource(serial)),
              'resource_target': target}
    full = {**common, 'wire_bytes': len(raw), 'wire_sha256': digest(raw),
            'body_sha256': digest((0).to_bytes(4, 'little') + WORKLOAD['accepted_payload_bytes'].to_bytes(4, 'little') + payload(serial, WORKLOAD['accepted_payload_bytes'])),
            'used': True, 'held_fd': True, 'fd_identity': '1:123',
            'after_receive': {'fds': 5, 'memfds': [target]}}
    partial = {**common, 'fd_identity': '1:123', 'wire_bytes': 4480, 'prefix_sha256': digest(raw[:4480]),
               'partial': True, 'eof': True, 'after_close': {'fds': 4, 'memfds': []}}
    retained = [{'stage': stage, 'serial': serial, 'fds': 1, 'held_fd': True,
                 'fd_identity': '1:123', 'resource': resource(serial).decode(),
                 'resource_sha256': digest(resource(serial)), 'resource_target': target,
                 'fd_state': {'fds': 5, 'memfds': [target]}}
                for stage in ('after_source', 'after_slow')]
    watches, kills, down_rows = [], [], []
    for role, at in [('source', 1300), ('slow', 1500)]:
        registration = {'name': identities[role]['name'], 'peer': peers[role],
                        'monitor_ref': 'ref-' + role, 'registered_ms': 1000}
        down = {**registration, 'reason': 'killed', 'received_ms': at + 1}
        watches.append({'event': 'watch', **registration})
        down_rows.append(down)
        kills.append({'name': identities[role]['name'], 'peer': peers[role],
                      'monitor': 'DOWN:killed', 'kill_ms': at, 'guard_deadline': 6000,
                      'observed_ms': at + 1, 'received_ms': at + 1,
                      'consumed_ms': at + 2, 'down': down})
    health = {'latency_ms': 1, 'fds': 0, 'serial': 10001, 'strict_fence': True,
              'reply_serial': 10001, 'sender': 'org.freedesktop.DBus'}
    return {'result': 'passed_scoped_fd_fanout', 'candidate_hashes_after': True,
            'helpers_hashes_after': True, 'counts': WORKLOAD['counts'].copy(),
            'ready': {'pid': '2000', 'config_file': None, 'profile': 'system', 'resource_limits': WORKLOAD['limits'],
                      'send_timeout_ms': 5000,
                      'watcher': {'watcher': '<0.999.0>', 'registered': 0, 'waiting': 0, 'rows': []}},
            'warm_identities': warm_identities, 'warm_peer_map': warm_peers,
            'identities': identities, 'peer_map': peers, 'baseline': baseline,
            'actor_baseline': actor_baseline, 'actor_final': copy.deepcopy(actor_baseline),
            'warmups': warmups, 'warm_trace': {'rows': warm_rows, 'failures': [], 'peak_queue': 4, 'seen': 3},
            'trace': copy.deepcopy(trace), 'final_trace': copy.deepcopy(trace),
            'broadcast': {'serial': serial, 'target': None, 'payload_bytes': WORKLOAD['accepted_payload_bytes'],
                          'fd_identity': '1:123', 'source_closed': True, 'after_send': {'fds': 4, 'memfds': []}},
            'subscriptions': {r: {'subscribed': True, 'rule': WORKLOAD['match_rule'], 'name': identities[r]['name']}
                              for r in ('fast', 'slow')},
            'stall': {'event': 'stalled', 'name': identities['slow']['name'], 'peer': peers['slow'], 'sndbuf': 1024},
            'source_eof': {'eof': True},
            'full': full, 'partial': partial, 'retained': retained,
            'release': {'held_fd': False, 'fd_identity': '1:123', 'fd_state': {'fds': 4, 'memfds': []}},
            'frozen': out,
            'phases': {'connected': state(roles, held=False, matches=False, now=900),
                       'blocked': state(roles, pending=True),
                       'after_health': state(roles, pending=True, now=1200),
                       'after_source': state(('fast', 'slow', 'observer'), pending=True, now=1303),
                       'after_slow': state(('fast', 'observer'), now=1503),
                       'released': state(('fast', 'observer'), held=False, now=1600)},
            'source_health': health.copy(), 'observer_health': health.copy(),
            'observer_recovery_health': health.copy(), 'health_elapsed_ms': 2,
            'final_fences': {r: {**health, 'extra_messages': 0} for r in ('fast', 'observer')},
            'kills': kills, 'watches': watches, 'final': final,
            'watcher_shutdown': {'event': 'watcher_stopped', 'watcher': '<0.999.0>',
                                 'registered': 2, 'waiting': 0, 'rows': down_rows, 'queries': 6,
                                 'max_watches': 4, 'max_queries': 32,
                                 'clock': 'BEAM monotonic receipt of DOWN', 'monitor': 'DOWN:normal'},
            'collector_shutdown': {'event': 'collector_stopped', 'monitor': 'DOWN:normal'},
            'cleanup': [{'role': r, 'returncode': 0, 'method': 'eof'} for r in (*roles, 'daemon')]}


class EvidenceOracleTest(unittest.TestCase):
    def reject(self, mutate):
        evidence = valid_evidence()
        mutate(evidence)
        with self.assertRaises(AssertionError):
            assert_report(evidence)

    def test_complete_valid_evidence(self):
        assert_report(valid_evidence())

    def test_saved_current_report_accounting_contract(self):
        # Candidate15 run1 report SHA256:
        # 40f537fce3dea4b92a028d3322aaeb36c2c5dd2d4c7aef0e2ef7af5e5c486525
        evidence = valid_evidence()
        for state in (evidence['baseline'], evidence['final'], *evidence['phases'].values()):
            usage = state['usage']
            for counts in (usage['global'], *usage['uids'].values(), *usage['peers'].values()):
                counts.update(dict.fromkeys(ACTIVATION_METRICS, 0))
        self.assertEqual(evidence['phases']['blocked']['usage']['global'], {
            'connections': 4, 'authenticating': 0,
            'ingress_messages': 0, 'ingress_bytes': 0, 'ingress_fds': 0,
            'egress_messages': 1, 'egress_bytes': 196752, 'egress_fds': 1,
            'frame_bytes': 0, 'frame_fds': 0,
            'activation_messages': 0, 'activation_bytes': 0, 'activation_fds': 0,
        })
        assert_report(evidence)

    def test_activation_credits_are_zero_in_every_nonactivation_phase_and_scope(self):
        for sample in ('baseline', 'final', *valid_evidence()['phases']):
            for scope in ('global', 'uids', 'peers'):
                for metric in ACTIVATION_METRICS:
                    def mutate(e, sample=sample, scope=scope, metric=metric):
                        state = e[sample] if sample in ('baseline', 'final') else e['phases'][sample]
                        counts = state['usage'][scope]
                        if scope != 'global':
                            if not counts:
                                counts['unexpected'] = dict.fromkeys(METRICS, 0)
                            counts = next(iter(counts.values()))
                        counts[metric] = 1
                    with self.subTest(sample=sample, scope=scope, metric=metric):
                        self.reject(mutate)

    def test_exact_accounting_metric_keys_in_every_phase_and_scope(self):
        for sample in ('baseline', 'final', *valid_evidence()['phases']):
            for scope in ('global', 'uids', 'peers'):
                for metric in (*METRICS, 'unknown_metric'):
                    def mutate(e, sample=sample, scope=scope, metric=metric):
                        state = e[sample] if sample in ('baseline', 'final') else e['phases'][sample]
                        counts = state['usage'][scope]
                        if scope != 'global':
                            if not counts:
                                counts['unexpected'] = dict.fromkeys(METRICS, 0)
                            counts = next(iter(counts.values()))
                        if metric == 'unknown_metric':
                            counts[metric] = 0
                        else:
                            counts.pop(metric, None)
                    with self.subTest(sample=sample, scope=scope, metric=metric):
                        self.reject(mutate)

    def test_counts_and_frozen_inputs(self):
        self.reject(lambda e: e['counts'].update(full=0))
        self.reject(lambda e: e.update(candidate_hashes_after=False))
        self.reject(lambda e: e.update(helpers_hashes_after=False))

    def test_four_independent_kernel_identities(self):
        self.reject(lambda e: e['identities']['fast'].update(pid=e['identities']['slow']['pid']))
        self.reject(lambda e: e['identities']['slow']['external'].update(uids=[0] * 4))
        self.reject(lambda e: e['phases']['blocked']['peers'][0]['credentials'].update(pid=999))

    def test_daemon_proc_identity_across_all_inventory_samples(self):
        for sample in ('baseline', 'final', 'connected', 'blocked', 'after_health',
                       'after_source', 'after_slow', 'released'):
            for field, value in [('pid', 999), ('uids', [999] * 4), ('gids', [999] * 4)]:
                def mutate(e, sample=sample, field=field, value=value):
                    row = e[sample] if sample in ('baseline', 'final') else e['phases'][sample]
                    row['external'][field] = value
                with self.subTest(sample=sample, field=field):
                    self.reject(mutate)

    def test_snapshot_daemon_pid_matches_ready(self):
        self.reject(lambda e: e['phases']['blocked'].update(pid='999'))
        self.reject(lambda e: e['final'].update(pid='999'))

    def test_actor_proc_identity_across_all_inventory_samples(self):
        for sample in ('baseline', 'final', 'actor_baseline', 'actor_final', 'connected',
                       'blocked', 'after_health', 'after_source', 'after_slow', 'released'):
            for field, value in [('pid', 999), ('uids', [999] * 4), ('gids', [999] * 4)]:
                def mutate(e, sample=sample, field=field, value=value):
                    if sample in ('actor_baseline', 'actor_final'):
                        row = e[sample]['fast']
                    elif sample in ('baseline', 'final'):
                        row = e[sample]['actors']['fast']
                    else:
                        row = e['phases'][sample]['actors']['fast']
                    row[field] = value
                with self.subTest(sample=sample, field=field):
                    self.reject(mutate)

    def test_stale_peer_mapping_or_connection(self):
        self.reject(lambda e: e['peer_map'].update(slow='<0.999.0>'))
        self.reject(lambda e: e['phases']['after_source']['peers'].append(e['phases']['blocked']['peers'][0]))

    def test_broadcast_has_no_destination(self):
        self.reject(lambda e: e['broadcast'].update(target=e['identities']['fast']['name']))
        self.reject(lambda e: e['broadcast'].update(source_closed=False))

    def test_only_matched_recipients_and_actual_source_eof(self):
        self.reject(lambda e: e['subscriptions']['fast'].update(rule="type='signal'"))
        self.reject(lambda e: e['stall'].update(sndbuf=4096))
        self.reject(lambda e: e['source_eof'].update(eof=False))

    def test_exact_admission_targets_and_no_rejections(self):
        self.reject(lambda e: e['trace']['rows'].pop())
        self.reject(lambda e: e['trace']['rows'].append(e['trace']['rows'][-1].copy()))
        self.reject(lambda e: e['trace']['rows'][-1].update(target=e['peer_map']['observer']))
        self.reject(lambda e: e['final_trace']['failures'].append({'fds': 1}))

    def test_warmup_actual_resources(self):
        self.reject(lambda e: e['warmups'][0]['result'].update(used=False))
        self.reject(lambda e: e['warmups'][1].update(serial=904))

    def test_exact_full_wire_and_resource(self):
        for key, value in [('wire_bytes', 16), ('encoded_sha256', '0' * 64),
                           ('wire_sha256', '0' * 64), ('body_sha256', '0' * 64),
                           ('resource_sha256', '0' * 64), ('fds', 2), ('sender', ':9.9')]:
            with self.subTest(key=key):
                self.reject(lambda e: e['full'].update({key: value}))

    def test_retained_fd_survives_both_cleanups(self):
        self.reject(lambda e: e['full'].update(held_fd=False))
        self.reject(lambda e: e['retained'][0].update(held_fd=False))
        self.reject(lambda e: e['retained'][1].update(fd_identity='1:999'))
        self.reject(lambda e: e['retained'][1].update(resource_sha256='0' * 64))
        self.reject(lambda e: e['retained'].reverse())

    def test_full_resource_object_provenance_not_just_name_and_data(self):
        def wrong_object(e):
            e['full']['fd_identity'] = '1:999'
            for row in e['retained']:
                row['fd_identity'] = '1:999'
            e['release']['fd_identity'] = '1:999'
        self.reject(wrong_object)

    def test_partial_resource_object_matches_source(self):
        self.reject(lambda e: e['partial'].update(fd_identity='1:999'))

    def test_release_and_actor_inventory(self):
        self.reject(lambda e: e['release'].update(held_fd=True))
        self.reject(lambda e: e['phases']['after_slow']['actors']['fast'].update(fds=4, memfds=[]))
        self.reject(lambda e: e['release']['fd_state'].update(fds=5))

    def test_exact_partial_disposition(self):
        for key, value in [('wire_bytes', 4481), ('prefix_sha256', '0' * 64),
                           ('encoded_sha256', '0' * 64), ('fds', 2), ('eof', False),
                           ('resource_target', '/memfd:unrelated (deleted)')]:
            with self.subTest(key=key):
                self.reject(lambda e: e['partial'].update({key: value}))

    def test_partial_prefix_contains_body_payload_despite_consistent_offset_hashes(self):
        for boundary in ('one_byte', 'header_only', 'header_plus_eight'):
            def mutate(e, boundary=boundary):
                expected = packet(101, None, WORKLOAD['accepted_payload_bytes'],
                                  e['identities']['source']['name'])
                header_size = struct.unpack_from('<I', expected, 12)[0]
                body_at = 16 + header_size + (-header_size % 8)
                offset = {'one_byte': 1, 'header_only': body_at,
                          'header_plus_eight': body_at + 8}[boundary]
                e['frozen']['offset'] = offset
                for phase in e['phases'].values():
                    for peer in phase['peers']:
                        if peer['name'] == e['identities']['slow']['name'] and peer['output']:
                            peer['output']['offset'] = offset
                e['partial'].update(wire_bytes=offset,
                                    prefix_sha256=digest(expected[:offset]))
            with self.subTest(boundary=boundary):
                self.reject(mutate)

    def test_slow_original_writer_unchanged(self):
        self.reject(lambda e: e['phases']['after_source']['peers'][1]['output'].update(deadline=9999))
        self.reject(lambda e: e['frozen'].update(offset=0))

    def test_exact_phase_fd_and_memfd_inventory(self):
        self.reject(lambda e: e['phases']['after_source']['external'].update(fds=20))
        self.reject(lambda e: e['phases']['after_slow']['external']['memfds'].append('/memfd:fanout-101 (deleted)'))

    def test_exact_global_uid_peer_credits(self):
        self.reject(lambda e: e['phases']['blocked']['usage']['global'].update(egress_fds=2))
        self.reject(lambda e: e['phases']['after_source']['usage']['uids']['1101'].update(egress_bytes=1))
        self.reject(lambda e: e['phases']['after_slow']['usage'].update(reservations=1))

    def test_names_matches_authorities_and_xml(self):
        self.reject(lambda e: e['phases']['after_slow'].update(matches=2))
        self.reject(lambda e: e['phases']['after_source']['names'].append(e['identities']['source']['name']))
        self.reject(lambda e: e['phases']['blocked']['authorities'].update(Router='<0.2.0>'))
        self.reject(lambda e: e['phases']['blocked']['usage']['xml'].update(queues={}))

    def test_health_zero_rights_and_original_deadlines(self):
        self.reject(lambda e: e.update(health_elapsed_ms=1001))
        self.reject(lambda e: e['source_health'].update(fds=1))
        self.reject(lambda e: e['observer_recovery_health'].update(sender=':9.9'))
        self.reject(lambda e: e['phases']['after_health'].update(now_ms=6000))

    def test_kill_receipt_not_consumption_and_bounded_cleanup(self):
        self.reject(lambda e: e['kills'][0].update(received_ms=1299, observed_ms=1299))
        self.reject(lambda e: e['kills'][1].update(observed_ms=1502))
        self.reject(lambda e: e['kills'][0].update(guard_deadline=9999))
        self.reject(lambda e: e['kills'][1].update(kill_ms=6000))
        self.reject(lambda e: e['phases']['after_source'].update(now_ms=2301))

    def test_inventory_phase_chronology(self):
        self.reject(lambda e: e['baseline'].update(now_ms=1800))
        self.reject(lambda e: e['phases']['connected'].update(now_ms=1200))
        self.reject(lambda e: e['phases']['after_health'].update(now_ms=1050))
        self.reject(lambda e: e['phases']['released'].update(now_ms=1400))
        self.reject(lambda e: e['final'].update(now_ms=1400))

    def test_consumed_down_precedes_following_cleanup_inventory(self):
        for index, stage in enumerate(('after_source', 'after_slow')):
            with self.subTest(stage=stage):
                self.reject(lambda e, index=index, stage=stage: e['kills'][index].update(
                    consumed_ms=e['phases'][stage]['now_ms'] + 1))

    def test_monitor_registration_precedes_kill(self):
        def late_registration(e):
            e['phases']['blocked']['now_ms'] = 1302
            e['watches'][0]['registered_ms'] = 1301
            e['kills'][0]['down']['registered_ms'] = 1301
        self.reject(late_registration)

    def test_watcher_records_registration_and_normal_join(self):
        self.reject(lambda e: e['watcher_shutdown']['rows'].pop())
        self.reject(lambda e: e['watcher_shutdown'].update(queries=33))
        self.reject(lambda e: e['watcher_shutdown'].update(monitor='DOWN:killed'))
        self.reject(lambda e: e['watches'][0].update(registered_ms=2000))
        self.reject(lambda e: e['collector_shutdown'].update(monitor='DOWN:killed'))

    def test_watch_ack_requires_actual_event(self):
        for index in range(2):
            with self.subTest(index=index, event='wrong'):
                self.reject(lambda e, index=index: e['watches'][index].update(event='down'))
            with self.subTest(index=index, event='missing'):
                self.reject(lambda e, index=index: e['watches'][index].pop('event'))

    def test_down_scalars_match_watch_ack_and_kill_receipt(self):
        for index in range(2):
            for field, value in [('name', ':9.9'), ('peer', '<0.999.0>'),
                                 ('monitor_ref', 'ref-wrong'), ('registered_ms', 999),
                                 ('reason', 'normal'), ('received_ms', 999)]:
                with self.subTest(index=index, field=field):
                    self.reject(lambda e, index=index, field=field, value=value:
                                e['kills'][index]['down'].update({field: value}))

    def test_down_rows_exclude_ack_event_and_extra_metadata(self):
        for index in range(2):
            for field, value in [('event', 'watch'), ('pid', 999)]:
                with self.subTest(index=index, field=field):
                    self.reject(lambda e, index=index, field=field, value=value:
                                e['kills'][index]['down'].update({field: value}))

    def test_terminal_down_rows_match_consumed_scalars_exactly(self):
        for index in range(2):
            for field, value in [('name', ':9.9'), ('peer', '<0.999.0>'),
                                 ('monitor_ref', 'ref-wrong'), ('registered_ms', 999),
                                 ('reason', 'normal'), ('received_ms', 999),
                                 ('event', 'watch'), ('pid', 999)]:
                def mutate(e, index=index, field=field, value=value):
                    rows = e['watcher_shutdown']['rows']
                    rows[index] = {**rows[index], field: value}
                with self.subTest(index=index, field=field):
                    self.reject(mutate)

    def test_final_fence_rejects_extra_messages(self):
        self.reject(lambda e: e['final_fences']['fast'].update(extra_messages=1))
        self.reject(lambda e: e['final_fences']['observer'].update(fds=1))

    def test_exact_warmed_recovery(self):
        self.reject(lambda e: e['final']['external'].update(fds=13))
        self.reject(lambda e: e['actor_final']['slow'].update(fds=4))
        self.reject(lambda e: e['final']['usage']['global'].update(egress_fds=1))
        self.reject(lambda e: e['final'].update(matches=1))

    def test_all_five_owned_children_exit_normally(self):
        self.reject(lambda e: e['cleanup'].pop())
        self.reject(lambda e: e['cleanup'][0].update(method='kill'))
        self.reject(lambda e: e['cleanup'][-1].update(returncode=1))


if __name__ == '__main__':
    unittest.main()
