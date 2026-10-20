"""Acceptance regressions only; synthetic state never supplies VM evidence."""
import ast
import copy
import subprocess
import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('res01_runner', Path(__file__).with_name('run.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

METRICS = ('connections', 'authenticating', 'frame_bytes', 'frame_fds', 'ingress_messages',
           'ingress_bytes', 'ingress_fds', 'egress_messages', 'egress_bytes', 'egress_fds',
           'activation_messages', 'activation_bytes', 'activation_fds')
AUTHORITIES = {'GaoBus.' + key: '#PID<0.' + str(index + 1) + '.0>' for index, key in enumerate(
    ('Supervisor', 'Listener', 'Router', 'Limits', 'NameRegistry', 'MatchRules', 'Policy', 'PeerSupervisor'))}


def observation(uids=(1100,), held=(), names=(), matches=(), peer_numbers=None, actor_pids=None, unique_numbers=None):
    """Independent model of the root observation contract."""
    active, children, peers, accounts, counts, unique_rows, reverse = [], [], [], {}, {}, [], []
    global_counts = {key: 0 for key in METRICS}
    uid_counts = {}
    for index, uid in enumerate(uids):
        identity = dict(pid=300 + index if actor_pids is None else actor_pids[index], uid=uid, gid=uid, proc_status=f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{uid}\t{uid}\t{uid}\t{uid}\n')
        unique = None if index in held else ':1.' + str(index + 1 if unique_numbers is None else unique_numbers[index])
        peer = '#PID<0.' + str(100 + index if peer_numbers is None else peer_numbers[index]) + '.0>'
        active.append(dict(identity=identity, unique=unique))
        values = {key: int(key == 'connections' or key == 'authenticating' and index in held) for key in METRICS}
        counts[peer] = values
        accounts[peer] = dict(uid=uid, counts=values, tokens={'map': {}}, ingress_waiting=False, xml_completed=False)
        children.append(dict(peer=peer, credentials={key: identity[key] for key in ('pid', 'uid', 'gid')}, unique=unique,
                             phase='authenticating' if unique is None else 'connected', auth_phase='authenticated' if unique is None else 'connected'))
        for key, value in values.items():
            global_counts[key] += value
            uid_counts.setdefault(str(uid), {metric: 0 for metric in METRICS})[key] += value
        if unique is not None:
            unique_rows.append([unique, peer])
            reverse.append([peer, unique])
            peers.append(dict(peer=peer, credentials=identity | {'unique_name': unique}, name=unique,
                              names=[], match_rules=False, capabilities=0))
    name_rows = []
    for name, owner, queue in [('org.foundation.Observer', 0, [])] + list(names):
        owner_peer, unique = children[owner]['peer'], active[owner]['unique']
        queued = [[children[index]['peer'], active[index]['unique'], 0] for index in queue]
        name_rows.append([name, owner_peer, unique, 0, queued])
        reverse.append([owner_peer, name])
        reverse.extend([children[index]['peer'], name] for index in queue)
    entries = [[children[index]['peer'], '#Ref<0.' + str(number) + '.0>', {'type': 'signal', 'member': rule}, rule]
               for number, (index, rule) in enumerate(matches)]
    for row in peers:
        # names_for/1 exposes unique and primary ownership, never queued claims.
        row['names'] = [row['name']] + [name for name, owner, _, _, _ in name_rows if owner == row['peer']]
        row['match_rules'] = any(entry[0] == row['peer'] for entry in entries)
        row['credentials'] = {key: row['credentials'][key] for key in ('pid', 'uid', 'gid', 'unique_name')}
    limits = {'global': global_counts, 'uids': uid_counts, 'peers': counts,
              'reservations': 0, 'reload_reservations': 0, 'limits': copy.deepcopy(fixture.WORKLOAD['profile']),
              'xml': {'limits': None, 'queues': None, 'global': {'incomplete': 0, 'completed': 0}, 'uids': {}}}
    extra = dict(authorities=AUTHORITIES.copy(), limits=limits,
                 accounting=dict(peers=accounts, retired={}, reservations={}, bound_handles={}, accept_observers={}, reload=None),
                 children=children, supervised=dict(active=len(uids), specs=len(uids), workers=len(uids), supervisors=0),
                 names=dict(names=sorted(name_rows), uniques=sorted(unique_rows),
                            pid_names=sorted(reverse, key=lambda row: (int(row[0].split('.')[1]), row[1])),
                            max_names_per_peer=2, max_name_entries=4, xml_limits=False),
                 matches=dict(entries=entries, max_matches_per_peer=2, max_match_entries=3, xml_limits=False))
    state = dict(event='snapshot', router=AUTHORITIES['GaoBus.Router'], policy='unchanged rules/generation', peers=peers,
                 names=[fixture.BUS] + [row[0] for row in name_rows] + [row[0] for row in unique_rows],
                 queues=[dict(name=n, owner=p, unique=u, flags=f, queue=[dict(peer=q, unique=v, flags=g) for q, v, g in qs])
                         for n, p, u, f, qs in sorted(name_rows)],
                 usage={'global': global_counts.copy(), 'reservations': 0,
                        'peers': [dict(peer=p, counts=c) for p, c in counts.items()],
                        'uids': [dict(uid=int(u), counts=c) for u, c in uid_counts.items()]}, res01=extra)
    # Construct expected joins independently; a broken validator must not stop
    # construction of the counterexample it is supposed to reject or qualify.
    joins = [dict(identity=actor['identity'], peer=child['peer'], unique=actor['unique'],
                  counts=counts[child['peer']], child=child) for actor, child in zip(active, children)]
    return dict(state=state, active=active, joins=joins)


def shutdown_observation(pid=200, actor_pid=300, returncode=0):
    """Inert retirement witness; never a claim about live Linux processes."""
    before = dict(stdin_closed=True, wrapper_waited=True, wrapper_returncode=returncode,
                  pid_absent=True, actor_pid_absent=True, group_absent=True,
                  timed_out=False, errors=[], elapsed_ms=10)
    return dict(method='eof', returncode=returncode, process_group_retired=True,
                pid=pid, identity=dict(pid=actor_pid, uid=1100, gid=1100, starttime_ticks=123,
                              wrapper_pid=pid, wrapper_starttime_ticks=122, pgid=pid),
                pid_absent=True, actor_pid_absent=True, group_absent=True, before_containment=before)


def accepted_report():
    """A complete synthetic transcript permits positive and adversarial replay."""
    base = observation()
    report = dict(selected=fixture.SELECTED.copy(), outcomes={}, authorities=AUTHORITIES.copy(), baseline=base['state'], bus_id=['synthetic-id'],
                  daemon_shutdown=shutdown_observation(100, 100),
                  quit_flushed=True, socket_removed=True, shutdown_errors=[],
                  actors_shutdown=[shutdown_observation()])
    for dimension in fixture.SELECTED:
        trials = {}
        for label in fixture.TRIALS[dimension]:
            uid = 1101 if label in ('1101', 'mixed', 'queued') else 1100
            target_peer, reused_peer = None, None
            if dimension == 'uid_connections':
                uids = (1100,) + (uid,) * (3 if uid == 1100 else 4)
                n, released, reused = observation(uids), observation(uids[:-1]), observation(uids)
                allocation_count = len(uids) - 1
                reused_peer = reused['joins'][-1]['peer']
            elif dimension == 'global_connections':
                uids = (1100, 1100, 1100, 1100, 1101, 1101)
                n, released, reused = observation(uids), observation(uids[:-1]), observation(uids)
                allocation_count, reused_peer = 5, reused['joins'][-1]['peer']
            elif dimension == 'uid_authenticating':
                uids = (1100, uid, uid)
                n = observation(uids, held=(1, 2))
                released = observation(uids + (1101 if uid == 1100 else 1100,), held=(2,),
                                       peer_numbers=(100, 101, 102, 900), actor_pids=(300, 301, 302, 900))
                reused = observation(uids + (uid,), held=(2, 3))
                allocation_count, reused_peer = 2, reused['joins'][-1]['peer']
            elif dimension == 'global_authenticating':
                uids = (1100, 1100, 1100, 1101)
                n, released = observation(uids, held=(1, 2, 3)), observation(uids, held=(2, 3))
                reused = observation(uids + (1101,), held=(2, 3, 4))
                allocation_count, reused_peer = 3, reused['joins'][-1]['peer']
            elif dimension == 'peer_names':
                index = 0 if uid == 1100 else 1
                uids = (1100,) if index == 0 else (1100, 1101)
                prefix = 'org.foundation.Res01A' if index == 0 else 'org.foundation.Service.Res01'
                names = tuple((f'{prefix}.Name{number}', index, []) for number in range(1 if index == 0 else 2))
                n, released, reused = observation(uids, names=names), observation(uids, names=names[:-1]), observation(uids, names=names)
                allocation_count, target_peer = len(names), n['joins'][index]['peer']
                reused_peer = target_peer
            elif dimension == 'global_names':
                names = (('org.foundation.Res01A.One', 0, []), ('org.foundation.Service.Res01.Queue', 1, [2]))
                n = observation((1100, 1101, 1101), names=names)
                released_names = (names[0], (names[1][0], 1, []))
                released = observation((1100, 1101, 1101), names=released_names)
                reused = observation((1100, 1101, 1101), names=released_names + (('org.foundation.Service.Res01.Fresh', 2, []),))
                allocation_count, target_peer = 3, n['joins'][2]['peer']
                reused_peer = target_peer
            else:
                global_case = dimension == 'global_matches'
                uids = (1100, 1101, 1100) if global_case else (1100, uid)
                entries = (((2, 'One'), (2, 'Two'), (1, 'One')) if global_case
                           else ((1, 'One'), (1, 'One' if label == 'duplicate' else 'Two')))
                n, released, reused = observation(uids, matches=entries), observation(uids, matches=entries[1:]), observation(uids, matches=entries)
                released['state']['res01']['matches']['entries'] = copy.deepcopy(n['state']['res01']['matches']['entries'][1:])
                if label == 'duplicate':
                    n['state']['res01']['matches']['entries'][0][3] = "type='signal',member='One'"
                    n['state']['res01']['matches']['entries'][1][3] = "member='One',type='signal'"
                    released['state']['res01']['matches']['entries'] = copy.deepcopy(n['state']['res01']['matches']['entries'][1:])
                    replacement = copy.deepcopy(n['state']['res01']['matches']['entries'][0])
                    replacement[1] = '#Ref<0.2.0>'
                    reused['state']['res01']['matches']['entries'] = copy.deepcopy(n['state']['res01']['matches']['entries'][1:]) + [replacement]
                allocation_count, target_peer = len(entries), n['joins'][1]['peer']
                reused_peer = target_peer
            phases = dict(before=copy.deepcopy(base), N=n, rejected=copy.deepcopy(n), released=released, reused=reused,
                          baseline=copy.deepcopy(base), baseline_repeated=copy.deepcopy(base))
            rejection = (dict(admitted=False, closed=True, begin_sent=False, response_hex='')
                         if 'connections' in dimension or 'authenticating' in dimension
                         else dict(request_serial=9, reply=dict(type=3, reply_serial=9, error=fixture.LIMIT, body=[])))
            trials[label] = dict(phases=phases, target_peer=target_peer, reused_peer=reused_peer, target_uid=uid,
                                 headroom=fixture.headroom(n['state'], target_peer, uid, dimension), rejection=rejection,
                                 allocations=[dict(success=True) for _ in range(allocation_count)], reallocation_ms=10,
                                 probes=[dict(elapsed_ms=5, owner=dict(type=2, body=[':1.1']), bus_id=dict(type=2, body=['synthetic-id']))],
                                 socket_closes=[dict(closed=True)], held_elapsed_ms=300,
                                 auth_completed=dict(connections_unchanged=True, auth_delta=-1))
            trial = trials[label]
            if dimension == 'uid_connections':
                trial['independent'] = observation(uids + (1101 if uid == 1100 else 1100,),
                    peer_numbers=tuple(range(100, 100 + len(uids))) + (900,),
                    actor_pids=tuple(range(300, 300 + len(uids))) + (900,))
            elif dimension == 'uid_authenticating':
                trial['independent'] = observation(uids + (1101 if uid == 1100 else 1100,), held=(1, 2, 3),
                                                  peer_numbers=(100, 101, 102, 900), actor_pids=(300, 301, 302, 900))
            if 'authenticating' in dimension:
                trial['all_completed'] = observation(tuple(actor['identity']['uid'] for actor in reused['active']))
        report['outcomes'][dimension] = dict(status='passed', trials=trials)
    death_before = observation((1100, 1101, 1101), names=(('org.foundation.Service.Res01.Queue', 1, [2]), ('org.foundation.Service.Res01.Fresh', 2, [])), matches=((2, 'Death'),))
    death_after = observation((1100, 1101), names=(('org.foundation.Service.Res01.Queue', 1, []),))
    death_reuse = observation((1100, 1101, 1101),
        names=(('org.foundation.Service.Res01.Queue', 1, []), ('org.foundation.Service.Res01.Fresh', 2, [])),
        matches=((2, 'Death'),), peer_numbers=(100, 101, 103), actor_pids=(300, 301, 303), unique_numbers=(1, 2, 4))
    death_reuse['state']['res01']['matches']['entries'][0][1] = '#Ref<0.1.0>'
    report['outcomes']['global_names']['death'] = dict(before=death_before, after=death_after, repeated=copy.deepcopy(death_after),
        reuse=death_reuse, actual_actor_pid=302, actor_dead_pidfd=True, actor_proc_absent=True,
        wrapper_exit=137, reused=True, reallocation_ms=20)
    return report


def replace_observer_identity(observed):
    """An internally consistent replacement still violates original binding."""
    observed['active'][0]['identity']['pid'] = 999
    observed['state']['res01']['children'][0]['credentials']['pid'] = 999
    observed['state']['peers'][0]['credentials']['pid'] = 999


class StateAcceptance(unittest.TestCase):
    def test_real_registered_and_pre_begin_identity_joins(self):
        row = observation((1100, 1100, 1101), held=(1, 2))
        self.assertEqual(fixture.validate_state(row['state'], row['active'], AUTHORITIES), row['joins'])

    def test_distinct_same_uid_held_actors_cover_every_trusted_child(self):
        row = observation((1100, 1101, 1101), held=(1, 2))
        joined = fixture.validate_state(row['state'], row['active'], AUTHORITIES)
        self.assertEqual(joined, row['joins'])
        self.assertEqual(len({actor['identity']['pid'] for actor in row['active']}), 3)
        self.assertEqual({actor['peer'] for actor in joined},
                         {child['peer'] for child in row['state']['res01']['children']})
        self.assertEqual([actor['identity']['uid'] for actor in joined if actor['unique'] is None], [1101, 1101])

    def test_duplicate_held_actor_pid_cannot_replace_an_omitted_trusted_child(self):
        row = observation((1100, 1101, 1101), held=(1, 2))
        fixture.validate_state(row['state'], row['active'], AUTHORITIES)
        for description in ('duplicate actor record', 'duplicate PID only', 'unvisited child corrupted'):
            changed = copy.deepcopy(row)
            if description == 'duplicate PID only':
                changed['active'][2]['identity']['pid'] = changed['active'][1]['identity']['pid']
            else:
                changed['active'][2] = copy.deepcopy(changed['active'][1])
            if description == 'unvisited child corrupted':
                changed['state']['res01']['children'][2]['auth_phase'] = 'connected'
            self.assertEqual(changed['state']['res01']['limits']['global'], row['state']['res01']['limits']['global'])
            self.assertEqual(changed['state']['res01']['limits']['uids'], row['state']['res01']['limits']['uids'])
            with self.subTest(mutation=description), self.assertRaises(AssertionError):
                fixture.validate_state(changed['state'], changed['active'], AUTHORITIES)

    def test_queued_waiter_original_names_include_only_unique_and_primary(self):
        queued_name = 'org.foundation.Service.Res01.Queue'
        primary_name = 'org.foundation.Service.Res01.Fresh'
        row = observation((1100, 1101, 1101), names=((queued_name, 1, [2]), (primary_name, 2, [])))
        waiter = row['state']['peers'][2]
        self.assertEqual(set(waiter['names']), {waiter['name'], primary_name})
        self.assertIn([waiter['peer'], queued_name], row['state']['res01']['names']['pid_names'])
        self.assertEqual(fixture.validate_state(row['state'], row['active'], AUTHORITIES), row['joins'])

    def test_queue_and_reverse_validation_rejects_missing_extra_and_duplicate_associations(self):
        row = observation((1100, 1101, 1101), names=(('org.foundation.Service.Res01.Queue', 1, [2]),))
        fixture.validate_state(row['state'], row['active'], AUTHORITIES)
        mutations = (
            ('missing queued reverse', lambda s: s['res01']['names']['pid_names'].remove(['#PID<0.102.0>', 'org.foundation.Service.Res01.Queue'])),
            ('extra reverse', lambda s: s['res01']['names']['pid_names'].append(['#PID<0.102.0>', 'org.foundation.Service.Res01.Unowned'])),
            ('duplicate reverse', lambda s: s['res01']['names']['pid_names'].append(s['res01']['names']['pid_names'][-1].copy())),
            ('missing original queue', lambda s: s['queues'][-1]['queue'].clear()),
            ('duplicate queue member', lambda s: s['res01']['names']['names'][-1][4].append(s['res01']['names']['names'][-1][4][0].copy())),
            ('queued claim in primary API', lambda s: s['peers'][2]['names'].append('org.foundation.Service.Res01.Queue')),
            ('missing primary API ownership', lambda s: s['peers'][1]['names'].remove('org.foundation.Service.Res01.Queue')),
        )
        for label, mutate in mutations:
            changed = copy.deepcopy(row)
            mutate(changed['state'])
            with self.subTest(mutation=label), self.assertRaises((AssertionError, KeyError)):
                fixture.validate_state(changed['state'], changed['active'], AUTHORITIES)

    def test_native_pid_digit_boundary_order_qualifies(self):
        row = observation((1100, 1101), peer_numbers=(99, 100))
        reverse = row['state']['res01']['names']['pid_names']
        self.assertEqual(reverse[0][0], '#PID<0.99.0>')
        self.assertEqual(reverse[-1][0], '#PID<0.100.0>')
        self.assertNotEqual(reverse, sorted(reverse))
        self.assertEqual(fixture.validate_state(row['state'], row['active'], AUTHORITIES), row['joins'])

    def test_native_pid_order_does_not_hide_duplicate_reverse_associations(self):
        row = observation((1100, 1101), peer_numbers=(99, 100))
        fixture.validate_state(row['state'], row['active'], AUTHORITIES)
        row['state']['res01']['names']['pid_names'].append(['#PID<0.99.0>', ':1.1'])
        with self.assertRaises(AssertionError):
            fixture.validate_state(row['state'], row['active'], AUTHORITIES)

    def test_rejects_identity_accounting_profile_and_table_drift(self):
        baseline = observation((1100, 1101), names=(('org.foundation.Service.Res01.One', 1, []),), matches=((1, 'One'),))
        mutations = (
            lambda r: r['active'][1]['identity'].update(uid=1100),
            lambda r: r['state']['res01']['children'][1]['credentials'].update(pid=999),
            lambda r: r['state']['res01']['accounting']['peers']['#PID<0.101.0>'].update(uid=1100),
            lambda r: r['state']['res01']['limits']['global'].update(connections=99),
            lambda r: r['state']['res01']['limits']['uids']['1101'].update(connections=99),
            lambda r: r['state']['res01']['limits']['limits']['uid'].update(authenticating=3),
            lambda r: r['state']['res01']['names']['pid_names'].pop(),
            lambda r: r['state']['res01']['matches']['entries'].append(r['state']['res01']['matches']['entries'][0]),
            lambda r: r['state']['res01']['accounting']['retired'].update(tombstone={}),
            lambda r: r['state']['res01']['limits'].update(reload_reservations=1),
            lambda r: r['state']['res01']['supervised'].update(active=3),
            lambda r: r['state']['res01']['authorities'].update({'GaoBus.Router': '#PID<0.999.0>'}),
        )
        for mutation in mutations:
            changed = copy.deepcopy(baseline)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises((AssertionError, KeyError)):
                fixture.validate_state(changed['state'], changed['active'], AUTHORITIES)

    def test_held_peer_must_not_appear_in_router_or_have_begin_credit_retired(self):
        held = observation((1100, 1101), held=(1,))
        held['state']['res01']['children'][1]['auth_phase'] = 'connected'
        with self.assertRaises(AssertionError):
            fixture.validate_state(held['state'], held['active'], AUTHORITIES)

    def test_global_names_counts_queue_associations(self):
        row = observation((1100, 1101, 1101), names=(('org.foundation.Res01A.One', 0, []), ('org.foundation.Service.Res01.Queue', 1, [2])))
        fixture.validate_state(row['state'], row['active'], AUTHORITIES)
        proof = fixture.headroom(row['state'], '#PID<0.102.0>', 1101, 'global_names')
        self.assertEqual(proof['remaining']['global_names'], 0)
        self.assertEqual(len(row['state']['res01']['names']['names']), 3)
        self.assertEqual(proof['remaining']['peer_names'], 1)

    def test_nonunique_and_not_reached_boundaries_fail(self):
        for sample in (observation((1100, 1101)), observation((1100, 1100, 1100, 1100, 1101, 1101))):
            with self.assertRaises(AssertionError):
                fixture.headroom(sample['state'], None, 1100, 'global_connections')

    def test_exact_limits_error_and_serial_are_required(self):
        sample = dict(request_serial=4, reply=dict(type=3, reply_serial=4, error=fixture.LIMIT, body=[]))
        fixture.reply(sample, error=fixture.LIMIT)
        for key, value in [('reply_serial', 5), ('error', fixture.BUS + '.Error.AccessDenied'), ('type', 2)]:
            changed = copy.deepcopy(sample)
            changed['reply'][key] = value
            with self.assertRaises(AssertionError):
                fixture.reply(changed, error=fixture.LIMIT)


class LauncherAcceptance(unittest.TestCase):
    def test_missing_duplicate_and_wrong_source_anchors_fail(self):
        source = (Path(__file__).parent.parent / 'vm_security' / 'daemon.exs').read_text()
        fixture.guard_source(source)
        for changed in (source.replace('GaoBus.Limits.defaults()', 'bad()', 1),
                        source + '\nGaoBus.Limits.defaults()',
                        source.replace('Stream.repeatedly', 'Stream.changed'),
                        source + '\nStream.repeatedly(fn -> IO.read(:stdio, :line) end)'):
            with self.assertRaises(AssertionError):
                fixture.guard_source(changed)

    def test_provenance_profile_and_honest_transform_fail_closed(self):
        provenance = dict(event='res01_provenance', original_sha256=fixture.WORKLOAD['original_pins']['daemon.exs'],
                          transformed_sha256='a' * 64, transformation='res01-two-defaults-one-readonly-snapshot-v1',
                          defaults_replaced=2, snapshot_insertions=1, profile=copy.deepcopy(fixture.WORKLOAD['profile']),
                          defaults_profile=copy.deepcopy(fixture.WORKLOAD['profile']),
                          authorities=copy.deepcopy(fixture.WORKLOAD['authorities']), lifecycle='embedded',
                          config_file=None, inherited_listener=False, max_connections=256)
        ready = dict(configuration=dict(resource_limits=copy.deepcopy(provenance['profile']), auth_limits=dict(timeout_ms=1500, idle_timeout_ms=500)))
        fixture.validate_provenance(provenance, ready)
        for mutation in (
            lambda p: p.update(defaults_replaced=1), lambda p: p.update(snapshot_insertions=2),
            lambda p: p.update(transformed_sha256=p['original_sha256']),
            lambda p: p.update(config_file='/etc/dbus.conf'), lambda p: p.update(inherited_listener=True),
            lambda p: p['authorities'].update(max_name_entries=5), lambda p: p['profile']['global'].update(connections=7),
        ):
            changed = copy.deepcopy(provenance)
            mutation(changed)
            with self.assertRaises(AssertionError):
                fixture.validate_provenance(changed, ready)


class SelectionAcceptance(unittest.TestCase):
    def test_zero_missing_skipped_failed_and_running_never_pass(self):
        for selection in ([], fixture.SELECTED[:-1], fixture.SELECTED + [fixture.SELECTED[0]]):
            with self.assertRaises(AssertionError):
                fixture.complete(dict(selected=selection, outcomes={}))
        for status in ('blocked', 'skipped', 'failed', 'running'):
            report = dict(selected=fixture.SELECTED, outcomes={name: dict(status=status) for name in fixture.SELECTED})
            with self.assertRaises(AssertionError):
                fixture.complete(report)

    def test_passed_boolean_without_per_case_evidence_never_passes(self):
        report = dict(selected=fixture.SELECTED, outcomes={name: dict(status='passed', trials={}) for name in fixture.SELECTED})
        with self.assertRaises(AssertionError):
            fixture.complete(report)

    def test_complete_rejects_duplicate_saved_held_actor_join_coverage(self):
        report = accepted_report()
        fixture.complete(report)
        for label in ('1100', '1101'):
            for description in ('duplicate actor and saved join', 'duplicate saved join only'):
                changed = copy.deepcopy(report)
                rejected = changed['outcomes']['uid_authenticating']['trials'][label]['phases']['rejected']
                if description == 'duplicate actor and saved join':
                    rejected['active'][2] = copy.deepcopy(rejected['active'][1])
                rejected['joins'][2] = copy.deepcopy(rejected['joins'][1])
                with self.subTest(uid=label, mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                    fixture.complete(changed)

    def test_complete_transcript_and_mutations(self):
        transcript = accepted_report()
        fixture.complete(transcript)
        mutations = (
            lambda r: r['outcomes']['peer_names']['trials'].pop('1101'),
            lambda r: r['outcomes']['global_names']['trials']['queued']['phases'].pop('reused'),
            lambda r: r['outcomes']['global_connections']['trials']['mixed']['allocations'].pop(),
            lambda r: r['outcomes']['uid_authenticating']['trials']['1100'].update(held_elapsed_ms=401),
            lambda r: r['outcomes']['peer_matches']['trials']['duplicate']['rejection']['reply'].update(error=fixture.BUS + '.Error.AccessDenied'),
            lambda r: r['outcomes']['peer_names']['trials']['1100']['probes'][0]['owner'].update(body=[':1.999']),
            lambda r: r['outcomes']['global_matches']['trials']['mixed']['phases']['rejected']['state']['res01']['matches']['entries'][0].__setitem__(1, '#Ref<0.changed.0>'),
            lambda r: r['outcomes']['global_names']['death'].update(actor_dead_pidfd=False),
            lambda r: r.update(socket_removed=False),
        )
        for mutation in mutations:
            changed = copy.deepcopy(transcript)
            mutation(changed)
            with self.subTest(mutation=mutation), self.assertRaises((AssertionError, KeyError)):
                fixture.complete(changed)

    def test_complete_positive_has_full_independence_completion_and_canonical_duplicate_witnesses(self):
        report = accepted_report()
        for dimension in ('uid_connections', 'uid_authenticating'):
            for label, trial in report['outcomes'][dimension]['trials'].items():
                n = trial['phases']['N']
                independent = trial['independent']
                self.assertEqual(len(independent['active']), len(n['active']) + 1)
                witness = independent['joins'][-1]
                self.assertEqual(witness['identity']['uid'], 1101 if label == '1100' else 1100)
                self.assertEqual(witness['unique'] is None, dimension == 'uid_authenticating')
        for dimension in ('uid_authenticating', 'global_authenticating'):
            for trial in report['outcomes'][dimension]['trials'].values():
                completed = trial['all_completed']
                self.assertEqual(completed['state']['res01']['limits']['global']['authenticating'], 0)
                self.assertEqual([r['identity'] for r in completed['active']],
                                 [r['identity'] for r in trial['phases']['reused']['active']])
                self.assertTrue(all(row['unique'] is not None for row in completed['joins']))
        duplicate = report['outcomes']['peer_matches']['trials']['duplicate']
        entries = duplicate['phases']['N']['state']['res01']['matches']['entries']
        self.assertEqual(entries[0][2], entries[1][2])
        self.assertNotEqual(entries[0][1], entries[1][1])
        self.assertNotEqual(entries[0][3], entries[1][3])
        self.assertEqual(duplicate['phases']['released']['state']['res01']['matches']['entries'], [entries[1]])
        fixture.complete(report)

    def test_complete_rejects_absent_or_shape_only_independent_observations(self):
        report = accepted_report()
        fixture.complete(report)
        for dimension in ('uid_connections', 'uid_authenticating'):
            for label in ('1100', '1101'):
                for malformed in ('absent', None, True, {}, {'passed': True}):
                    changed = copy.deepcopy(report)
                    trial = changed['outcomes'][dimension]['trials'][label]
                    if malformed == 'absent':
                        trial.pop('independent')
                    else:
                        trial['independent'] = malformed
                    with self.subTest(dimension=dimension, uid=label, malformed=malformed), self.assertRaises((AssertionError, KeyError, TypeError)):
                        fixture.complete(changed)

    def test_complete_revalidates_independent_authorities_observer_accounting_and_joins(self):
        report = accepted_report()
        fixture.complete(report)
        mutations = (
            ('authority restart', lambda o: o['state']['res01']['authorities'].update({'GaoBus.NameRegistry': '#PID<0.999.0>'})),
            ('observer replacement', replace_observer_identity),
            ('unjoined actor PID', lambda o: o['active'][-1]['identity'].update(pid=999)),
            ('unexpected UID', lambda o: o['active'][-1]['identity'].update(uid=999)),
            ('global credit drift', lambda o: o['state']['res01']['limits']['global'].update(connections=99)),
            ('absent joins', lambda o: o.pop('joins')),
            ('missing witness join', lambda o: o['joins'].pop()),
            ('forged witness peer join', lambda o: o['joins'][-1].update(peer='#PID<0.999.0>')),
        )
        for dimension in ('uid_connections', 'uid_authenticating'):
            for label in ('1100', '1101'):
                for description, mutate in mutations:
                    changed = copy.deepcopy(report)
                    mutate(changed['outcomes'][dimension]['trials'][label]['independent'])
                    with self.subTest(dimension=dimension, uid=label, mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                        fixture.complete(changed)

    def test_complete_requires_other_uid_witness_while_target_uid_stays_saturated(self):
        report = accepted_report()
        fixture.complete(report)
        for dimension in ('uid_connections', 'uid_authenticating'):
            for label in ('1100', '1101'):
                trial = report['outcomes'][dimension]['trials'][label]
                n = trial['phases']['N']
                uids = tuple(row['identity']['uid'] for row in n['active'])
                target_uid = int(label)
                other_uid = 1101 if target_uid == 1100 else 1100
                held = tuple(range(1, len(uids))) if dimension == 'uid_authenticating' else ()
                wrong_uid = observation(uids + (target_uid,), held=held + ((len(uids),) if held else ()))
                no_witness = copy.deepcopy(n)
                unsaturated = observation(uids[:-1] + (other_uid,), held=tuple(range(1, len(uids))) if held else ())
                alternatives = [('same UID witness', wrong_uid), ('no admitted witness', no_witness), ('target credit released first', unsaturated)]
                if held:
                    alternatives.append(('witness already sent BEGIN', observation(uids + (other_uid,), held=held)))
                for description, replacement in alternatives:
                    changed = copy.deepcopy(report)
                    changed['outcomes'][dimension]['trials'][label]['independent'] = replacement
                    with self.subTest(dimension=dimension, uid=label, mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                        fixture.complete(changed)

    def test_complete_rejects_absent_or_shape_only_all_completed_observations(self):
        report = accepted_report()
        fixture.complete(report)
        for dimension in ('uid_authenticating', 'global_authenticating'):
            for label in fixture.TRIALS[dimension]:
                for malformed in ('absent', None, True, {}, {'all_completed': True}):
                    changed = copy.deepcopy(report)
                    trial = changed['outcomes'][dimension]['trials'][label]
                    if malformed == 'absent':
                        trial.pop('all_completed')
                    else:
                        trial['all_completed'] = malformed
                    with self.subTest(dimension=dimension, uid=label, malformed=malformed), self.assertRaises((AssertionError, KeyError, TypeError)):
                        fixture.complete(changed)

    def test_complete_revalidates_all_completed_zero_credit_and_original_holder_joins(self):
        report = accepted_report()
        fixture.complete(report)
        for dimension in ('uid_authenticating', 'global_authenticating'):
            for label, trial in report['outcomes'][dimension]['trials'].items():
                completed = trial['all_completed']
                uids = tuple(row['identity']['uid'] for row in completed['active'])
                replacements = (
                    ('holder still authenticating', observation(uids, held=(len(uids) - 1,))),
                    ('holder omitted', observation(uids[:-1])),
                    ('holder PID substituted', observation(uids, actor_pids=tuple(range(300, 300 + len(uids) - 1)) + (999,))),
                    ('holder UID substituted', observation(uids[:-1] + (1101 if uids[-1] == 1100 else 1100,))),
                    ('baseline substituted', copy.deepcopy(trial['phases']['baseline'])),
                )
                for description, replacement in replacements:
                    changed = copy.deepcopy(report)
                    changed['outcomes'][dimension]['trials'][label]['all_completed'] = replacement
                    with self.subTest(dimension=dimension, uid=label, mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                        fixture.complete(changed)
                for description, mutate in (
                    ('authority restart', lambda o: o['state']['res01']['authorities'].update({'GaoBus.Limits': '#PID<0.999.0>'})),
                    ('observer replaced', replace_observer_identity),
                    ('unreconciled zero credit', lambda o: o['state']['res01']['limits']['global'].update(authenticating=1)),
                    ('absent joins', lambda o: o.pop('joins')),
                    ('missing holder join', lambda o: o['joins'].pop()),
                    ('forged holder peer join', lambda o: o['joins'][-1].update(peer='#PID<0.999.0>')),
                ):
                    changed = copy.deepcopy(report)
                    mutate(changed['outcomes'][dimension]['trials'][label]['all_completed'])
                    with self.subTest(dimension=dimension, uid=label, mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                        fixture.complete(changed)

    def test_complete_requires_canonical_duplicate_matches_with_distinct_surviving_reference(self):
        report = accepted_report()
        fixture.complete(report)
        for description in ('different canonical rules', 'shared reference', 'surviving reference replaced', 'both references removed'):
            changed = copy.deepcopy(report)
            phases = changed['outcomes']['peer_matches']['trials']['duplicate']['phases']
            n_entries = phases['N']['state']['res01']['matches']['entries']
            if description == 'different canonical rules':
                n_entries[1][2]['member'] = 'Two'
                n_entries[1][3] = "member='Two',type='signal'"
                phases['released']['state']['res01']['matches']['entries'] = copy.deepcopy(n_entries[1:])
                phases['reused']['state']['res01']['matches']['entries'][0] = copy.deepcopy(n_entries[1])
            elif description == 'shared reference':
                n_entries[1][1] = n_entries[0][1]
                phases['released']['state']['res01']['matches']['entries'] = copy.deepcopy(n_entries[1:])
            elif description == 'surviving reference replaced':
                phases['released']['state']['res01']['matches']['entries'][0][1] = '#Ref<0.999.0>'
            else:
                phases['released']['state']['res01']['matches']['entries'].clear()
                phases['released']['state']['peers'][1]['match_rules'] = False
            phases['rejected'] = copy.deepcopy(phases['N'])
            with self.subTest(mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.complete(changed)


class DeathAcceptance(unittest.TestCase):
    def test_real_new_actor_name_and_fresh_canonical_match_qualify_after_death(self):
        report = accepted_report()
        death = report['outcomes']['global_names']['death']
        before, after, reused = death['before'], death['after'], death['reuse']
        victim = next(row for row in before['joins'] if row['identity']['pid'] == death['actual_actor_pid'])
        surviving = {row['peer']: row for row in after['joins']}
        replacement = [row for row in reused['joins'] if row['peer'] not in surviving]
        self.assertEqual(len(replacement), 1)
        replacement = replacement[0]
        self.assertEqual(replacement['identity']['uid'], 1101)
        self.assertNotEqual(replacement['identity']['pid'], victim['identity']['pid'])
        self.assertNotEqual(replacement['peer'], victim['peer'])
        self.assertNotEqual(replacement['unique'], victim['unique'])
        self.assertEqual({row['peer']: row for row in reused['joins'] if row['peer'] in surviving}, surviving)
        name_rows = reused['state']['res01']['names']['names']
        self.assertIn(['org.foundation.Service.Res01.Fresh', replacement['peer'], replacement['unique'], 0, []], name_rows)
        self.assertFalse(any(any(item[0] == replacement['peer'] for item in row[4]) for row in name_rows))
        before_match = before['state']['res01']['matches']['entries'][0]
        reuse_match = reused['state']['res01']['matches']['entries'][0]
        self.assertEqual(reuse_match[0], replacement['peer'])
        self.assertEqual(reuse_match[2], before_match[2])
        self.assertNotEqual(reuse_match[1], before_match[1])
        self.assertEqual(after['state']['res01']['matches']['entries'], [])
        fixture.complete(report)

    def test_every_death_phase_requires_full_saved_identity_joins(self):
        report = accepted_report()
        fixture.complete(report)
        mutations = (
            ('absent joins', lambda o: o.pop('joins')),
            ('missing surviving join', lambda o: o['joins'].pop(0)),
            ('duplicate surviving join', lambda o: o['joins'].__setitem__(1, copy.deepcopy(o['joins'][0]))),
            ('forged surviving peer join', lambda o: o['joins'][0].update(peer='#PID<0.999.0>')),
        )
        for phase in ('before', 'after', 'repeated', 'reuse'):
            for description, mutate in mutations:
                changed = copy.deepcopy(report)
                mutate(changed['outcomes']['global_names']['death'][phase])
                with self.subTest(phase=phase, mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                    fixture.complete(changed)

    def test_every_death_phase_preserves_original_observer_identity(self):
        report = accepted_report()
        fixture.complete(report)
        for phases in (('before',), ('after', 'repeated'), ('reuse',)):
            changed = copy.deepcopy(report)
            for phase in phases:
                observed = changed['outcomes']['global_names']['death'][phase]
                replace_observer_identity(observed)
                fixture.validate_state(observed['state'], observed['active'], AUTHORITIES)
            with self.subTest(phases=phases), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.complete(changed)

    def test_every_death_phase_preserves_original_authorities(self):
        report = accepted_report()
        fixture.complete(report)
        for phase in ('before', 'after', 'repeated', 'reuse'):
            changed = copy.deepcopy(report)
            changed['outcomes']['global_names']['death'][phase]['state']['res01']['authorities']['GaoBus.NameRegistry'] = '#PID<0.999.0>'
            with self.subTest(phase=phase), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.complete(changed)

    def test_cleaned_after_cannot_substitute_for_death_reuse(self):
        report = accepted_report()
        fixture.complete(report)
        death = report['outcomes']['global_names']['death']
        death['reuse'] = copy.deepcopy(death['after'])
        self.assertTrue(death['reused'])
        with self.assertRaises((AssertionError, KeyError, TypeError)):
            fixture.complete(report)

    def test_killed_actor_pid_or_dead_before_cannot_resurrect_in_reuse(self):
        report = accepted_report()
        fixture.complete(report)
        for description in ('dead before copied as reuse', 'killed actor PID on a new peer'):
            changed = copy.deepcopy(report)
            death = changed['outcomes']['global_names']['death']
            if description == 'dead before copied as reuse':
                death['reuse'] = copy.deepcopy(death['before'])
            else:
                reused = death['reuse']
                reused['active'][2]['identity']['pid'] = death['actual_actor_pid']
                reused['state']['res01']['children'][2]['credentials']['pid'] = death['actual_actor_pid']
                reused['state']['peers'][2]['credentials']['pid'] = death['actual_actor_pid']
            fixture.validate_state(death['reuse']['state'], death['reuse']['active'], AUTHORITIES)
            with self.subTest(mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.complete(changed)

    def test_death_cleanup_preserves_survivors_and_retires_victim_allocations(self):
        report = accepted_report()
        fixture.complete(report)
        queue = ('org.foundation.Service.Res01.Queue', 1, [])
        alternatives = (
            ('survivor actor substituted', observation((1100, 1101), names=(queue,), actor_pids=(300, 999))),
            ('surviving primary name removed', observation((1100, 1101))),
            ('victim primary name retained by survivor', observation((1100, 1101), names=(queue, ('org.foundation.Service.Res01.Fresh', 1, [])))),
            ('victim match retained by survivor', observation((1100, 1101), names=(queue,), matches=((1, 'Death'),))),
        )
        for description, replacement in alternatives:
            fixture.validate_state(replacement['state'], replacement['active'], AUTHORITIES)
            changed = copy.deepcopy(report)
            death = changed['outcomes']['global_names']['death']
            death['after'] = copy.deepcopy(replacement)
            death['repeated'] = copy.deepcopy(replacement)
            with self.subTest(mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.complete(changed)

    def test_partial_or_stale_death_reallocation_never_qualifies(self):
        report = accepted_report()
        fixture.complete(report)
        queue = ('org.foundation.Service.Res01.Queue', 1, [])
        fresh = ('org.foundation.Service.Res01.Fresh', 2, [])

        def replacement(**overrides):
            values = dict(uids=(1100, 1101, 1101), names=(queue, fresh), matches=((2, 'Death'),),
                          peer_numbers=(100, 101, 103), actor_pids=(300, 301, 303), unique_numbers=(1, 2, 4))
            values.update(overrides)
            observed = observation(**values)
            for entry in observed['state']['res01']['matches']['entries']:
                entry[1] = '#Ref<0.1.0>'
            return observed

        alternatives = [
            ('replacement connection only', replacement(names=(queue,), matches=())),
            ('replacement name only', replacement(matches=())),
            ('replacement match only', replacement(names=(queue,))),
            ('wrong replacement name', replacement(names=(queue, ('org.foundation.Service.Res01.Unrelated', 2, [])))),
            ('different canonical match', replacement(matches=((2, 'OtherDeath'),))),
            ('surviving primary name lost during reuse', replacement(names=(fresh,))),
            ('replacement requeued without runtime allocation', replacement(names=(('org.foundation.Service.Res01.Queue', 1, [2]), fresh))),
            ('dead peer resurrected', replacement(peer_numbers=(100, 101, 102))),
            ('dead unique name resurrected', replacement(unique_numbers=(1, 2, 3))),
            ('wrong replacement UID', replacement(uids=(1100, 1101, 1100))),
        ]
        stale_reference = replacement()
        stale_reference['state']['res01']['matches']['entries'][0][1] = '#Ref<0.0.0>'
        alternatives.append(('dead match reference resurrected', stale_reference))
        for description, reused in alternatives:
            fixture.validate_state(reused['state'], reused['active'], AUTHORITIES)
            changed = copy.deepcopy(report)
            changed['outcomes']['global_names']['death']['reuse'] = reused
            with self.subTest(mutation=description), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.complete(changed)


class TeardownAcceptance(unittest.TestCase):
    def test_quit_zero_exit_socket_and_all_owned_groups_required(self):
        report = dict(daemon_shutdown=shutdown_observation(100, 100),
                      quit_flushed=True, socket_removed=True, shutdown_errors=[],
                      actors_shutdown=[shutdown_observation()])
        fixture.validate_teardown(report)
        for mutation in (
            lambda r: r.update(quit_flushed=False), lambda r: r.update(socket_removed=False),
            lambda r: r['daemon_shutdown'].update(method='terminate'),
            lambda r: r['daemon_shutdown'].update(returncode=-9),
            lambda r: r['daemon_shutdown'].update(process_group_retired=False),
            lambda r: r['actors_shutdown'][0].update(process_group_retired=False),
            lambda r: r['actors_shutdown'][0].update(returncode=1),
            lambda r: r.update(shutdown_errors=['failed cleanup']),
        ):
            changed = copy.deepcopy(report)
            mutation(changed)
            with self.assertRaises(AssertionError):
                fixture.validate_teardown(changed)

    def report(self):
        return dict(daemon_shutdown=shutdown_observation(100, 100), quit_flushed=True,
                    socket_removed=True, shutdown_errors=[], actors_shutdown=[shutdown_observation()])

    def test_missing_false_timeout_or_error_precontainment_never_qualifies(self):
        for target in ('daemon_shutdown', 'actor'):
            for field in ('missing', 'stdin_closed', 'wrapper_waited', 'pid_absent',
                          'actor_pid_absent', 'group_absent', 'timed_out', 'errors', 'wrapper_returncode'):
                report = self.report()
                row = report['actors_shutdown'][0] if target == 'actor' else report[target]
                if field == 'missing':
                    del row['before_containment']
                else:
                    row['before_containment'][field] = ({'timed_out': True, 'errors': ['probe failed'],
                        'wrapper_returncode': 1}.get(field, False))
                with self.subTest(target=target, field=field), self.assertRaises((AssertionError, KeyError, TypeError)):
                    fixture.validate_teardown(report)

    def test_unrecorded_sigkill_status_never_qualifies(self):
        for code in (-9, 137):
            report = self.report()
            report['actors_shutdown'][0] = shutdown_observation(returncode=code)
            with self.subTest(code=code), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.validate_teardown(report)

    def test_final_pid_actor_or_group_absence_also_required(self):
        for target in ('daemon_shutdown', 'actor'):
            for field in ('pid_absent', 'actor_pid_absent', 'group_absent'):
                report = self.report()
                row = report['actors_shutdown'][0] if target == 'actor' else report[target]
                row[field] = False
                with self.subTest(target=target, field=field), self.assertRaises((AssertionError, KeyError, TypeError)):
                    fixture.validate_teardown(report)

    def death_report(self, code=137):
        report = self.report()
        row = shutdown_observation(returncode=code)
        identity = row['identity']
        identity.update(uid=1101, gid=1101, proc_status='Uid:\t1101\t1101\t1101\t1101\nGid:\t1101\t1101\t1101\t1101\n')
        operation = dict(identity=copy.deepcopy(identity), current_identity=copy.deepcopy(identity), wrapper_pid=row['pid'], signal=9,
                         method='pidfd_send_signal', identity_checked=True, signal_sent=True,
                         actor_dead_pidfd=True, actor_proc_absent=True, wrapper_exit=code)
        victim = copy.deepcopy(identity)
        death = dict(operation=copy.deepcopy(operation), actual_actor_pid=identity['pid'], signal=9,
                     actor_dead_pidfd=True, actor_proc_absent=True, wrapper_exit=code,
                     before=dict(active=[dict(identity=victim)]))
        report.update(deliberate_deaths=[operation], outcomes=dict(global_names=dict(death=death)))
        report['actors_shutdown'] = [row, shutdown_observation(201, 301)]
        return report

    def test_exact_recorded_pidfd_victim_exception(self):
        for code in (-9, 137):
            fixture.validate_teardown(self.death_report(code))

    def test_sigkill_exception_cannot_transfer_to_other_actor_or_incarnation(self):
        mutations = (
            lambda r: r['actors_shutdown'][1].update(returncode=137, before_containment=dict(r['actors_shutdown'][1]['before_containment'], wrapper_returncode=137)),
            lambda r: r['actors_shutdown'][0]['identity'].update(starttime_ticks=124),
            lambda r: r['actors_shutdown'][0]['identity'].update(wrapper_starttime_ticks=124),
            lambda r: r['actors_shutdown'][0].update(pid=999),
            lambda r: r['deliberate_deaths'][0].update(method='kill'),
            lambda r: r['deliberate_deaths'][0].update(identity_checked=False),
            lambda r: r['deliberate_deaths'][0].update(signal_sent=False),
            lambda r: r['deliberate_deaths'][0].update(actor_dead_pidfd=False),
            lambda r: r['deliberate_deaths'][0].update(actor_proc_absent=False),
            lambda r: r['outcomes']['global_names']['death'].update(actual_actor_pid=999),
            lambda r: r['outcomes']['global_names']['death']['before']['active'][0]['identity'].update(uid=1100),
            lambda r: r['outcomes']['global_names']['death'].update(wrapper_exit=0),
            lambda r: r['actors_shutdown'][0].update(returncode=0, before_containment=dict(r['actors_shutdown'][0]['before_containment'], wrapper_returncode=0)),
        )
        for index, mutation in enumerate(mutations):
            report = self.death_report()
            mutation(report)
            with self.subTest(mutation=index), self.assertRaises((AssertionError, KeyError, TypeError)):
                fixture.validate_teardown(report)


class CleanupAcceptance(unittest.TestCase):
    def controlled_stop(self, retained=False, timeout=False, probe_error=False):
        """Execute the actual helper body against inert process/clock witnesses."""
        events, ticks = [], [0]
        state = dict(contained=False)
        def now():
            ticks[0] += 0.25
            return ticks[0]
        def exists(path):
            events.append(('probe', path))
            return retained and not state['contained'] and path == '/proc/300'
        def group(pid, code):
            events.append(('group', pid, code))
            if probe_error and not state['contained']:
                raise PermissionError('controlled probe error')
            if retained and not state['contained']:
                return
            raise ProcessLookupError()
        def wait(timeout):
            events.append(('wait', timeout))
            if timeout == 5 and timeout_error:
                raise subprocess.TimeoutExpired('inert wrapper', timeout)
            return 0
        timeout_error = timeout
        def contain():
            events.append(('contain_and_drain',))
            state['contained'] = True
            return dict(pid=200, method='eof', returncode=0, raw_logs_drained=True)
        channel = SimpleNamespace(process=SimpleNamespace(pid=200,
            stdin=SimpleNamespace(close=lambda: events.append(('stdin_closed',))), wait=wait), stop=contain)
        tree = ast.parse(Path(fixture.stop_channel.__code__.co_filename).read_text())
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'stop_channel')
        namespace = dict(time=SimpleNamespace(monotonic=now), subprocess=subprocess,
                         os=SimpleNamespace(killpg=group),
                         Path=lambda *parts: SimpleNamespace(exists=lambda: exists('/'.join(parts))))
        exec(compile(ast.Module(body=[node], type_ignores=[]), '<actual-stop-channel-inert>', 'exec'), namespace)
        result = namespace['stop_channel'](channel, dict(pid=300))
        return result, events

    def test_actual_helper_observes_retirement_before_containment_and_drains(self):
        result, events = self.controlled_stop()
        self.assertEqual(events[:2], [('stdin_closed',), ('wait', 5)])
        containment = events.index(('contain_and_drain',))
        self.assertIn(('probe', '/proc/200'), events[:containment])
        self.assertIn(('probe', '/proc/300'), events[:containment])
        self.assertIn(('group', 200, 0), events[:containment])
        self.assertTrue(result['raw_logs_drained'])
        before = result['before_containment']
        self.assertTrue(all(before[key] for key in ('stdin_closed', 'wrapper_waited', 'pid_absent', 'actor_pid_absent', 'group_absent')))
        self.assertFalse(before['timed_out'])
        self.assertEqual(before['errors'], [])

    def test_fallback_final_absence_cannot_erase_retained_actor_or_group(self):
        result, _ = self.controlled_stop(retained=True)
        self.assertFalse(result['before_containment']['actor_pid_absent'])
        self.assertFalse(result['before_containment']['group_absent'])
        self.assertTrue(result['actor_pid_absent'] and result['group_absent'])

    def test_wait_timeout_and_probe_error_remain_recorded_with_drains(self):
        for kwargs in (dict(timeout=True), dict(probe_error=True)):
            result, events = self.controlled_stop(**kwargs)
            self.assertIn(('contain_and_drain',), events)
            self.assertTrue(result['before_containment']['timed_out'] or result['before_containment']['errors'])


class DeathOperationAcceptance(unittest.TestCase):
    def operation(self, drift=False):
        """Replay only the real recorded death callsite; no live PID/FD exists."""
        source = Path(fixture.__file__).read_text()
        begin = source.index('                    operation = dict(identity=shutdown_identities')
        end = source.index('                    death_after = settle()', begin)
        import textwrap
        code = textwrap.dedent(source[begin:end])
        events = []
        identity = dict(pid=300, uid=1101, gid=1101, starttime_ticks=123,
                        wrapper_pid=200, wrapper_starttime_ticks=122, pgid=200)
        channel = SimpleNamespace(process=SimpleNamespace(pid=200, returncode=137,
            wait=lambda timeout: events.append(('wait', timeout))))
        target = dict(channel=channel, identity=identity)
        actual = dict(identity, starttime_ticks=124) if drift else identity
        report = dict(deliberate_deaths=[])
        namespace = dict(target=target, actor_pid=300,
            report=report, active=[target], death_before=dict(active=[dict(identity=identity)]),
            accepted_identity=lambda *args, **kwargs: actual,
            os=SimpleNamespace(pidfd_open=lambda pid: events.append(('open', pid)) or 99,
                               close=lambda fd: events.append(('close', fd))),
            signal=SimpleNamespace(SIGKILL=9, pidfd_send_signal=lambda fd, sig: events.append(('signal', fd, sig))),
            select=SimpleNamespace(select=lambda fds, *_: events.append(('select', fds)) or ([99], [], [])),
            remaining=lambda deadline: 1, time=SimpleNamespace(monotonic=lambda: 10),
            Path=lambda path: SimpleNamespace(exists=lambda: False))
        # The inert channel is deliberately unhashable; bind it without a live process.
        class Identities:
            def __getitem__(self, value):
                assert value is channel
                return identity
        namespace['shutdown_identities'] = Identities()
        try:
            exec(compile(code, '<actual-death-operation-inert>', 'exec'), namespace)
        except AssertionError:
            if not drift:
                raise
        return report, events

    def test_pidfd_signal_is_recorded_for_checked_victim_and_reaped_wrapper(self):
        report, events = self.operation()
        self.assertEqual(events, [('open', 300), ('signal', 99, 9), ('select', [99]), ('close', 99), ('wait', 1)])
        operation = report['deliberate_deaths'][0]
        self.assertTrue(operation['identity_checked'] and operation['signal_sent'] and operation['actor_dead_pidfd'] and operation['actor_proc_absent'])
        self.assertEqual(operation['wrapper_exit'], 137)

    def test_incarnation_drift_refuses_signal_and_closes_pidfd(self):
        report, events = self.operation(drift=True)
        self.assertEqual(events, [('open', 300), ('close', 99)])
        self.assertFalse(report['deliberate_deaths'][0]['identity_checked'])
        self.assertFalse(report['deliberate_deaths'][0]['signal_sent'])


class WitnessRecoveryAcceptance(unittest.TestCase):
    """Actual helper/callsite bodies with inert /proc, pidfd and wait witnesses."""
    fields = ('pid', 'uid', 'gid', 'starttime_ticks', 'wrapper_pid', 'wrapper_starttime_ticks', 'pgid')

    def replay(self, status=None, drift=None, missing=None, victim_drift=None, victim_missing=None):
        events = []
        launch_status = 'Uid:\t1101\t1101\t1101\t1101\nGid:\t1101\t1101\t1101\t1101\n'
        identity = dict(pid=300, uid=1101, gid=1101, proc_status=launch_status,
                        starttime_ticks=123, wrapper_pid=200, wrapper_starttime_ticks=122, pgid=200)
        channel = SimpleNamespace(process=SimpleNamespace(pid=200, returncode=137,
            wait=lambda timeout: events.append(('wait', timeout))))
        target = dict(channel=channel, identity=dict(identity), unique=':1.2')
        victim = dict(identity)
        if victim_drift:
            victim[victim_drift] += 1
        if victim_missing:
            del victim[victim_missing]
        class Identities:
            def __getitem__(self, value):
                assert value is channel
                return identity
        def read(parts):
            path = '/'.join(map(str, parts))
            events.append(('read', path))
            if missing == path:
                raise FileNotFoundError('inert missing proc witness')
            if path == '/proc/300/status':
                if isinstance(status, Exception):
                    raise status
                return launch_status + 'Name:\tcurrent-actor\n' if status is None else status
            pid = int(parts[1])
            fields = ['0'] * 20
            fields[0], fields[2], fields[19] = 'S', '200', str(123 if pid == 300 else 122)
            if drift == 'starttime_ticks' and pid == 300 or drift == 'wrapper_starttime_ticks' and pid == 200:
                fields[19] = '999'
            if drift == 'pgid' and pid == 300:
                fields[2] = '999'
            return str(pid) + ' (inert witness) ' + ' '.join(fields)
        namespace = dict(target=target, actor_pid=300, report=dict(deliberate_deaths=[]), active=[target],
            death_before=dict(active=[dict(identity=victim)]), shutdown_identities=Identities(),
            validate_identity=fixture.validate_identity,
            os=SimpleNamespace(pidfd_open=lambda pid: events.append(('open', pid)) or 99,
                               close=lambda fd: events.append(('close', fd))),
            signal=SimpleNamespace(SIGKILL=9, pidfd_send_signal=lambda fd, sig: events.append(('signal', fd, sig))),
            select=SimpleNamespace(select=lambda fds, *_: ([99], [], [])),
            remaining=lambda deadline: 1, time=SimpleNamespace(monotonic=lambda: 10),
            Path=lambda *parts: SimpleNamespace(read_text=lambda: read(parts), exists=lambda: False))
        source = Path(fixture.__file__).read_text()
        main = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        helper = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == 'accepted_identity')
        exec(compile(ast.Module(body=[helper], type_ignores=[]), '<actual-identity-helper-inert>', 'exec'), namespace)
        begin = source.index('                    operation = dict(identity=shutdown_identities')
        end = source.index('                    death_after = settle()', begin)
        import textwrap
        error = None
        try:
            exec(compile(textwrap.dedent(source[begin:end]), '<actual-witness-death-inert>', 'exec'), namespace)
        except (AssertionError, KeyError, TypeError, ValueError, StopIteration, OSError) as caught:
            error = caught
        return namespace['report']['deliberate_deaths'][0], events, error

    def assert_refused(self, **kwargs):
        operation, events, error = self.replay(**kwargs)
        self.assertIsNotNone(error, 'missing/drifting witness accepted by actual helper/callsite')
        self.assertFalse(operation['identity_checked'])
        self.assertFalse(operation['signal_sent'])
        self.assertNotIn(('signal', 99, 9), events)
        self.assertIn(('close', 99), events)
        self.assertFalse(any(event[0] == 'wait' for event in events))

    def test_current_credentials_observed_before_signal_with_volatile_status_allowed(self):
        operation, events, error = self.replay()
        self.assertIsNone(error)
        self.assertIn(('read', '/proc/300/status'), events)
        self.assertLess(events.index(('read', '/proc/300/status')), events.index(('signal', 99, 9)))
        self.assertTrue(operation['identity_checked'] and operation['signal_sent'])
        self.assertIn('Name:\tcurrent-actor', operation['current_identity']['proc_status'])

    def test_each_current_kernel_uid_gid_field_drift_refuses_signal(self):
        for field in ('Uid:', 'Gid:'):
            for index in range(4):
                values = [1101] * 4
                values[index] = 1100
                status = ''.join(key + '\t' + '\t'.join(map(str, values if key == field else [1101] * 4)) + '\n'
                                 for key in ('Uid:', 'Gid:'))
                with self.subTest(field=field, index=index):
                    self.assert_refused(status=status)

    def test_current_credentials_missing_malformed_or_read_error_refuses_signal(self):
        for status in ('', 'Uid:\t1101\t1101\t1101\t1101\n',
                       'Uid:\t1101\nGid:\t1101\n', 'Uid:\tbad\nGid:\tbad\n',
                       PermissionError('inert credential read denied')):
            with self.subTest(status=repr(status)):
                self.assert_refused(status=status)
        self.assert_refused(missing='/proc/300/status')

    def test_current_actor_wrapper_group_drift_or_missing_refuses_signal(self):
        for field in ('starttime_ticks', 'wrapper_starttime_ticks', 'pgid'):
            with self.subTest(field=field):
                self.assert_refused(drift=field)
        for path in ('/proc/300/stat', '/proc/200/stat'):
            with self.subTest(path=path):
                self.assert_refused(missing=path)

    def test_predeath_victim_incarnation_drift_or_missing_refuses_signal(self):
        for field in self.fields:
            for mutation in ('victim_drift', 'victim_missing'):
                with self.subTest(field=field, mutation=mutation):
                    self.assert_refused(**{mutation: field})

    def enriched_report(self):
        report = TeardownAcceptance().death_report()
        operation = report['deliberate_deaths'][0]
        operation['identity']['proc_status'] = 'Uid:\t1101\t1101\t1101\t1101\nGid:\t1101\t1101\t1101\t1101\n'
        operation['current_identity'] = copy.deepcopy(operation['identity'])
        report['actors_shutdown'][0]['identity'] = copy.deepcopy(operation['identity'])
        death = report['outcomes']['global_names']['death']
        death['operation'] = copy.deepcopy(operation)
        death['before']['active'][0]['identity'] = copy.deepcopy(operation['identity'])
        return report

    def test_retirement_requires_all_predeath_incarnation_fields(self):
        fixture.validate_teardown(self.enriched_report())
        for field in self.fields[3:]:
            for missing in (True, False):
                report = self.enriched_report()
                victim = report['outcomes']['global_names']['death']['before']['active'][0]['identity']
                if missing:
                    del victim[field]
                else:
                    victim[field] += 1
                with self.subTest(field=field, missing=missing), self.assertRaises((AssertionError, KeyError, TypeError)):
                    fixture.validate_teardown(report)

    def test_retirement_requires_current_credential_and_incarnation_witness(self):
        for field in ('missing', 'proc_status') + self.fields:
            report = self.enriched_report()
            operation = report['deliberate_deaths'][0]
            if field == 'missing':
                del operation['current_identity']
            elif field == 'proc_status':
                operation['current_identity'][field] = 'Uid:\t1100\t1100\t1100\t1100\nGid:\t1101\t1101\t1101\t1101\n'
            else:
                operation['current_identity'][field] += 1
            report['outcomes']['global_names']['death']['operation'] = copy.deepcopy(operation)
            with self.subTest(field=field), self.assertRaises((AssertionError, KeyError, TypeError, StopIteration)):
                fixture.validate_teardown(report)

    def test_public_snapshot_retains_saved_incarnation_without_proc_reads(self):
        original = dict(pid=300, uid=1101, gid=1101, proc_status='saved launch status', custom='original field')
        saved = dict(original, starttime_ticks=123, wrapper_pid=200, wrapper_starttime_ticks=122, pgid=200)
        namespace = dict(active=[dict(channel='inert', identity=original, unique=':1.2')],
                         shutdown_identities={'inert': saved})
        main = next(node for node in ast.parse(Path(fixture.__file__).read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'main')
        helper = next(node for node in main.body if isinstance(node, ast.FunctionDef) and node.name == 'public_active')
        exec(compile(ast.Module(body=[helper], type_ignores=[]), '<actual-public-active-inert>', 'exec'), namespace)
        self.assertEqual(namespace['public_active'](), [dict(identity=saved, unique=':1.2')])
        self.assertNotIn('starttime_ticks', original)


class ArtifactModeAcceptance(unittest.TestCase):
    def test_nix_readonly_normalization_retains_source_executable_bit(self):
        for source, stored in ((0o644, 0o444), (0o755, 0o555)):
            result = fixture.validate_artifact_mode(source, SimpleNamespace(st_mode=stat.S_IFREG | stored))
            self.assertEqual(result, dict(source_mode=source, expected_store_mode=stored, actual_store_mode=stored))

    def test_writable_execute_bit_symlink_and_nonregular_drift_fail(self):
        for source, mode in ((0o644, stat.S_IFREG | 0o644), (0o755, stat.S_IFREG | 0o755),
                             (0o644, stat.S_IFREG | 0o555), (0o755, stat.S_IFREG | 0o444),
                             (0o644, stat.S_IFLNK | 0o444), (0o644, stat.S_IFDIR | 0o444)):
            with self.subTest(source=source, mode=mode), self.assertRaises(AssertionError):
                fixture.validate_artifact_mode(source, SimpleNamespace(st_mode=mode))


if __name__ == '__main__':
    unittest.main()
