"""Data-only D286 regressions. No sockets, pipes, children, or host probes."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from scripts.foundation.pro01_reference_fd_splits import actor as fixture
from scripts.foundation.pro01_reference_fd_splits import run as runner
from apps.gao_bus.test.fixtures import transport_actor as wire


def sends(mode='rights_at_split', split=17):
    rows = []
    for data, controls in fixture.placement(mode, split):
        rows.append(dict(direction='send', role='source-0', method='sendmsg' if controls else 'send',
                         hex=data.hex(), requested_hex=data.hex(), requested=len(data),
                         count=len(data), controls=[dict(level=1, kind=1, hex='0300000004000000',
                         fds=[3, 4], identities=['pipe:[11]', 'pipe:[12]'])] if controls else [],
                         monotonic=1., completed=1.01, outcome='sent'))
    return rows


def receipt(serial, source, identities, payloads):
    ids = identities
    body = {10: wire.u32(1) + wire.u32(0), 11: wire.u32(0) + wire.u32(1), 12: b''}[serial]
    fields = {1: '/foundation', 2: 'org.foundation.Transport', 3: 'Resource',
              6: ':1.2', 7: source, 8: 'hh' if ids else ''}
    if ids:
        fields[9] = 2
    raw = wire.frame(4, serial, [(key, {1:'o', 2:'s', 3:'s', 6:'s', 7:'s', 8:'g', 9:'u'}[key], value)
                               for key, value in fields.items()], body)
    return dict(type=4, serial=serial, fields=fields, body=body.hex(), wire_hex=raw.hex(),
                identities=ids, payloads=payloads)


def triplet():
    bundles = [dict(identities=['pipe:[11]', 'pipe:[12]'], payloads=['6130', '6131']),
               dict(identities=['pipe:[13]', 'pipe:[14]'], payloads=['6230', '6231'])]
    return bundles, [receipt(10, ':1.1', **bundles[0]), receipt(11, ':1.1', **bundles[1]),
                     receipt(12, ':1.1', [], [])]


def launch_evidence(successful=True):
    """Synthetic saved-event timeline; no Role instances or operating-system calls."""
    events, identities, now = [], {}, 10.

    def at():
        nonlocal now
        now += .01
        return now

    def launch(name, number):
        identity = dict(pid=100 + number, starttime_ticks=1000 + number)
        identities[name] = identity
        began, completed = at(), at()
        events.append(dict(event='role_launch', role=name, **identity, started=began,
                           completed=completed, deadline=completed + 3))

    def activate(name):
        launched = next(e for e in events if e['event'] == 'role_launch' and e['role'] == name)
        identity = identities[name]
        requested, accepted = at(), at()
        events.append(dict(event='role_open_request', role=name, **identity,
                           requested=requested, deadline=launched['deadline'], command='open'))
        events.append(dict(event='role_open_gate', role=name, **identity,
                           accepted=accepted, deadline=launched['deadline'], command='open',
                           client_created=False, resource_fds=0))
        connection = dict(identity, fd=7, inode=10000 + identity['pid'])
        events.append(dict(event='connection', role=name, connection=connection))
        events.append(dict(event='registered', role=name, connection=connection))
        events.append(dict(event='role_process', role=name, **identity,
                           opened_completed=at(), deadline=launched['deadline']))

    def shutdown(name, normal, deadline=None):
        began, finished = at(), at()
        events.append(dict(event='role_shutdown', role=name, **identities[name], normal=normal,
                           started=began, finished=finished, seconds=finished - began,
                           deadline=deadline if deadline is not None else began + 5,
                           returncode=0 if normal else -15, pid_absent=True,
                           stdout_tail='', stderr_tail='', failure=None))

    launch('source-0', 0)
    activate('source-0')
    launch('target', 1)
    activate('target')
    if not successful:
        launch('source-1', 2)
        began = at()
        deadline = began + 5
        events.append(dict(event='failure_cleanup', started=began, deadline=deadline))
        for name in ('source-1', 'source-0', 'target'):
            shutdown(name, False, deadline)
        return events
    for index in range(286):
        name = fixture.role(index)
        if index < 285:
            launch(fixture.role(index + 1), index + 2)
        shutdown(name, True)
        observer_health, target_health = at(), at()
        events.append(dict(event='case', index=index, source_role=name,
                           connection=dict(identities[name], fd=7, inode=10000 + identities[name]['pid']),
                           after_health=dict(finished=observer_health), target_health=dict(finished=target_health)))
        events.append(dict(event='case_retired', role=name, index=index, **identities[name], finished=at()))
        if index < 285:
            activate(fixture.role(index + 1))
    shutdown('target', True)
    return events


class LaunchTests(unittest.TestCase):
    def rejected(self, events, successful=True):
        with self.assertRaises(AssertionError):
            runner.validate_launch_order(events, successful=successful)

    def test_accepts_one_pending_exec_and_exact_286_retired_sources(self):
        result = runner.validate_launch_order(launch_evidence(), successful=True)
        self.assertEqual(result['launched'], 287)
        self.assertEqual(result['opened'], 287)
        self.assertEqual(result['retired'], 286)

    def test_rejects_connection_before_open_duplicate_wrong_open_and_pid(self):
        for mutation in ('before', 'duplicate', 'wrong', 'pid', 'starttime', 'resource'):
            events = launch_evidence()
            request = next(e for e in events if e['event'] == 'role_open_request' and e['role'] == 'source-1')
            gate = next(e for e in events if e['event'] == 'role_open_gate' and e['role'] == 'source-1')
            if mutation == 'before':
                connection = next(e for e in events if e['event'] == 'connection' and e['role'] == 'source-1')
                events.remove(connection)
                events.insert(events.index(request), connection)
            elif mutation == 'duplicate': events.insert(events.index(request), copy.deepcopy(request))
            elif mutation == 'wrong': gate['command'] = 'prefix'
            elif mutation == 'pid': gate['pid'] += 1
            elif mutation == 'starttime': gate['starttime_ticks'] += 1
            else: gate['resource_fds'] = 1
            with self.subTest(mutation=mutation): self.rejected(events)

    def test_rejects_early_activation_two_pending_and_leftover_pending(self):
        for mutation in ('early', 'two', 'leftover'):
            events = launch_evidence()
            if mutation == 'early':
                opened = [e for e in events if e.get('role') == 'source-1' and e['event'] in
                          ('role_open_request', 'role_open_gate', 'connection', 'registered', 'role_process')]
                for e in opened: events.remove(e)
                index = next(i for i,e in enumerate(events) if e['event'] == 'case_retired')
                events[index:index] = opened
            elif mutation == 'two':
                launched = next(e for e in events if e['event'] == 'role_launch' and e['role'] == 'source-2')
                events.remove(launched)
                index = next(i for i,e in enumerate(events) if e['event'] == 'role_launch' and e['role'] == 'source-1')
                events.insert(index + 1, launched)
            else:
                events.append(dict(event='role_launch', role='source-286', pid=999, starttime_ticks=999,
                                   started=50., completed=50.01, deadline=53.01))
            with self.subTest(mutation=mutation): self.rejected(events)

    def test_rejects_restarted_or_expired_original_launch_deadline(self):
        for mutation in ('restart', 'expired', 'late_completion'):
            events = launch_evidence()
            launched = next(e for e in events if e['event'] == 'role_launch' and e['role'] == 'source-1')
            request = next(e for e in events if e['event'] == 'role_open_request' and e['role'] == 'source-1')
            gate = next(e for e in events if e['event'] == 'role_open_gate' and e['role'] == 'source-1')
            if mutation == 'restart':
                request['deadline'] = gate['deadline'] = request['requested'] + 3
            elif mutation == 'expired':
                gate['accepted'] = launched['deadline'] + .01
            else:
                opened = next(e for e in events if e['event'] == 'role_process' and e['role'] == 'source-1')
                opened['opened_completed'] = launched['deadline'] + .01
            with self.subTest(mutation=mutation): self.rejected(events)

    def test_failed_execution_requires_pending_active_target_shared_cleanup(self):
        events = launch_evidence(successful=False)
        result = runner.validate_launch_order(events, successful=False)
        self.assertEqual(result['launched'], 3)
        self.assertEqual(result['opened'], 2)
        for mutation in ('missing_pending', 'deadline', 'late', 'alive'):
            bad = copy.deepcopy(events)
            pending = next(e for e in bad if e['event'] == 'role_shutdown' and e['role'] == 'source-1')
            if mutation == 'missing_pending': bad.remove(pending)
            elif mutation == 'deadline': pending['deadline'] += 1
            elif mutation == 'late': pending['finished'] = pending['deadline'] + .01
            else: pending['pid_absent'] = False
            with self.subTest(mutation=mutation): self.rejected(bad, successful=False)


class DataTests(unittest.TestCase):
    def test_literal_and_all_286_placements(self):
        self.assertEqual([len(v) for v in fixture.vectors()], [144, 144, 128])
        self.assertEqual(hashlib.sha256(fixture.FIRST).hexdigest(), fixture.FIRST_SHA256)
        for mode, split in fixture.selection():
            rows = sends(mode, split)
            fixture.validate_placement(rows, mode, split, ['pipe:[11]', 'pipe:[12]'])
            self.assertEqual(b''.join(bytes.fromhex(row['hex']) for row in rows), fixture.FIRST[:split])

    def test_census_rejects_missing_duplicate_reordered_out_of_range_failed(self):
        cases = [dict(mode=mode, split=split, result='PASS') for mode, split in fixture.selection()]
        fixture.validate_cases(cases)
        wrong = copy.deepcopy(cases)
        wrong[0]['split'] = 0
        failed = copy.deepcopy(cases)
        failed[-1]['result'] = 'FAIL'
        for rows in (cases[:-1], cases + cases[:1], cases[1:2] + cases[:1] + cases[2:], wrong, failed):
            with self.assertRaises(AssertionError):
                fixture.validate_cases(rows)

    def test_short_send_reconstruction_and_controls(self):
        rows = sends('rights_with_prefix', 17)
        first = rows[0]
        first.update(hex=fixture.FIRST[:5].hex(), count=5)
        remainder = dict(first, method='send', controls=[], hex=fixture.FIRST[5:17].hex(),
                         requested_hex=fixture.FIRST[5:17].hex(), requested=12, count=12)
        rows.append(remainder)
        fixture.validate_placement(rows, 'rights_with_prefix', 17, ['pipe:[11]', 'pipe:[12]'])
        for field, value in [('hex', 'ff'), ('count', 99), ('controls', [])]:
            bad = copy.deepcopy(rows)
            bad[0][field] = value
            with self.assertRaises(AssertionError):
                fixture.validate_placement(bad, 'rights_with_prefix', 17, ['pipe:[11]', 'pipe:[12]'])

    def test_barrier_identity_deadline_unchanged_sendmsg_and_fd_inventory(self):
        trace = sends()
        identity = dict(pid=123, starttime_ticks=456, fd=7, inode=890)
        def sample(at):
            return dict(connection=identity, live=True, success=True, sole_writer=True,
                        duplicated_connection=False, error=None, units='transmit allocation accounting',
                        allocation=0, ioctl=21521, kernel='offline', send_trace=fixture.send_signature(trace),
                        started=at, finished=at + .01)
        baseline = {'3': 'socket:[9]'}
        held = dict(started=1.2, finished=1.21, fds=dict(baseline, **{'4':'pipe:[11]', '5':'pipe:[12]'}),
                    fdinfo={'4':dict(flags=0o2000000, raw='flags:\t02000000\nino:\t11\n'),
                            '5':dict(flags=0o2000000, raw='flags:\t02000000\nino:\t12\n')})
        barrier = dict(started=1.02, first=sample(1.03), health=dict(started=1.05, finished=1.1),
                       second=sample(1.3), inventory=held, fences=[dict(started=1.15, finished=1.16,
                       pending=False, connection=dict(pid=321, starttime_ticks=654, fd=8, inode=900))], finished=1.32)
        fixture.validate_hold(barrier, identity, trace, 21521, 'offline', baseline, ['pipe:[11]', 'pipe:[12]'])
        for mutation in ('identity', 'late', 'sendmsg', 'fd', 'cloexec', 'pending'):
            bad = copy.deepcopy(barrier)
            if mutation == 'identity': bad['second']['connection']['inode'] += 1
            elif mutation == 'late': bad['finished'] = 2.02
            elif mutation == 'sendmsg': bad['second']['send_trace']['events'] += 1
            elif mutation == 'fd': bad['inventory']['fds']['6'] = 'pipe:[11]'
            elif mutation == 'cloexec': bad['inventory']['fdinfo']['4']['flags'] = 0
            else: bad['fences'][0]['pending'] = True
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                fixture.validate_hold(bad, identity, trace, 21521, 'offline', baseline, ['pipe:[11]', 'pipe:[12]'])

    def test_exact_receipt_order_fields_body_resources_payloads(self):
        bundles, rows = triplet()
        fixture.validate_receipts(rows, ':1.1', bundles)
        for mutation in ('order', 'body', 'ids', 'payload', 'path', 'interface', 'tail'):
            bad = copy.deepcopy(rows)
            if mutation == 'order': bad.reverse()
            elif mutation == 'body': bad[0]['body'] = '0000000001000000'
            elif mutation == 'ids': bad[0]['identities'].reverse()
            elif mutation == 'payload': bad[0]['payloads'][0] = '00'
            elif mutation == 'path': bad[0]['fields'][1] = '/wrong'
            elif mutation == 'interface': bad[0]['fields'][2] = 'wrong.Interface'
            else: bad[-1]['identities'] = ['pipe:[99]']
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                fixture.validate_receipts(bad, ':1.1', bundles)

    def test_raw_receive_and_ancillary_evidence_are_required(self):
        _, rows = triplet()
        raw = []
        for index, row in enumerate(rows):
            ids = row['identities']
            raw.append(dict(direction='receive', role='target', hex=row['wire_hex'], requested=1024,
                            flags=0, monotonic=index, completed=index + .01,
                            controls=[dict(level=1, kind=1, hex='0300000004000000', fds=[3,4],
                                           identities=ids)] if ids else []))
        fixture.validate_stream(raw, b'', rows)
        for mutation in ('missing', 'corrupt', 'rights', 'ids', 'control_bytes', 'extra'):
            bad = copy.deepcopy(raw)
            if mutation == 'missing': bad.pop(0)
            elif mutation == 'corrupt': bad[0]['hex'] = 'ff' + bad[0]['hex'][2:]
            elif mutation == 'rights': bad[0]['controls'] = []
            elif mutation == 'ids': bad[0]['controls'][0]['identities'].reverse()
            elif mutation == 'control_bytes': bad[0]['controls'][0]['hex'] = '00'
            else: bad.append(copy.deepcopy(bad[-1]))
            with self.subTest(mutation=mutation), self.assertRaises((AssertionError, ValueError)):
                fixture.validate_stream(bad, b'', rows)

    def test_cleanup_requires_normal_exit_absence_and_private_paths_removed(self):
        report = dict(status='passed', actor_returncode=0, failures=[], socket_removed=True,
                      socket_parent_removed=True, cleanup_seconds=.1,
                      cleanup=[dict(role='actor', returncode=0, pid_absent=True),
                               dict(role='reference', returncode=0, pid_absent=True)])
        runner.validate_cleanup(report)
        for key, value in [('actor_returncode', 1), ('socket_removed', False), ('socket_parent_removed', False),
                           ('cleanup_seconds', 5.1), ('failures', ['containment'])]:
            bad = copy.deepcopy(report)
            bad[key] = value
            with self.assertRaises(AssertionError): runner.validate_cleanup(bad)


if __name__ == '__main__':
    unittest.main()
