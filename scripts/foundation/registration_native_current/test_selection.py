"""Pure controls over extracted SEC16 request/snapshot/settle bodies; no actors."""
import ast
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest

import selection

ORIGINAL = Path('/nix/store/hdh2s37zn69svyv4jdbx130drcack5zf-osbus-registration-original-fixtures/run.py')


def projected_source():
    source = ORIGINAL.read_text()
    for old, new in selection.PATCHES['run.py']:
        assert source.count(old) == 1 and new not in source
        source = source.replace(old, new)
    return source


def function(source, name):
    matches = [node for node in ast.walk(ast.parse(source))
               if isinstance(node, ast.FunctionDef) and node.name == name]
    assert len(matches) == 1
    return matches[0]


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now


class Channel:
    def __init__(self, clock, durations, ok=True):
        self.clock, self.durations, self.ok = clock, iter(durations), ok
        self.commands, self.timeouts = [], []
        self.serial = 0

    def begin(self, **command):
        self.commands.append(command)
        if command['op'] == 'call':
            self.serial += 1

    def read(self, timeout):
        self.timeouts.append(timeout)
        self.clock.now += next(self.durations)
        bodies = dict(ListNames=[['org.observer']], GetNameOwner=[':1.1'],
                      GetConnectionUnixUser=[1100], GetConnectionUnixProcessID=[42],
                      GetId=['bus-id'])
        member = self.commands[-1].get('member')
        return dict(ok=self.ok, result=dict(reply_serial=self.serial,
                    sender='org.freedesktop.DBus', body=bodies.get(member, [])), wire=[])


class Harness:
    def __init__(self, source, durations, persistence=2.0, ok=True, deadline=60.0):
        self.clock = Clock()
        self.channel = Channel(self.clock, durations, ok)
        self.saved = []
        self.current = dict(receipts=[], snapshots=[], snapshot_records=[],
                            process_samples=[], daemon_events=[], settles=[],
                            daemon=dict(identity=dict(pid=43, uid=0, gid=0)))
        self.worker = dict(channel=self.channel, serial=0,
                           public=dict(identity=dict(pid=42, uid=1100, gid=1100), unique=':1.1'))

        def persist():
            self.clock.now += persistence
            self.saved.append(copy.deepcopy(self.current))

        def process_sample(identity):
            value = dict(identity=identity, complete=True)
            self.current['process_samples'].append(copy.deepcopy(value))
            return value

        def native_snapshot(limit):
            value = dict(event='snapshot', peers=[], names=[], queues=[], usage={})
            self.current['daemon_events'].append(copy.deepcopy(value))
            return value

        self.namespace = dict(time=self.clock, deadline=deadline, current=self.current,
            persist=persist, copy=copy, process_sample=process_sample,
            native_snapshot=native_snapshot, OBSERVER='org.observer', BUS='org.freedesktop.DBus',
            endpoint=SimpleNamespace(stat=lambda: SimpleNamespace(st_ino=7, st_dev=8)),
            validate_observer=lambda value, public: None)
        nodes = [function(source, name) for name in ('remaining', 'request', 'call', 'snapshot', 'settle')]
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(ORIGINAL), 'exec'), self.namespace)

    def request(self, limit=None, op='call'):
        return self.namespace['request'](self.worker, limit=limit, op=op)

    def settle(self):
        return self.namespace['settle'](self.worker)


class ReportingCheckpointControls(unittest.TestCase):
    def test_timely_response_does_not_charge_synchronous_reporting(self):
        harness = Harness(projected_source(), [0.005])
        response = harness.request()
        self.assertTrue(response['ok'])
        self.assertAlmostEqual(harness.current['receipts'][0]['elapsed_ms'], 5)
        self.assertEqual(harness.saved, [])
        self.assertAlmostEqual(harness.clock.now, 0.005)

    def test_original_request_reproduces_reporting_deadline_failure(self):
        harness = Harness(ORIGINAL.read_text(), [0.005])
        with self.assertRaisesRegex(AssertionError, 'SEC16 request exceeded fixed caller deadline'):
            harness.request()
        self.assertTrue(harness.current['receipts'][0]['response']['ok'])
        self.assertAlmostEqual(harness.current['receipts'][0]['elapsed_ms'], 5)
        self.assertEqual(harness.saved[0]['receipts'], harness.current['receipts'])
        self.assertAlmostEqual(harness.clock.now, 2.005)

    def test_shared_settle_keeps_all_five_calls_and_final_checkpoint(self):
        harness = Harness(projected_source(), [0.005] * 10)
        result = harness.settle()
        self.assertEqual(len(harness.current['receipts']), 10)
        self.assertEqual(len(harness.current['snapshots']), 2)
        self.assertEqual(len(harness.current['snapshot_records']), 2)
        self.assertEqual(len(harness.current['process_samples']), 4)
        self.assertEqual(len(harness.current['daemon_events']), 2)
        self.assertEqual([c['member'] for c in harness.channel.commands],
                         ['ListNames', 'GetNameOwner', 'GetConnectionUnixUser',
                          'GetConnectionUnixProcessID', 'GetId'] * 2)
        self.assertEqual(result, harness.current['snapshots'][-1])
        self.assertEqual(len(harness.saved), 1)
        self.assertEqual(harness.saved[-1], harness.current)
        settle, = harness.current['settles']
        self.assertTrue(settle['completed'])
        self.assertAlmostEqual(settle['elapsed_ms'], 50)
        self.assertEqual((settle['budget_ms'], settle['budget_reads']), (1000, 128))

    def test_original_shared_settle_charges_repeated_reporting(self):
        harness = Harness(ORIGINAL.read_text(), [0.005] * 10, persistence=0.4)
        with self.assertRaisesRegex(AssertionError, 'SEC16 request exceeded fixed caller deadline'):
            harness.settle()
        self.assertEqual(len(harness.current['receipts']), 3)
        self.assertEqual(len(harness.saved), 4)  # three requests, then settle finally
        self.assertFalse(harness.current['settles'][-1]['completed'])
        self.assertEqual(harness.saved[-1], harness.current)

    def test_actual_late_response_is_still_rejected(self):
        harness = Harness(projected_source(), [1.001])
        with self.assertRaisesRegex(AssertionError, 'SEC16 request exceeded fixed caller deadline'):
            harness.request()
        self.assertEqual(harness.channel.timeouts, [1.0])
        self.assertEqual(len(harness.current['receipts']), 1)

    def test_registration_case_keeps_two_second_bound(self):
        harness = Harness(projected_source(), [1.5])
        self.assertTrue(harness.request(op='registration_case')['ok'])
        self.assertEqual(harness.channel.timeouts, [2.0])
        harness = Harness(projected_source(), [2.001])
        with self.assertRaisesRegex(AssertionError, 'SEC16 request exceeded fixed caller deadline'):
            harness.request(op='registration_case')

    def test_supplied_enclosing_deadline_and_authority_deadline_are_retained(self):
        for deadline, limit, expected in [(60.0, 0.003, 0.003), (0.003, None, 0.003)]:
            with self.subTest(deadline=deadline, limit=limit):
                harness = Harness(projected_source(), [0.005], deadline=deadline)
                with self.assertRaisesRegex(AssertionError, 'SEC16 request exceeded fixed caller deadline'):
                    harness.request(limit=limit)
                self.assertEqual(harness.channel.timeouts, [expected])
        harness = Harness(projected_source(), [0.005])
        with self.assertRaisesRegex(AssertionError, 'SEC16 fixed authority/request deadline'):
            harness.request(limit=0.0)
        self.assertEqual(harness.channel.commands, [])

    def test_failed_response_is_still_rejected_and_receipt_retained(self):
        harness = Harness(projected_source(), [0.005], ok=False)
        with self.assertRaises(AssertionError):
            harness.request()
        self.assertFalse(harness.current['receipts'][0]['response']['ok'])

    def test_settle_finally_keeps_receipts_on_actual_deadline_failure(self):
        harness = Harness(projected_source(), [0.005, 1.001])
        with self.assertRaisesRegex(AssertionError, 'SEC16 request exceeded fixed caller deadline'):
            harness.settle()
        self.assertEqual(len(harness.current['receipts']), 2)
        self.assertEqual(len(harness.saved), 1)
        self.assertEqual(harness.saved[-1], harness.current)
        self.assertFalse(harness.current['settles'][-1]['completed'])


if __name__ == '__main__':
    unittest.main()
