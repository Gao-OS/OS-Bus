"""Actual copied settle AST with a deterministic clock; no process, socket or VM."""
import ast
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest

import normalize

ROOT = Path(__file__).absolute().parents[3]
DONOR = ROOT / ('test/reports/foundation/continuation-20261011-full-goal/'
                'environment/m1-sec02-complete1/source3/fixture1/run.py')
VM3 = Path('/nix/store/w15x76z7qwwr92v9qqq5ly3qaqrw176l-osbus-identity-claim-current-inputs/fixtures/run.py')
OLD_CONTROL = b"                    current['snapshots'].append(value);persist();return value\n"
NEW_CONTROL = b"                    current['snapshots'].append(value);return value\n"


def runner():
    return normalize.patch_runner(DONOR.read_bytes())


def controller(source, *, read_seconds=0.01, write_seconds=0.55, complete=True, external_complete=True):
    tree = ast.parse(source)
    names = {'remaining', 'control', 'settle'}
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    boundary, = [node for node in ast.walk(tree) if isinstance(node, ast.Try)
                 and node.handlers and node.finalbody
                 and ast.unparse(node.handlers[0].body[0]).startswith("current.update(status='failed'")]
    boundary = copy.deepcopy(boundary)
    boundary.body = ast.parse('return probe()').body
    exercise = ast.parse('def exercise(probe):\n    pass\n').body[0]
    exercise.body = [boundary]
    clock = SimpleNamespace(now=0.0)
    current = dict(status='running', daemon_events=[], snapshots=[], settles=[], external_fds=[],
                   shutdown_errors=[], daemon=dict(identity=dict(pid=200)), receipts=[])
    saved, events = [], []

    def read(timeout):
        events.append(('read', timeout))
        clock.now += read_seconds
        return dict(event='snapshot', complete=complete, key='stable')

    def external(value):
        events.append(('external', clock.now))
        result = dict(complete=external_complete, source=value)
        current['external_fds'].append(result)
        return result

    def persist():
        events.append(('persist', clock.now))
        clock.now += write_seconds
        saved.append(copy.deepcopy(current))

    stdin = SimpleNamespace(write=lambda _: None, flush=lambda: None)
    channel = SimpleNamespace(process=SimpleNamespace(stdin=stdin), read=read)
    namespace = dict(time=SimpleNamespace(monotonic=lambda: clock.now), deadline=60,
                     current=current, persist=persist, daemon=channel,
                     external_fds=external, state_key=lambda value: value['key'],
                     workers=[], retired=set(), reference=None, reference_log=None,
                     os=SimpleNamespace(path=SimpleNamespace(lexists=lambda _: False)),
                     backend='gao_bus', endpoint=None)
    module = ast.fix_missing_locations(ast.Module(body=functions + [exercise], type_ignores=[]))
    exec(compile(module, str(VM3) + ':pure-control', 'exec', optimize=0), namespace)
    # The original backend teardown sees no real daemon or workers. Settle still
    # uses the synthetic channel; only the extracted wrapper gets daemon=None.
    wrapped = namespace['exercise']

    def exercise(probe):
        def guarded_probe():
            try:
                return probe()
            finally:
                namespace['daemon'] = None
        try:
            return dict(value=wrapped(guarded_probe))
        except AssertionError as error:
            return dict(error=error)

    return SimpleNamespace(namespace=namespace, current=current, saved=saved,
                           events=events, exercise=exercise, clock=clock)


class SharedSettleTest(unittest.TestCase):
    def test_two_timely_complete_samples_precede_diagnostic_writes(self):
        c = controller(runner())
        result = c.exercise(lambda: c.namespace['settle'](dict(key='stable')))
        self.assertNotIn('error', result)
        self.assertEqual(len(c.current['snapshots']), 2)
        self.assertEqual(len(c.current['external_fds']), 2)
        settle, = c.current['settles']
        self.assertEqual((settle['budget_ms'], settle['budget_reads']), (1000, 128))
        self.assertAlmostEqual(settle['elapsed_ms'], 20)
        first_write = next(i for i, event in enumerate(c.events) if event[0] == 'persist')
        self.assertEqual([event[0] for event in c.events[:first_write]],
                         ['read', 'external', 'read', 'external'])
        self.assertEqual(len(c.saved), 2)  # Original settle-finally and backend-finally.
        for saved in c.saved:
            self.assertEqual(saved['snapshots'], c.current['snapshots'])
            self.assertEqual(saved['settles'], c.current['settles'])

    def test_original_snapshot_writes_can_exhaust_the_shared_budget(self):
        c = controller(VM3.read_bytes())
        result = c.exercise(lambda: c.namespace['settle'](dict(key='stable')))
        self.assertIn('error', result)
        self.assertEqual(len(c.current['snapshots']), 2)
        self.assertGreater(c.current['settles'][0]['elapsed_ms'], 1000)
        self.assertEqual(len(c.saved), 5)  # Two snapshots, settle, backend failure, teardown.
        self.assertEqual(c.saved[-1]['status'], 'failed')

    def test_truly_late_two_sample_settle_still_fails_and_persists(self):
        c = controller(runner(), read_seconds=0.55)
        result = c.exercise(lambda: c.namespace['settle'](dict(key='stable')))
        self.assertIn('error', result)
        self.assertEqual(len(c.current['snapshots']), 2)
        self.assertAlmostEqual(c.current['settles'][0]['elapsed_ms'], 1100)
        self.assertEqual(len(c.saved), 3)  # Settle, backend failure, teardown.
        for saved in c.saved:
            self.assertEqual(saved['snapshots'], c.current['snapshots'])
            self.assertEqual(saved['settles'], c.current['settles'])
        self.assertEqual(c.saved[-1]['status'], 'failed')

    def test_incomplete_snapshot_never_qualifies_and_read_bound_remains(self):
        c = controller(runner(), read_seconds=0.001, complete=False)
        result = c.exercise(lambda: c.namespace['settle']())
        self.assertEqual(str(result['error']), 'SEC02 full snapshot did not settle in128reads')
        self.assertEqual(len(c.current['snapshots']), 128)
        self.assertEqual(c.current['external_fds'], [])
        self.assertEqual(len(c.current['settles'][0]['samples']), 128)

    def test_incomplete_external_view_cannot_qualify(self):
        c = controller(runner(), read_seconds=0.001, external_complete=False)
        result = c.exercise(lambda: c.namespace['settle']())
        self.assertEqual(str(result['error']), 'SEC02 full snapshot did not settle in128reads')
        self.assertEqual(len(c.current['external_fds']), 128)

    def test_expected_state_mismatch_cannot_qualify(self):
        c = controller(runner(), read_seconds=0.001)
        result = c.exercise(lambda: c.namespace['settle'](dict(key='different')))
        self.assertEqual(str(result['error']), 'SEC02 full snapshot did not settle in128reads')
        self.assertEqual(len(c.current['settles'][0]['samples']), 128)


class RunnerPatchTest(unittest.TestCase):
    def test_only_snapshot_persist_is_removed_from_vm3(self):
        self.assertEqual(runner(), VM3.read_bytes().replace(OLD_CONTROL, NEW_CONTROL))
        self.assertEqual(runner().replace(NEW_CONTROL, OLD_CONTROL), VM3.read_bytes())
        expected = ast.parse(VM3.read_bytes().replace(OLD_CONTROL, NEW_CONTROL))
        self.assertEqual(ast.dump(ast.parse(runner())), ast.dump(expected))

    def test_donor_drift_or_repeated_application_is_rejected(self):
        for source in [DONOR.read_bytes() + b'\n', runner()]:
            with self.assertRaises(AssertionError):
                normalize.patch_runner(source)
        self.assertEqual(hashlib.sha256(DONOR.read_bytes()).hexdigest(), normalize.RUNNER_SHA)


if __name__ == '__main__':
    import sys
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError('Run with -B and without Python optimization')
    unittest.main()
