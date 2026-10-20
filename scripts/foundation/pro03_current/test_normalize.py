"""Execute actual copied-runner AST with inert clock/channel/report I/O only."""
import ast
import copy
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

import normalize as N

ROOT = Path(__file__).resolve().parents[3]
DONOR = ROOT / ('test/reports/foundation/continuation-20261011-full-goal/environment/'
                'm1-pro03-complete1/source1/fixture1/run.py')


def source():
    override = os.environ.get('PRO03_PERSISTENCE_SOURCE')
    return Path(override).read_bytes() if override else N.patch_runner(DONOR.read_bytes())


def main_node(data):
    return next(node for node in ast.parse(data).body
                if isinstance(node, ast.FunctionDef) and node.name == 'main')


class ReportWriter:
    def __init__(self, model):
        self.model = model
        self.saved = []
        self.pending = None

    def __truediv__(self, name):
        assert name in ('qualification.json.tmp', 'qualification.json')
        return self

    def write_text(self, value):
        self.model.now += 1.6
        self.pending = json.loads(value)

    def replace(self, target):
        assert target is self and self.pending is not None
        self.saved.append(self.pending)
        self.pending = None


class Model:
    def __init__(self, response_seconds=0.002):
        self.now = 10.0
        self.response_seconds = response_seconds
        self.current = dict(status='running', receipts=[], snapshots=[], settles=[])
        self.report = dict(backends=[self.current], result='failed')
        self.writer = ReportWriter(self)
        self.commands = []
        self.worker = dict(public=dict(identity=dict(pid=994, uid=1100, gid=1100)),
                           channel=SimpleNamespace(begin=self.begin, read=self.read))
        self.snapshot_calls = 0
        self.namespace = dict(time=SimpleNamespace(monotonic=lambda: self.now),
                              deadline=70.0, current=self.current, report=self.report,
                              evidence=self.writer, json=json,
                              validate_observer=lambda value, public: None)
        main = main_node(source())
        required = ('persist', 'remaining', 'request', 'settle')
        functions = [copy.deepcopy(node) for node in ast.walk(main)
                     if isinstance(node, ast.FunctionDef) and node.name in required]
        assert sorted(node.name for node in functions) == sorted(required)
        module = ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[]))
        exec(compile(module, str(DONOR), 'exec'), self.namespace)
        self.namespace['snapshot'] = self.snapshot

    def begin(self, **command):
        self.commands.append(command)

    def read(self, timeout):
        self.now += self.response_seconds
        return dict(ok=True, result=dict(names=[':1.0', 'org.foundation.Observer']))

    def snapshot(self, observer, limit):
        for member in ('ListNames', 'GetNameOwner', 'GetConnectionUnixUser',
                       'GetConnectionUnixProcessID', 'GetId'):
            self.namespace['request'](self.worker, limit=limit, op='call', member=member)
        self.snapshot_calls += 1
        value = dict(daemon=dict(complete=True), observer=dict(process=dict(complete=True)))
        self.current['snapshots'].append(copy.deepcopy(value))
        return value

    def boundary(self, action):
        """Use actual backend exception handler and final persistence statement."""
        main = main_node(source())
        trial, = [node for node in ast.walk(main) if isinstance(node, ast.Try)
                  and any(isinstance(child, ast.For) and isinstance(child.target, ast.Name)
                          and child.target.id == 'case' for child in node.body)]
        assert ast.unparse(trial.finalbody[-1]) == 'persist()'
        wrapper = ast.Try(body=ast.parse('action()').body,
                          handlers=copy.deepcopy(trial.handlers), orelse=[],
                          finalbody=[copy.deepcopy(trial.finalbody[-1])])
        self.namespace['action'] = action
        exec(compile(ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[])),
                     str(DONOR), 'exec'), self.namespace)


class SchedulingControls(unittest.TestCase):
    def test_fast_request_excludes_slow_report_writer(self):
        model = Model()
        response = model.namespace['request'](model.worker, op='call', member='ListNames')
        self.assertTrue(response['ok'])
        self.assertAlmostEqual(model.now, 10.002)
        self.assertEqual(model.writer.saved, [])
        self.assertEqual(len(model.current['receipts']), 1)
        self.assertAlmostEqual(model.current['receipts'][0]['elapsed_ms'], 2.0)

    def test_settle_keeps_shared_deadline_and_flushes_all_records_at_boundary(self):
        model = Model()
        model.boundary(lambda: model.namespace['settle'](model.worker))
        settled = model.current['settles'][0]
        self.assertTrue(settled['completed'])
        self.assertEqual(settled['budget_ms'], 1000)
        self.assertAlmostEqual(settled['elapsed_ms'], 20.0)
        self.assertEqual(len(model.current['receipts']), 10)
        self.assertEqual(len(model.current['snapshots']), 2)
        self.assertEqual(len(model.writer.saved), 1)
        self.assertEqual(model.writer.saved[-1]['backends'][0], model.current)

    def test_real_request_overrun_still_fails_and_flushes_exception_and_receipt(self):
        model = Model(response_seconds=1.001)
        with self.assertRaisesRegex(AssertionError, 'PRO03 request exceeded fixed caller deadline'):
            model.boundary(lambda: model.namespace['request'](model.worker, op='call', member='GetId'))
        self.assertEqual(model.current['status'], 'failed')
        self.assertEqual(len(model.current['receipts']), 1)
        self.assertEqual(len(model.writer.saved), 2)
        self.assertEqual(model.writer.saved[-1]['backends'][0], model.current)

    def test_partial_settle_and_exception_flush_after_channel_failure(self):
        model = Model()
        original = model.namespace['snapshot']

        def fail_second(observer, limit):
            if model.snapshot_calls:
                raise ValueError('inert channel read failed')
            return original(observer, limit)

        model.namespace['snapshot'] = fail_second
        with self.assertRaisesRegex(ValueError, 'inert channel read failed'):
            model.boundary(lambda: model.namespace['settle'](model.worker))
        self.assertFalse(model.current['settles'][0]['completed'])
        self.assertEqual(len(model.current['settles'][0]['samples']), 1)
        self.assertEqual(len(model.current['receipts']), 5)
        self.assertEqual(len(model.writer.saved), 2)
        self.assertEqual(model.writer.saved[-1]['backends'][0], model.current)


class SourceControls(unittest.TestCase):
    def test_exact_inverse_and_only_two_persistence_calls_removed(self):
        original = DONOR.read_bytes()
        patched = N.patch_runner(original)
        expected = original
        for before, after in N.PERSISTENCE_REPLACEMENTS:
            expected = expected.replace(before, after)
        self.assertEqual(patched, expected)
        for before, after in reversed(N.PERSISTENCE_REPLACEMENTS):
            patched = patched.replace(after, before)
        self.assertEqual(patched, original)
        before_ast = ast.parse(original)
        for node in ast.walk(before_ast):
            if isinstance(node, ast.FunctionDef) and node.name in ('request', 'settle'):
                if node.name == 'request':
                    node.body = [child for child in node.body if ast.unparse(child) != 'persist()']
                else:
                    node.body[-1].finalbody = [child for child in node.body[-1].finalbody
                                               if ast.unparse(child) != 'persist()']
        self.assertEqual(ast.dump(before_ast), ast.dump(ast.parse(expected)))

    def test_all_deadlines_assertions_and_numeric_constants_are_identical(self):
        before = ast.parse(DONOR.read_bytes())
        after = ast.parse(N.patch_runner(DONOR.read_bytes()))
        for kind in (ast.Assert,):
            self.assertEqual([ast.dump(n) for n in ast.walk(before) if isinstance(n, kind)],
                             [ast.dump(n) for n in ast.walk(after) if isinstance(n, kind)])
        self.assertEqual([n.value for n in ast.walk(before) if isinstance(n, ast.Constant)
                          and type(n.value) in (int, float)],
                         [n.value for n in ast.walk(after) if isinstance(n, ast.Constant)
                          and type(n.value) in (int, float)])

    def test_donor_drift_or_repeated_patch_is_rejected(self):
        original = DONOR.read_bytes()
        for invalid in (original + b'\n', N.patch_runner(original)):
            with self.assertRaises(AssertionError):
                N.patch_runner(invalid)


if __name__ == '__main__':
    assert sys.dont_write_bytecode and sys.flags.optimize == 0
    unittest.main()
