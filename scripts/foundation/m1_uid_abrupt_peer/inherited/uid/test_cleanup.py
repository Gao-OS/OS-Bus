"""Inactive cleanup/persistence regressions; no process or VM is started.

UID_CLEANUP_SOURCE may point to root's preserved before-repair runner for RED.
Extract actual cleanup, both acceptance bodies and case persistence scheduling.
"""
import ast
import copy
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest


SOURCE = Path(os.environ.get('UID_CLEANUP_SOURCE', str(Path(__file__).with_name('run.py'))))


def unique(nodes, predicate, label):
    found = [node for node in nodes if predicate(node)]
    if len(found) != 1:
        raise AssertionError(('actual source definition missing/ambiguous', label, len(found)))
    return found[0]


def actual_cleanup(model):
    tree = ast.parse(SOURCE.read_text())
    main = unique(tree.body, lambda n: isinstance(n, ast.FunctionDef) and n.name == 'main', 'main')
    stop = unique(ast.walk(main), lambda n: isinstance(n, ast.FunctionDef) and n.name == 'stop_channel', 'stop_channel')
    retire = unique(ast.walk(main), lambda n: isinstance(n, ast.FunctionDef) and n.name == 'retire', 'retire')
    assert isinstance(retire.body[0], ast.Assign)
    assert len(retire.body[0].targets) == 1 and isinstance(retire.body[0].targets[0], ast.Name)
    assert retire.body[0].targets[0].id == 'result'
    assert all(isinstance(n, (ast.Assert, ast.Assign)) for n in retire.body[1:])
    final = unique(ast.walk(main), lambda n: isinstance(n, ast.For) and isinstance(n.target, ast.Name)
                   and n.target.id == 'shutdown', 'final shutdown predicates')
    assert all(isinstance(n, (ast.Assert, ast.Assign)) for n in final.body)
    retire_check = ast.parse('def accept_retire(result):\n pass').body[0]
    final_check = ast.parse('def accept_final(shutdown):\n pass').body[0]
    retire_check.body = copy.deepcopy(retire.body[1:])
    final_check.body = copy.deepcopy(final.body)
    module = ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(stop), retire_check, final_check], type_ignores=[]))
    namespace = dict(time=model.clock, os=model.os, Path=model.path, subprocess=subprocess)
    exec(compile(module, str(SOURCE), 'exec'), namespace)
    return namespace['stop_channel'], [namespace['accept_retire'], namespace['accept_final']]


def actual_case_persistence(report, selected, evidence, simulate_case):
    tree = ast.parse(SOURCE.read_text())
    main = unique(tree.body, lambda n: isinstance(n, ast.FunctionDef) and n.name == 'main', 'main')
    flag = unique(main.body, lambda n: isinstance(n, ast.Assign) and any(
        isinstance(target, ast.Name) and target.id == 'persistence_deferred' for target in n.targets),
        'initial persistence deferral')
    persist = unique(main.body, lambda n: isinstance(n, ast.FunctionDef) and n.name == 'persist', 'persist')
    trial = unique(main.body, lambda n: isinstance(n, ast.Try) and any(
        isinstance(child, ast.For) and isinstance(child.target, ast.Name) and child.target.id == 'case'
        for child in n.body), 'case lifecycle')
    loop = unique(trial.body, lambda n: isinstance(n, ast.For) and isinstance(n.target, ast.Name)
                  and n.target.id == 'case', 'selected case loop')
    flush = trial.finalbody[-1]
    assert isinstance(flush, ast.Expr) and isinstance(flush.value, ast.Call)
    assert isinstance(flush.value.func, ast.Name) and flush.value.func.id == 'persist'
    wrapper = ast.parse('def exercise(report, selected, evidence, simulate_case):\n pass').body[0]
    bindings = ast.parse("""
baseline = {}
state_key = lambda state: state
def names_case(row):
    simulate_case(row, persist, report)
matches_case = names_case
""").body
    # Execute the actual case loop and exception handler. Cleanup effects are
    # inert; the actual final shutdown persist call runs after that marker.
    cleanup_marker = ast.parse("report['inert_shutdown_finished'] = True").body[0]
    lifecycle = ast.Try(body=[copy.deepcopy(loop)], handlers=copy.deepcopy(trial.handlers),
                        orelse=[], finalbody=[cleanup_marker, copy.deepcopy(flush)])
    wrapper.body = [copy.deepcopy(flag), copy.deepcopy(persist)] + bindings + [lifecycle]
    module = ast.fix_missing_locations(ast.Module(body=[wrapper], type_ignores=[]))
    namespace = dict(json=SimpleNamespace(dumps=evidence.dumps))
    exec(compile(module, str(SOURCE), 'exec'), namespace)
    namespace['exercise'](report, selected, evidence, simulate_case)


class Evidence:
    """In-memory atomic-write target; no filesystem access or process."""
    def __init__(self):
        self.serializations = 0
        self.writes = []
        self.pending = None

    def dumps(self, value, **options):
        self.serializations += 1
        return json.dumps(value, **options)

    def __truediv__(self, name):
        assert name in ('qualification.json.tmp', 'qualification.json')
        return self

    def write_text(self, text):
        self.pending = json.loads(text)

    def replace(self, destination):
        assert destination is self and self.pending is not None
        self.writes.append(self.pending)
        self.pending = None


class PersistenceRegression(unittest.TestCase):
    def exercise(self, failure=None):
        selected = ['uid_names', 'uid_matches']
        report = dict(outcomes={case: dict(status='blocked', reason='not_executed') for case in selected},
                      receipts=[], snapshots=[], probes=[], result='failed')
        evidence = Evidence()

        def simulate(row, persist, current):
            initial_serializations = evidence.serializations
            for index in range(3):
                current['receipts'].append(dict(index=index, response={'body': ['full-receipt']}))
                current['snapshots'].append(dict(index=index, state={'entries': ['full-snapshot']}))
                current['probes'].append(dict(index=index, unique=':inert-observer'))
                persist()
                self.assertEqual(evidence.serializations, initial_serializations)
            row['phases'] = dict(baseline_recovered={})
            if row is current['outcomes']['uid_matches']:
                if failure == 'case':
                    raise RuntimeError('inert case failure')
                if failure == 'baseline':
                    row['phases']['baseline_recovered'] = dict(mismatch=True)

        if failure:
            expected = RuntimeError if failure == 'case' else AssertionError
            with self.assertRaises(expected):
                actual_case_persistence(report, selected, evidence, simulate)
        else:
            actual_case_persistence(report, selected, evidence, simulate)
        self.assertEqual(evidence.serializations, len(evidence.writes))
        self.assertEqual(evidence.writes[-1], report)
        self.assertTrue(report['inert_shutdown_finished'])
        self.assertEqual(len(report['receipts']), 6)
        self.assertEqual(len(report['snapshots']), 6)
        self.assertEqual(len(report['probes']), 6)
        self.assertEqual(report['outcomes']['uid_names']['status'], 'passed')
        return report, evidence

    def test_case_writes_are_deferred_and_full_success_checkpoints_restored(self):
        report, evidence = self.exercise()
        self.assertEqual(len(evidence.writes), 5)
        self.assertEqual([write['outcomes']['uid_matches']['status'] for write in evidence.writes],
                         ['blocked', 'blocked', 'running', 'passed', 'passed'])
        self.assertEqual(len(evidence.writes[1]['receipts']), 3)
        self.assertEqual(len(evidence.writes[3]['snapshots']), 6)
        self.assertEqual(report['counts'], dict(selected=2, executed=2, passed=2, failed=0, blocked=0, skipped=0))

    def assert_failure_checkpoints(self, failure):
        report, evidence = self.exercise(failure)
        self.assertEqual(len(evidence.writes), 6)
        self.assertEqual(evidence.writes[3]['outcomes']['uid_matches']['status'], 'failed')
        self.assertNotIn('failure', evidence.writes[3])
        self.assertEqual(evidence.writes[4]['failure'], report['failure'])
        self.assertNotIn('inert_shutdown_finished', evidence.writes[4])
        self.assertEqual(report['counts'], dict(selected=2, executed=2, passed=1, failed=1, blocked=0, skipped=0))
        self.assertEqual(report['result'], 'failed')

    def test_case_exception_flushes_full_failure_and_shutdown_evidence(self):
        self.assert_failure_checkpoints('case')

    def test_baseline_assertion_failure_restores_physical_checkpoint_writes(self):
        self.assert_failure_checkpoints('baseline')


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        value = self.now
        self.now += 0.125
        return value


class Stdin:
    def __init__(self, model):
        self.model = model
        self.closed = False

    def close(self):
        self.model.events.append('stdin-close')
        self.closed = True


class Process:
    def __init__(self, model):
        self.model = model
        self.pid = 501
        self.returncode = None
        self.stdin = Stdin(model)

    def wait(self, timeout):
        model = self.model
        model.events.append(('wait', timeout))
        assert self.stdin.closed
        if not model.wrapper_exists:
            return self.returncode
        if model.scenario == 'timeout':
            model.clock.now += timeout
            raise subprocess.TimeoutExpired(['inert-wrapper'], timeout)
        model.wrapper_exists = False
        self.returncode = 1 if model.scenario == 'nonzero' else 0
        model.actor_exists = model.scenario in ('actor-residual', 'late-retirement')
        model.group_exists = model.scenario in ('descendant-residual', 'actor-residual', 'late-retirement', 'probe-error')
        return self.returncode


class Channel:
    """Model the existing wait, unconditional group containment and drain."""
    def __init__(self, model):
        self.model = model
        self.process = Process(model)

    def stop(self):
        model = self.model
        model.events.append('containment-enter')
        model.containment_calls += 1
        self.process.stdin.close()
        method = 'eof'
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            method = 'terminate'
            model.wrapper_exists = False
            self.process.returncode = -15
        # This is the original transport's distinguishing counterexample:
        # EOF/zero may label the wrapper while descendants require SIGKILL.
        model.forced_group_cleanup = model.group_exists
        model.events.append(('original-group-containment', model.group_exists))
        model.wrapper_exists = model.actor_exists = model.group_exists = False
        model.events.append('raw-log-drain')
        return dict(command=['inert-wrapper'], pid=self.process.pid,
                    method=method, returncode=self.process.returncode)


class Model:
    def __init__(self, scenario, accepted=True):
        self.scenario = scenario
        self.clock = Clock()
        self.events = []
        self.wrapper_exists = self.actor_exists = self.group_exists = True
        self.containment_calls = 0
        self.forced_group_cleanup = False
        self.probe_failed = False
        self.channel = Channel(self)
        pid = self.channel.process.pid if scenario == 'descendant-residual' else 502
        self.accepted = dict(pid=pid, uid=1100, gid=1100) if accepted else None
        self.os = SimpleNamespace(killpg=self.killpg)

    def killpg(self, pgid, sig):
        assert pgid == self.channel.process.pid and sig == 0
        self.events.append('group-probe')
        if self.scenario == 'probe-error' and not self.probe_failed:
            self.probe_failed = True
            raise PermissionError('inert probe failure')
        if self.scenario == 'late-retirement' and self.clock.now >= 0.75:
            self.actor_exists = self.group_exists = False
        if not self.group_exists:
            raise ProcessLookupError('inert group absent')

    def path(self, root, pid):
        assert root == '/proc'
        pid = int(pid)
        assert pid in (self.channel.process.pid, 502)
        return SimpleNamespace(exists=lambda: self.wrapper_exists if pid == self.channel.process.pid else self.actor_exists)


class CleanupRegression(unittest.TestCase):
    def execute(self, scenario, accepted=True):
        model = Model(scenario, accepted)
        stop, checks = actual_cleanup(model)
        result = stop(model.channel, model.accepted)
        self.assertEqual(model.containment_calls, 1)
        self.assertEqual(model.events[-1], 'group-probe')
        self.assertIn('raw-log-drain', model.events)
        self.assertTrue(result['pid_absent'])
        self.assertTrue(result['group_absent'])
        return model, result, checks

    def rejected_by_both_sites(self, checks, result):
        for check in checks:
            with self.subTest(acceptance=check.__name__):
                with self.assertRaises(AssertionError):
                    check(result)

    def test_zero_wrapper_with_residual_descendant_cannot_qualify(self):
        model, result, checks = self.execute('descendant-residual')
        # The old draft qualifies this exact post-containment EOF/zero shape.
        self.assertEqual((result['method'], result['returncode']), ('eof', 0))
        self.assertTrue(result['actor_pid_absent'])
        self.assertTrue(model.forced_group_cleanup)
        self.rejected_by_both_sites(checks, result)
        before = result['before_containment']
        self.assertTrue(before['wrapper_waited'] and before['pid_absent'] and before['actor_pid_absent'])
        self.assertEqual(before['wrapper_returncode'], 0)
        self.assertFalse(before['group_absent'])

    def test_kernel_actor_remaining_after_zero_wrapper_cannot_qualify(self):
        model, result, checks = self.execute('actor-residual')
        self.assertEqual((result['method'], result['returncode']), ('eof', 0))
        self.assertTrue(result['actor_pid_absent'] and model.forced_group_cleanup)
        self.rejected_by_both_sites(checks, result)
        before = result['before_containment']
        self.assertTrue(before['pid_absent'])
        self.assertFalse(before['actor_pid_absent'] or before['group_absent'])

    def test_clean_eof_is_observed_before_final_containment(self):
        model, result, checks = self.execute('clean')
        for check in checks:
            check(result)
        self.assertFalse(model.forced_group_cleanup)
        before = result['before_containment']
        self.assertTrue(before['stdin_closed'] and before['wrapper_waited'])
        self.assertEqual(before['wrapper_returncode'], 0)
        self.assertTrue(before['pid_absent'] and before['actor_pid_absent'] and before['group_absent'])
        self.assertFalse(before['timed_out'] or before['errors'])
        prefix = model.events[:model.events.index('containment-enter')]
        self.assertEqual(prefix[0], 'stdin-close')
        self.assertIn(('wait', 5), prefix)
        self.assertIn('group-probe', prefix)

    def test_bounded_natural_descendant_retirement_can_qualify(self):
        model, result, checks = self.execute('late-retirement')
        for check in checks:
            check(result)
        self.assertFalse(model.forced_group_cleanup)
        self.assertTrue(result['before_containment']['actor_pid_absent'])
        self.assertTrue(result['before_containment']['group_absent'])

    def test_wait_timeout_is_rejected_and_still_contained(self):
        model, result, checks = self.execute('timeout')
        self.rejected_by_both_sites(checks, result)
        before = result['before_containment']
        self.assertTrue(before['stdin_closed'] and before['timed_out'])
        self.assertFalse(before['wrapper_waited'])
        self.assertIsNone(before['wrapper_returncode'])
        self.assertTrue(model.forced_group_cleanup)
        self.assertEqual((result['method'], result['returncode']), ('terminate', -15))

    def test_probe_failure_still_invokes_containment_and_cannot_qualify(self):
        model, result, checks = self.execute('probe-error')
        self.rejected_by_both_sites(checks, result)
        self.assertEqual(len(result['before_containment']['errors']), 1)
        self.assertIn('inert probe failure', result['before_containment']['errors'][0])
        self.assertTrue(model.forced_group_cleanup)

    def test_nonzero_exit_or_unknown_actor_identity_cannot_qualify(self):
        for scenario, accepted in [('nonzero', True), ('clean', False)]:
            with self.subTest(scenario=scenario, accepted=accepted):
                _, result, checks = self.execute(scenario, accepted)
                self.rejected_by_both_sites(checks, result)


if __name__ == '__main__':
    unittest.main()
