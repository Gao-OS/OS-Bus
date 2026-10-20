"""Deterministic request/settle controls; no transport, daemon or VM."""
import ast
import copy
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

import normalize

PINNED = Path('/nix/store/mfklncj4bb9zkapgivflb5p8djyawka2-osbus-auth-bypass-current-inputs/fixtures/run.py')


def request_source():
    original = PINNED.read_bytes()
    return original if os.environ.get('SEC04_TEST_UNPATCHED') == '1' else normalize.patch_runner(original)


def controller(source, elapsed, response):
    tree = ast.parse(source)
    names = {'remaining', 'request', 'call', 'snapshot', 'settle'}
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    # Execute the original backend exception and teardown blocks around a pure
    # probe. Empty workers and absent daemons exercise their final persistence
    # without launching or interacting with a process or endpoint.
    boundary, = [node for node in ast.walk(tree) if isinstance(node, ast.Try)
                  and node.handlers and node.finalbody
                  and ast.unparse(node.handlers[0].body[0]).startswith("current['failure'] =")]
    guarded = copy.deepcopy(boundary)
    guarded.body = ast.parse('return probe()').body
    exercise = ast.parse('def exercise(probe):\n    pass\n').body[0]
    exercise.body = [guarded]
    clock = SimpleNamespace(now=0.0)
    current = dict(receipts=[], process_samples=[], daemon_events=[], snapshots=[],
                   snapshot_records=[], settles=[], retirements=[], shutdown_errors=[],
                   status='running', daemon=dict(identity=dict(pid=200, uid=0, gid=0)))
    saved, events = [], []
    worker = dict(public=dict(identity=dict(pid=100, uid=1100, gid=1100), unique=':1.1'), serial=1)
    command = {}

    def monotonic():
        events.append(('clock', clock.now))
        return clock.now

    def begin(**values):
        command.clear()
        command.update(values)
        events.append(('begin', copy.deepcopy(values)))

    def read(timeout):
        events.append(('read', timeout))
        clock.now += elapsed
        return response(worker, command) if callable(response) else response

    def persist():
        events.append(('persist', clock.now))
        # A full-graph diagnostic write alone exceeds the shared settle budget.
        clock.now += 10
        saved.append(copy.deepcopy(current))

    def process_sample(identity):
        return dict(identity=identity, complete=True, fds={})

    namespace = dict(time=SimpleNamespace(monotonic=monotonic), deadline=60,
                     current=current, persist=persist, BUS='org.freedesktop.DBus',
                     OBSERVER='org.foundation.Observer', copy=copy,
                     process_sample=process_sample, native_snapshot=lambda limit: None,
                     validate_observer=lambda value, public: None,
                     workers=[], retired=set(), daemon=None, reference=None,
                     reference_log=None, socket_identity=None, backend='reference',
                     endpoint=SimpleNamespace(stat=lambda: SimpleNamespace(st_ino=1, st_dev=2)),
                     os=SimpleNamespace(path=SimpleNamespace(lexists=lambda endpoint: False)))
    module = ast.fix_missing_locations(ast.Module(body=functions + [exercise], type_ignores=[]))
    exec(compile(module, str(PINNED) + ':pure-control', 'exec', optimize=0), namespace)
    worker['channel'] = SimpleNamespace(begin=begin, read=read)
    return SimpleNamespace(namespace=namespace, worker=worker, clock=clock,
                           current=current, saved=saved, events=events)


def exercise(control, probe):
    try:
        value = control.namespace['exercise'](probe)
    except AssertionError as error:
        return dict(error=error, saved=control.saved, current=control.current, events=control.events)
    return dict(value=value, saved=control.saved, current=control.current, events=control.events)


def run_request(source, elapsed, response, operation='call', limit=1):
    control = controller(source, elapsed, response)
    return exercise(control, lambda: control.namespace['request'](control.worker, limit=limit, op=operation))


class RequestDeadlineTest(unittest.TestCase):
    def check_receipt(self, result, response, elapsed, operation='call'):
        self.assertEqual(len(result['saved']), 2 if 'error' in result else 1)
        for saved in result['saved']:
            self.assertEqual(saved['receipts'], result['current']['receipts'])
        self.assertEqual(len(result['current']['receipts']), 1)
        receipt = result['current']['receipts'][0]
        self.assertEqual(receipt['identity'], dict(pid=100, uid=1100, gid=1100))
        self.assertEqual(receipt['request'], dict(op=operation))
        self.assertEqual(receipt['response'], response)
        self.assertEqual(receipt['elapsed_ms'], elapsed * 1000)
        self.assertEqual(set(receipt), {'identity', 'request', 'response', 'elapsed_ms'})
        if 'error' in result:
            self.assertEqual(result['saved'][0]['failure'], repr(result['error']))
            self.assertEqual(result['saved'][0]['status'], 'failed')
        self.assertEqual(result['saved'][-1]['endpoint_cleanup']['absent'], True)

    def test_on_time_response_survives_slow_diagnostic_persistence(self):
        response = dict(ok=True, result='on-time')
        result = run_request(request_source(), 0.25, response)
        self.assertNotIn('error', result)
        self.assertIs(result['value'], response)
        self.check_receipt(result, response, 0.25)

    def test_exact_caller_boundary_remains_inclusive(self):
        response = dict(ok=True)
        result = run_request(request_source(), 1.0, response)
        self.assertNotIn('error', result)
        self.check_receipt(result, response, 1.0)

    def test_truly_late_response_fails_and_still_persists(self):
        response = dict(ok=True, result='late')
        result = run_request(request_source(), 1.25, response)
        self.assertEqual(str(result['error']), 'SEC04 request exceeded fixed caller deadline')
        self.check_receipt(result, response, 1.25)

    def test_failed_response_preserves_original_assertion_and_receipt(self):
        response = dict(ok=False, error='actor failure')
        result = run_request(request_source(), 0.1, response)
        self.assertEqual(result['error'].args, (response,))
        self.check_receipt(result, response, 0.1)

    def test_original_two_second_attack_budget_remains(self):
        response = dict(ok=True)
        result = run_request(request_source(), 1.5, response, operation='attack', limit=None)
        self.assertNotIn('error', result)
        self.check_receipt(result, response, 1.5, operation='attack')


class SharedSettleTest(unittest.TestCase):
    def test_two_complete_snapshots_finish_before_any_full_graph_write(self):
        bodies = dict(ListNames=[[ 'org.foundation.Observer', ':1.1']],
                      GetNameOwner=[':1.1'], GetConnectionUnixUser=[1100],
                      GetConnectionUnixProcessID=[100], GetId=['bus-id'])

        def response(worker, command):
            return dict(ok=True, result=dict(reply_serial=worker['serial'],
                        sender='org.freedesktop.DBus', body=bodies[command['member']]))

        control = controller(request_source(), 0.01, response)
        result = exercise(control, lambda: control.namespace['settle'](control.worker))
        self.assertNotIn('error', result)
        self.assertEqual(len(result['current']['receipts']), 10)
        settle, = result['current']['settles']
        self.assertTrue(settle['completed'])
        self.assertEqual(len(settle['samples']), 2)
        self.assertAlmostEqual(settle['elapsed_ms'], 100)
        self.assertEqual((settle['budget_ms'], settle['budget_reads']), (1000, 128))
        self.assertEqual(len(result['saved']), 2)  # Original settle and teardown boundaries.
        for saved in result['saved']:
            self.assertEqual(saved['receipts'], result['current']['receipts'])
        events = result['events']
        self.assertEqual(sum(event[0] == 'read' for event in events[:next(
            i for i, event in enumerate(events) if event[0] == 'persist')]), 10)

    def test_failed_settle_preserves_exact_receipt_at_all_existing_boundaries(self):
        response = dict(ok=False, error='snapshot denied')
        control = controller(request_source(), 0.01, response)
        result = exercise(control, lambda: control.namespace['settle'](control.worker))
        self.assertEqual(result['error'].args, (response,))
        self.assertEqual(len(result['saved']), 3)  # Settle, backend exception, teardown.
        expected = dict(identity=dict(pid=100, uid=1100, gid=1100),
                        request=dict(op='call', member='ListNames', signature='', body=()),
                        response=response, elapsed_ms=10)
        for saved in result['saved']:
            self.assertEqual(saved['receipts'], [expected])
            self.assertFalse(saved['settles'][0]['completed'])


class RunnerPatchTest(unittest.TestCase):
    def test_single_exact_reversible_replacement(self):
        original = PINNED.read_bytes()
        patched = normalize.patch_runner(original)
        self.assertEqual(patched.count(normalize.NEW_REQUEST_BLOCK), 1)
        self.assertEqual(patched.replace(normalize.NEW_REQUEST_BLOCK, normalize.OLD_REQUEST_BLOCK), original)
        self.assertEqual(patched, original.replace(normalize.OLD_REQUEST_BLOCK, normalize.NEW_REQUEST_BLOCK))

    def test_donor_drift_or_repeated_application_is_rejected(self):
        original = PINNED.read_bytes()
        for changed in (original + b'\n', normalize.patch_runner(original)):
            with self.assertRaises(AssertionError):
                normalize.patch_runner(changed)


if __name__ == '__main__':
    import sys
    if sys.flags.optimize or not sys.dont_write_bytecode:
        raise RuntimeError('Run with -B and without Python optimization')
    unittest.main()
