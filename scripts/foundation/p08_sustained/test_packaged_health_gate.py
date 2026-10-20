"""Finite-barrier regressions for whole-capture exclusion and health admission."""
import random
import threading
import unittest
from unittest.mock import patch

import packaged_qualify as controller


class HealthGateTests(unittest.TestCase):
    def gate(self):
        gate = getattr(controller, 'HealthGate', None)
        self.assertIsNotNone(gate, 'whole-capture exclusion needs explicit health-priority admission')
        return gate()

    def wait(self, event):
        self.assertTrue(event.wait(2), 'finite barrier deadline')

    def launch(self, target, name):
        def run():
            try:
                target()
            except BaseException as error:
                self.errors.append(error)
        thread = threading.Thread(target=run, name=name)
        self.threads.append(thread)
        thread.start()
        return thread

    def setUp(self):
        self.threads, self.errors = [], []

    def tearDown(self):
        for thread in self.threads:
            thread.join(3)
            self.assertFalse(thread.is_alive(), 'test thread not contained')
        self.assertEqual(self.errors, [])

    def guest(self, gate):
        guest = object.__new__(controller.Guest)
        guest.health_lock = gate
        guest.started = 0.0
        guest.health = dict(started=0.0, count=0, max_ms=0.0, errors=[], observations=[])
        guest.report = dict(operation_count=2, rows={'whole-accounting': {}}, worker_barriers=[])
        guest.manifest = {}
        return guest

    def test_pending_regular_precedes_post_kill_and_repeated_snapshot(self):
        gate = self.gate()
        queued = {name: threading.Event() for name in ('post-kill', 'regular', 'snapshot')}
        admitted = []
        original_wait = gate.condition.wait
        def wait(timeout=None):
            queued[threading.current_thread().name].set()
            return original_wait(timeout)
        def enter(kind):
            with gate.section(kind, 9):
                admitted.append(kind)
        with patch.object(gate.condition, 'wait', side_effect=wait):
            with gate.section('snapshot:quiescent', 8):
                for name, kind in [('post-kill', 'health-post-kill'), ('regular', 'health-regular'),
                                   ('snapshot', 'snapshot:quiescent')]:
                    self.launch(lambda kind=kind: enter(kind), name)
                    self.wait(queued[name])
                self.assertEqual(admitted, [])
            for thread in self.threads:
                thread.join(2)
        self.assertEqual(admitted, ['health-regular', 'health-post-kill', 'snapshot:quiescent'])
        self.assertEqual(len(gate.receipts), 4)
        for receipt in gate.receipts:
            self.assertLessEqual(receipt['queued'], receipt['acquired'])
            self.assertLessEqual(receipt['acquired'], receipt['released'])
            self.assertAlmostEqual(receipt['wait_ms'], (receipt['acquired']-receipt['queued'])*1000)
            self.assertAlmostEqual(receipt['hold_ms'], (receipt['released']-receipt['acquired'])*1000)

    def test_capture_is_atomic_but_pure_verification_does_not_block_health_or_advance_worker(self):
        gate = self.gate()
        guest = self.guest(gate)
        # Bind the clock to this test's due origin without changing the schedule.
        guest.health['started'] = controller.time.monotonic()
        console_entered, console_release = threading.Event(), threading.Event()
        external_entered, external_release = threading.Event(), threading.Event()
        verification_entered, verification_release = threading.Event(), threading.Event()
        health_entered, next_operation = threading.Event(), threading.Event()
        health_queued = threading.Event()
        wait = gate.condition.wait
        def queued(timeout=None):
            if threading.current_thread().name == 'health':
                health_queued.set()
            return wait(timeout)
        calls = []
        order = list(controller.WORKLOAD['operations'])
        random.Random(controller.WORKLOAD['seed']).shuffle(order)
        class Worker:
            def request(inner, **request):
                if request['op'] == 'barrier':
                    return {'completed': guest.report['operation_count']}
                if calls:
                    next_operation.set()
                calls.append(len(calls))
                return {'kind': order[(2+len(calls)-1) % len(order)]}
        class Console:
            def request(inner, operation):
                console_entered.set()
                if len(calls) == 1:
                    self.wait(console_release)
                return {}
        class Observer:
            def request(inner, **request):
                health_entered.set()
                return {'latency_ms': 1.0}
        def external(pid):
            external_entered.set()
            if len(calls) == 1:
                self.wait(external_release)
            return {}
        def verify(*args):
            verification_entered.set()
            if len(calls) == 1:
                self.wait(verification_release)
        with patch.object(gate.condition, 'wait', side_effect=queued), \
             patch.object(controller, 'external', side_effect=external), \
             patch.object(controller, 'verify_sample', side_effect=verify), \
             patch.object(controller, 'verify_runtime'):
            self.launch(lambda: guest.operations(Worker(), Observer(), Console(), 1, count=2), 'worker')
            self.wait(console_entered)
            self.launch(lambda: guest.health_probe(Observer()), 'health')
            try:
                self.wait(health_queued)
                self.assertFalse(health_entered.is_set())
                console_release.set()
                self.wait(external_entered)
                self.assertFalse(health_entered.is_set())
                external_release.set()
                self.wait(verification_entered)
                self.wait(health_entered)
                self.assertFalse(next_operation.is_set())
            finally:
                console_release.set()
                external_release.set()
                verification_release.set()
                for thread in self.threads:
                    thread.join(3)
        self.assertTrue(next_operation.is_set())
        self.assertEqual(guest.report['operation_count'], 4)
        self.assertEqual(guest.report['worker_barriers'], [4])

    def test_validation_failure_still_blocks_next_operation(self):
        guest = self.guest(self.gate())
        calls = []
        order = list(controller.WORKLOAD['operations'])
        random.Random(controller.WORKLOAD['seed']).shuffle(order)
        class Worker:
            def request(inner, **request):
                calls.append(request)
                return {'kind': order[2]}
        class Console:
            def request(inner, operation): return {}
        with patch.object(controller, 'external', return_value={}), \
             patch.object(controller, 'verify_sample', side_effect=AssertionError('nonquiescent credit')):
            with self.assertRaisesRegex(AssertionError, 'nonquiescent credit'):
                guest.operations(Worker(), None, Console(), 1, count=2)
        self.assertEqual(len(calls), 1)
        self.assertEqual(guest.report['rows']['whole-accounting']['status'], 'failed')

    def test_slow_capture_actor_and_backlog_remain_failures(self):
        for kind in ('capture', 'actor', 'backlog'):
            with self.subTest(kind=kind):
                gate = self.gate()
                guest = self.guest(gate)
                clock = [0.0]
                class Observer:
                    def request(inner, **request):
                        clock[0] += 1.001 if kind == 'actor' else .01
                        return {'latency_ms': 1001.0 if kind == 'actor' else 10.0}
                with patch.object(controller.time, 'monotonic', side_effect=lambda: clock[0]):
                    if kind == 'capture':
                        queued, rejected = threading.Event(), []
                        wait = gate.condition.wait
                        def waiting(timeout=None):
                            queued.set()
                            return wait(timeout)
                        def probe():
                            try:
                                guest.health_probe(Observer())
                            except AssertionError as error:
                                rejected.append(str(error))
                        with gate.section('snapshot:quiescent', 0):
                            with patch.object(gate.condition, 'wait', side_effect=waiting):
                                thread = self.launch(probe, 'health')
                                self.wait(queued)
                            clock[0] += 1.2
                        thread.join(2)
                        self.assertEqual(rejected, ['independent end-to-end health deadline'])
                    elif kind == 'backlog':
                        clock[0] += 1.2
                    if kind != 'capture':
                        with self.assertRaisesRegex(AssertionError, 'end-to-end health deadline'):
                            guest.health_probe(Observer())
                self.assertEqual(guest.health['observations'][0]['due'], 0.0)
                self.assertGreater(guest.health['max_ms'], 1000)

    def test_regular_and_post_kill_actor_responses_remain_serialized(self):
        gate = self.gate()
        guest = self.guest(gate)
        guest.health['started'] = controller.time.monotonic()
        entered, release, queued = threading.Event(), threading.Event(), threading.Event()
        results, active, calls = [], [], []
        wait = gate.condition.wait
        def waiting(timeout=None):
            queued.set()
            return wait(timeout)
        class Observer:
            def request(inner, **request):
                self.assertEqual(active, [], 'actor requests overlapped')
                active.append(True)
                calls.append(len(calls)+1)
                identity = calls[-1]
                if identity == 1:
                    entered.set()
                    self.wait(release)
                active.clear()
                return {'latency_ms': 1.0, 'response_id': identity}
        with patch.object(gate.condition, 'wait', side_effect=waiting):
            self.launch(lambda: results.append(guest.health_probe(Observer())), 'regular')
            self.wait(entered)
            self.launch(lambda: results.append(guest.health_probe(Observer(), regular=False)), 'post-kill')
            try:
                self.wait(queued)
                self.assertEqual(calls, [1])
            finally:
                release.set()
                for thread in self.threads:
                    thread.join(3)
        by_index = {r['index']: r for r in results}
        self.assertEqual(by_index[0]['actor']['response_id'], 1)
        self.assertEqual(by_index[None]['actor']['response_id'], 2)
        self.assertEqual(guest.health['count'], 1)

    def test_overdue_due_indices_are_never_reset_or_consumed_by_post_kill(self):
        guest = self.guest(self.gate())
        clock = [.2]
        class Observer:
            def request(inner, **request):
                clock[0] += .01
                return {'latency_ms': 10.0}
        with patch.object(controller.time, 'monotonic', side_effect=lambda: clock[0]):
            for index in range(4):
                guest.health_probe(Observer())
                guest.health_probe(Observer(), regular=False)
        self.assertEqual(guest.health['count'], 4)
        self.assertEqual([r['index'] for r in guest.health['observations']], list(range(4)))
        self.assertEqual([round(r['due'], 6) for r in guest.health['observations']], [0, .05, .1, .15])
        self.assertAlmostEqual(guest.health['observations'][0]['latency_ms'], 210)


if __name__ == '__main__':
    unittest.main()
