"""Bounded orchestration tests with fake operations; never runtime evidence."""
import copy
import unittest
from unittest.mock import patch

import controller


def identity(pid, uid):
    return dict(pid=pid, uid=uid, gid=uid)


class Driver:
    """An in-memory ordering model, deliberately without transports or actors."""
    def __init__(self, backend='gao_bus'):
        self.backend = backend
        self.observer = dict(identity=identity(100, 1100), unique=':1.1',
                             bus_id='a' * 32, owner='org.foundation.Pro05Observer')
        self.log = []
        self.records = []
        self.sources = []
        self.serial = 10
        self.down = False
        self.bad_source_uid = False
        self.bad_restored_resources = False

    def start_source(self, family, iteration):
        source = dict(identity=identity(200 + len(self.sources), 1101),
                      unique=':1.' + str(2 + len(self.sources)), bus_id='a' * 32)
        self.sources.append(source)
        self.down = False
        self.log.append(('start', family, iteration))
        return source

    def make_snapshot(self, source=None):
        observer = copy.deepcopy(self.observer)
        observer.update(uid=1100, pid=self.observer['identity']['pid'])
        names = [controller.BUS, observer['unique'], observer['owner']]
        public = None
        if source is not None:
            public = copy.deepcopy(source)
            public.update(uid=1101, pid=source['identity']['pid'])
            names.append(source['unique'])
            if self.bad_source_uid:
                public['uid'] = 1100
        resources = dict(
            daemon=dict(identity=identity(50, 0), complete=True,
                        fd_targets={'0': '/dev/null', '3': 'socket:[300]'}, rss_kib=4096),
            observer=dict(identity=copy.deepcopy(self.observer['identity']), complete=True,
                          fd_targets={'0': 'pipe:[200]', '3': 'socket:[301]'}, rss_kib=1024))
        if source is not None:
            resources['daemon']['fd_targets']['4'] = 'socket:[' + str(source['identity']['pid']) + ']'
        elif self.down and self.bad_restored_resources:
            resources['daemon']['fd_targets']['4'] = 'socket:[leaked]'
        return dict(authority=dict(observer=observer, names=sorted(names), source=public,
                                   endpoint=dict(device=1, inode=300),
                                   core=dict(authority_pid='<0.1.0>')),
                    resources=resources)

    def snapshot(self, source, remaining_ms=None):
        self.log.append(('snapshot', None if source is None else source['unique'], remaining_ms))
        if remaining_ms is not None:
            assert 0 < remaining_ms <= 1500
        return self.make_snapshot(source)

    def native(self, source, reason=None):
        snapshot = self.make_snapshot(None if reason is not None else source)
        return dict(name=source['unique'], peer='<0.' + str(source['identity']['pid']) + '.0>',
                    reference='#Reference<' + str(source['identity']['pid']) + '>',
                    reason=reason, elapsed_ms=1, complete=True, errors=[], **snapshot)

    def watch(self, source):
        self.log.append(('watch', source['unique']))
        proof = dict(source_identity=copy.deepcopy(source['identity']), name=source['unique'])
        if self.backend == 'gao_bus':
            event = self.native(source)
            return dict(proof, kind='beam-monitor', peer=event['peer'],
                        reference=event['reference'], watch_event=event)
        return dict(proof, kind='public-name', watch_receipt=dict(fake_public_owner=True))

    def request(self, source, command):
        self.log.append((command['op'], source['unique'], copy.deepcopy(command)))
        if command['op'] == 'close':
            return dict(ok=True, budget_ms=3000, elapsed_ms=1, wire=[],
                        result=dict(disposition='controller-close', socket_closed=True))
        return dict(fake_operation=command['op'], command=copy.deepcopy(command))

    def await_down(self, source, watch, remaining_ms=None):
        self.log.append(('await_down', source['unique'], remaining_ms))
        assert remaining_ms == 1500
        self.down = True
        proof = dict(source_identity=copy.deepcopy(source['identity']),
                     name=source['unique'], elapsed_ms=1)
        if self.backend == 'gao_bus':
            event = self.native(source, 'normal')
            return dict(proof, kind='beam-monitor', peer=watch['peer'], reference=watch['reference'],
                        reason='normal', native_down=event)
        return dict(proof, kind='public-name', has_owner=False,
                    public_reply=dict(fake_public_owner=False))

    def observe(self, source_name=None):
        self.log.append(('observe', source_name))
        self.serial += 2
        return dict(response=dict(fake_observer=True), serial=self.serial)

    def retire(self, source):
        self.log.append(('retire', source['unique']))
        return dict(method='eof', returncode=0,
                    before_containment=dict(pid_absent=True, actor_pid_absent=True,
                                            group_absent=True, timed_out=False, errors=[]))

    def persist(self, record):
        self.records.append(copy.deepcopy(record))


class ControllerTest(unittest.TestCase):
    def setUp(self):
        # Wire behavior has its own finite replay tests. These mocks test only
        # controller sequencing, not bytes, processes, or qualification.
        for name in ('verify_target', 'verify_terminal', 'verify_observer'):
            mock = patch.object(controller, name, return_value=dict(runtime_qualification=False))
            mock.start()
            self.addCleanup(mock.stop)
        trace = patch.object(controller, 'verify_trace', return_value=b'')
        trace.start()
        self.addCleanup(trace.stop)

    def test_all_finite_groups_targets_and_pending_verdict(self):
        driver = Driver()
        result = controller.run_cases(driver)
        self.assertEqual(result['counts'], dict(source_groups=37, targets=41))
        expected = [('variant', 1), ('array', 1), ('struct', 1), ('match', 1), ('collection', 1)]
        expected += [('prefix', iteration) for iteration in range(1, 33)]
        self.assertEqual([(group['family'], group['iteration']) for group in result['groups']], expected)
        self.assertEqual([target['case'] for group in result['groups'] for target in group['targets']],
                         ['variant64', 'variant65', 'array32', 'array33', 'struct32', 'struct33',
                          'match_string', 'match_uint32', 'collection'] + ['prefix'] * 32)
        for group in result['groups']:
            self.assertEqual(group['source']['identity']['uid'], 1101)
            self.assertEqual(group['source']['bus_id'], driver.observer['bus_id'])
        self.assertFalse(result['runtime_qualification'])
        self.assertEqual(result['result'], 'pending-independent-runtime-review')
        self.assertTrue(all(record['runtime_qualification'] is False for record in driver.records))
        self.assertFalse(any(record.get('status') == 'passed' for record in driver.records))

    def test_terminal_eof_follows_real_down_and_restoration_before_retirement(self):
        driver = Driver()
        result = controller.run_cases(driver)
        for group in result['groups']:
            name = group['source']['unique']
            down_index = next(index for index, event in enumerate(driver.log)
                              if event[0] == 'await_down' and event[1] == name)
            retire_index = next(index for index, event in enumerate(driver.log)
                                if event[0] == 'retire' and event[1] == name)
            self.assertEqual(driver.log[down_index + 1][0:2], ('snapshot', None))
            if 'terminal' in group:
                eof_index = next(index for index, event in enumerate(driver.log)
                                 if event[0] == 'terminal' and event[1] == name)
                self.assertLess(down_index + 1, eof_index)
                self.assertLess(eof_index, retire_index)
                self.assertEqual(group['terminal']['authorization'],
                                 controller.authorization(group['down'], group['restoration']))
                self.assertFalse(any(event[0:2] == ('close', name) for event in driver.log))
            else:
                close_index = next(index for index, event in enumerate(driver.log)
                                   if event[0] == 'close' and event[1] == name)
                self.assertLess(close_index, down_index)
                self.assertLess(down_index, retire_index)
        positive_observers = [event for event in driver.log
                              if event[0] == 'observe' and event[1] is not None]
        self.assertEqual(positive_observers, [('observe', result['groups'][3]['source']['unique'])])

    def test_target_failure_retains_attempt_and_aborts_without_pass_or_eof(self):
        driver = Driver()
        with patch.object(controller, 'verify_target', side_effect=AssertionError('receipt mismatch')):
            with self.assertRaisesRegex(AssertionError, 'receipt mismatch'):
                controller.run_cases(driver)
        self.assertEqual(len(driver.sources), 1)
        self.assertEqual(driver.records[-1]['event'], 'failure')
        self.assertTrue(any(record['event'] == 'target' for record in driver.records))
        self.assertFalse(any(event[0] in ('terminal', 'await_down', 'retire') for event in driver.log))
        self.assertFalse(any(record['event'] == 'group-complete' for record in driver.records))

    def test_public_source_identity_mismatch_aborts_before_target(self):
        driver = Driver()
        driver.bad_source_uid = True
        with self.assertRaises(AssertionError):
            controller.run_cases(driver)
        self.assertFalse(any(event[0] == 'target' for event in driver.log))
        self.assertEqual(driver.records[-1]['event'], 'failure')

    def test_reused_prefix_source_name_aborts_before_its_target(self):
        driver = Driver()
        start = driver.start_source
        prefix_name = None

        def reused(family, iteration):
            nonlocal prefix_name
            source = start(family, iteration)
            if family == 'prefix' and iteration == 1:
                prefix_name = source['unique']
            elif family == 'prefix' and iteration == 2:
                source['unique'] = prefix_name
            return source

        with patch.object(driver, 'start_source', side_effect=reused):
            with self.assertRaisesRegex(AssertionError, 'source unique name reused'):
                controller.run_cases(driver)
        self.assertEqual(len(driver.sources), 7)
        self.assertEqual(len([event for event in driver.log if event[0] == 'target']), 10)
        self.assertEqual(len([event for event in driver.log if event[0] == 'watch']), 6)
        self.assertEqual(driver.records[-1]['event'], 'failure')

    def test_restoration_resource_mismatch_prevents_terminal_eof(self):
        driver = Driver()
        driver.bad_restored_resources = True
        with self.assertRaisesRegex(AssertionError, 'resource endpoint drift'):
            controller.run_cases(driver)
        self.assertTrue(any(event[0] == 'await_down' for event in driver.log))
        self.assertFalse(any(event[0] in ('terminal', 'retire') for event in driver.log))
        self.assertEqual(driver.records[-1]['event'], 'failure')

    def test_reference_retains_public_retirement_without_beam_claims(self):
        driver = Driver('reference')
        with patch.object(controller, '_public_reply') as check:
            result = controller.run_cases(driver)
        self.assertEqual(check.call_count, 74)
        for group in result['groups']:
            self.assertEqual(group['watch']['kind'], 'public-name')
            self.assertEqual(group['down']['kind'], 'public-name')
            self.assertNotIn('native_down', group['down'])
            self.assertNotIn('reference', group['down'])
        self.assertFalse(result['runtime_qualification'])


if __name__ == '__main__':
    unittest.main()
