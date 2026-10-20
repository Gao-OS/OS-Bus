"""Offline adapter regressions; synthetic bytes and injected I/O only.

These tests never launch the guest adapter, create files, inspect /proc, or
qualify a runtime gate. Importing helper functions does not run replay tests.
"""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

import actor_overlay
import controller
import run as adapter
from test_replay import BUS_ID, OBSERVER, SOURCE, encoded_message, ordinary_reply, response
from vectors import wire_string


def ident(pid, uid):
    return dict(pid=pid, uid=uid, gid=uid)


def sample(pid, uid):
    return dict(identity=ident(pid, uid), complete=True, errors=[], starttime_ticks=123,
                fd_targets={'0': 'pipe:[1]', '3': 'socket:[2]'}, fd_count=2,
                rss_bytes=1024, cpu_ticks=dict(user=1, system=2),
                proc_stat='raw stat', proc_stat_after='raw stat', proc_status='raw status')


def snapshot():
    return dict(authority=dict(observer=dict(unique=OBSERVER), names=[adapter.BUS, OBSERVER],
                               endpoint=dict(device=1, inode=2), core=dict(peer='<0.1.0>')),
                resources=dict(daemon=sample(50, 0), observer=sample(100, 1100)))


def make_driver():
    # Driver.__init__ only stores these Paths; no path is opened or probed.
    driver = adapter.Driver('reference', Path('/unused-candidate'), Path('/unused-original'),
                            Mock(), Mock(), Path('/unused-fixture'), Path('/unused-reference'),
                            100, Mock())
    driver.observer = dict(identity=ident(100, 1100), unique=OBSERVER,
                           bus_id=BUS_ID, owner=adapter.OWNER)
    driver.observer_worker = dict(identity=copy.deepcopy(driver.observer['identity']),
                                  channel=Mock(), serial=2)
    driver.record['daemon'] = dict(identity=ident(50, 0))
    return driver


def get_id_reply(serial):
    raw, parsed = ordinary_reply(90, serial, BUS_ID, destination=OBSERVER)
    write = actor_overlay._call('GetId', serial)
    return response([write], raw, parsed)


class DriverTest(unittest.TestCase):
    def test_public_reply_binds_blank_signature_request_to_raw_reply(self):
        value = get_id_reply(3)
        self.assertEqual(adapter.query_wire('GetId', 3), actor_overlay._call('GetId', 3))
        self.assertNotEqual(adapter.query_wire('GetId', 3), actor_overlay._call('GetId', 3, ''))
        self.assertEqual(adapter.checked_reply(value, 'GetId', 3, destination=OBSERVER),
                         value['result'])

    def test_public_credential_reply_binds_argument_destination_and_parsed_claim(self):
        fields = [(5, 'u', 3), (6, 's', OBSERVER), (7, 's', adapter.BUS)]
        raw = encoded_message(2, 90, fields, 'u', [1101])
        parsed = dict(type=2, serial=90, reply_serial=3, error=None, sender=adapter.BUS,
                      interface=None, member=None, body=[1101])
        write = actor_overlay._call('GetConnectionUnixUser', 3, 's', wire_string(SOURCE))
        value = response([write], raw, parsed)
        self.assertEqual(adapter.checked_reply(value, 'GetConnectionUnixUser', 3, 's', [SOURCE], OBSERVER),
                         parsed)
        forged = copy.deepcopy(value)
        forged['result']['body'] = [1100]
        with self.assertRaises(AssertionError):
            adapter.checked_reply(forged, 'GetConnectionUnixUser', 3, 's', [SOURCE], OBSERVER)
        with self.assertRaises(AssertionError):
            adapter.checked_reply(value, 'GetConnectionUnixUser', 3, 's', [':1.999'], OBSERVER)
        with self.assertRaises(AssertionError):
            adapter.checked_reply(value, 'GetConnectionUnixUser', 3, 's', [SOURCE], ':1.999')

    def test_public_calls_consume_worker_serials_without_mutating_observer_identity(self):
        driver = make_driver()
        public = copy.deepcopy(driver.observer)
        driver.observer_worker['channel'].read.side_effect = [get_id_reply(3), dict(ok=True, result={}),
                                                              get_id_reply(6), dict(ok=True, result={})]
        with patch.object(adapter.time, 'monotonic', return_value=10):
            result, _ = driver.public_call('GetId')
            self.assertEqual(result['body'], [BUS_ID])
            first_observed = driver.observe()
            driver.public_call('GetId')
            observed = driver.observe()
        self.assertEqual(first_observed['serial'], 4)
        self.assertEqual(observed['serial'], 7)
        self.assertEqual(driver.observer_worker['serial'], 8)
        self.assertEqual(driver.observer, public)
        self.assertEqual([entry['request']['op'] for entry in driver.record['receipts']],
                         ['call', 'observe', 'call', 'observe'])
        self.assertEqual(driver.record['receipts'][-1]['request']['serial'], 7)

    def test_dictionary_controller_request_preserves_input_and_caps_deadline(self):
        for operation, remaining_ms, caller_deadline, expected in (
                ('target', None, 100, 13), ('observe', None, 100, 11),
                ('terminal', 250, 100, 10.25), ('target', 500, 10.1, 10.1)):
            driver = make_driver()
            driver.deadline = caller_deadline
            worker = driver.observer_worker
            worker['channel'].read.return_value = dict(ok=True)
            command = dict(op=operation, case='prefix')
            if operation == 'observe':
                command = dict(op='observe', serial=3, owner=adapter.OWNER, source_name=None)
            elif operation == 'terminal':
                command['authorization'] = 'retained-proof-token'
            original = copy.deepcopy(command)
            with self.subTest(operation=operation, remaining_ms=remaining_ms), \
                    patch.object(adapter.time, 'monotonic', return_value=10):
                driver.request(worker, command, remaining_ms=remaining_ms)
            sent = worker['channel'].begin.call_args.kwargs
            self.assertEqual(command, original)
            self.assertEqual(sent, dict(original, deadline_monotonic=expected))
            self.assertAlmostEqual(worker['channel'].read.call_args.kwargs['timeout'], expected - 10)
            self.assertEqual(driver.record['receipts'][0]['request'], sent)

    def test_remaining_budget_propagates_to_native_down_and_actor_call(self):
        driver = make_driver()
        worker = driver.observer_worker
        worker['channel'].read.return_value = get_id_reply(3)
        driver.backend = 'gao_bus'
        source = dict(identity=ident(200, 1101), unique=SOURCE, bus_id=BUS_ID)
        event = dict(event='down', peer='<0.2.0>', reference='#Reference<1>', reason='normal')
        with patch.object(adapter.time, 'monotonic', return_value=10):
            driver.call(worker, 'GetId', remaining_ms=125)
            with patch.object(driver, 'native', return_value=event) as native:
                down = driver.await_down(source, {}, remaining_ms=250)
        self.assertEqual(worker['channel'].begin.call_args.kwargs['deadline_monotonic'], 10.125)
        self.assertAlmostEqual(native.call_args.args[1], 250)
        self.assertEqual(down['native_down'], event)
        self.assertEqual(down['source_identity'], source['identity'])

    def test_projection_excludes_volatile_metrics_and_preserves_incarnation_fds(self):
        before = snapshot()
        changed = copy.deepcopy(before)
        for role in ('daemon', 'observer'):
            changed['resources'][role].update(rss_bytes=4096, cpu_ticks=dict(user=20, system=10),
                                              proc_stat='later', proc_stat_after='later', proc_status='later')
        self.assertEqual(adapter.settled_projection(before), adapter.settled_projection(changed))
        for field, replacement in (('identity', ident(51, 0)), ('starttime_ticks', 124),
                                   ('fd_targets', {'4': 'socket:[leak]'})):
            drift = copy.deepcopy(changed)
            drift['resources']['daemon'][field] = replacement
            with self.subTest(field=field):
                self.assertNotEqual(adapter.settled_projection(before), adapter.settled_projection(drift))
        self.assertEqual(before['resources']['daemon']['rss_bytes'], 1024)
        self.assertEqual(changed['resources']['daemon']['rss_bytes'], 4096)

    def test_snapshot_restoration_settles_actual_projection_with_remaining_budget(self):
        driver = make_driver()
        baseline = snapshot()
        drift = copy.deepcopy(baseline)
        drift['resources']['daemon']['fd_targets']['4'] = 'socket:[not-yet-retired]'
        final = copy.deepcopy(baseline)
        final['resources']['daemon']['rss_bytes'] = 4096
        driver.baseline = copy.deepcopy(baseline)
        with patch.object(driver, '_snapshot', side_effect=[drift, drift, baseline, final]) as sampled, \
                patch.object(adapter.time, 'monotonic', return_value=10):
            result = driver.snapshot(None, remaining_ms=250)
        self.assertEqual(sampled.call_count, 4)
        self.assertTrue(all(call.args == (None, 10.25) for call in sampled.call_args_list))
        self.assertEqual(result, final)
        self.assertEqual(driver.record['settles'][-1]['samples'], 4)
        self.assertEqual(driver.record['settles'][-1]['budget_ms'], 250)
        self.assertEqual(driver.baseline, baseline)

    def test_fixed_memory_and_atom_endpoint_bounds(self):
        self.assertEqual(adapter.MEMORY_MAX, 256 * 1024 * 1024)
        self.assertEqual(adapter.ATOM_GROWTH_MAX, 16)
        baseline = snapshot()['resources']
        baseline['native'] = dict(complete=True, vm=dict(identity=dict(pid=50), atom_count=100,
                                                        memory=dict(total=adapter.MEMORY_MAX)))
        legal = copy.deepcopy(baseline)
        for role in ('daemon', 'observer'):
            legal[role]['rss_bytes'] = adapter.MEMORY_MAX
        legal['native']['vm']['atom_count'] = 116
        adapter.resource_bounds(legal, baseline)
        for mutation in ('rss', 'vm-memory', 'atoms', 'incomplete'):
            value = copy.deepcopy(legal)
            if mutation == 'rss':
                value['observer']['rss_bytes'] += 1
            elif mutation == 'vm-memory':
                value['native']['vm']['memory']['total'] += 1
            elif mutation == 'atoms':
                value['native']['vm']['atom_count'] += 1
            else:
                value['daemon'].update(complete=False, errors=[dict(observation='incomplete')])
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                adapter.resource_bounds(value, baseline)

    def test_disappearing_process_is_explicit_incomplete_without_fabricated_metrics(self):
        root = MagicMock()
        root.__truediv__.return_value.read_text.side_effect = FileNotFoundError('synthetic retirement')
        with patch.object(adapter, 'Path', return_value=root):
            value = adapter.process_sample(ident(100, 1100))
        self.assertIs(value['complete'], False)
        self.assertEqual(value['errors'], [dict(reason='process_retired', observation='incomplete')])
        self.assertIsNone(value['starttime_ticks'])
        self.assertIsNone(value['rss_bytes'])
        self.assertIsNone(value['cpu_ticks'])

    def test_snapshot_rejects_incomplete_sample_before_endpoint_observation(self):
        driver = make_driver()
        driver.endpoint = Mock()
        public = dict(ListNames=[adapter.BUS, OBSERVER, adapter.OWNER], GetNameOwner=OBSERVER,
                      GetConnectionUnixUser=1100, GetConnectionUnixProcessID=100, GetId=BUS_ID)
        broken = sample(50, 0)
        broken.update(complete=False, errors=[dict(reason='process_retired', observation='incomplete')])
        with patch.object(driver, 'public_call', side_effect=lambda member, *args:
                          (dict(body=[public[member]]), {})), \
                patch.object(adapter, 'process_sample', side_effect=[broken, sample(100, 1100)]):
            with self.assertRaises(AssertionError):
                driver._snapshot(None, 11)
        driver.endpoint.lstat.assert_not_called()
        self.assertEqual(driver.record['snapshots'], [])

    def test_snapshot_retains_configured_sentinel_after_checking_actual_owner(self):
        driver = make_driver()
        driver.endpoint = Mock()
        driver.endpoint.lstat.return_value = SimpleNamespace(st_mode=0o140666, st_dev=1, st_ino=2)
        public = dict(ListNames=[adapter.BUS, OBSERVER, adapter.OWNER], GetNameOwner=OBSERVER,
                      GetConnectionUnixUser=1100, GetConnectionUnixProcessID=100, GetId=BUS_ID)
        with patch.object(driver, 'public_call', side_effect=lambda member, *args:
                          (dict(body=[public[member]]), {})), \
                patch.object(adapter, 'process_sample', side_effect=[sample(50, 0), sample(100, 1100)]), \
                patch.object(adapter.time, 'monotonic', return_value=10):
            value = driver._snapshot(None, 11)
        controller._snapshot(value, driver.observer)
        self.assertEqual(value['authority']['observer']['owner'], adapter.OWNER)
        self.assertEqual(public['GetNameOwner'], OBSERVER)
        self.assertNotIn('native', value['resources'])

    def test_reference_public_proof_uses_real_replay_and_rejects_changed_claim(self):
        # A boolean has the same uint32 body encoding; only the signature differs.
        fields = [(5, 'u', 3), (6, 's', OBSERVER), (7, 's', adapter.BUS)]
        raw = encoded_message(2, 90, fields, 'u', [0])
        signature_field = b'\x08\x01g\0\x01u\0'
        self.assertEqual(raw.count(signature_field), 1)
        raw = raw.replace(signature_field, b'\x08\x01g\0\x01b\0')
        parsed = dict(type=2, serial=90, reply_serial=3, error=None, sender=adapter.BUS,
                      interface=None, member=None, body=[False])
        value = response([adapter.query_wire('NameHasOwner', 3, 's', [SOURCE])], raw, parsed)
        controller._public_reply(value, False, SOURCE, OBSERVER)
        forged = copy.deepcopy(value)
        forged['result']['body'] = [True]
        with self.assertRaises(AssertionError):
            controller._public_reply(forged, True, SOURCE, OBSERVER)

    def test_fd_read_race_is_explicit_incomplete_and_retains_other_raw_endpoints(self):
        accepted = ident(100, 1100)
        fields = ['0'] * 22
        fields[11], fields[12], fields[19] = '7', '8', '456'
        raw_stat = '100 (synthetic actor) ' + ' '.join(fields)
        raw_status = 'Pid:\t100\nUid:\t1100 1100 1100 1100\nGid:\t1100 1100 1100 1100\nVmRSS:\t8 kB\n'
        paths = {name: Mock() for name in ('stat', 'status', 'fd')}
        paths['stat'].read_text.return_value = raw_stat
        paths['status'].read_text.return_value = raw_status
        paths['fd'].iterdir.return_value = [SimpleNamespace(name='3')]
        root = MagicMock()
        root.__truediv__.side_effect = paths.__getitem__
        with patch.object(adapter, 'Path', return_value=root), \
                patch.object(adapter.os, 'readlink', side_effect=FileNotFoundError('synthetic FD race')):
            value = adapter.process_sample(accepted)
        self.assertIs(value['complete'], False)
        self.assertEqual(value['errors'], [dict(fd='3', reason='enoent', observation='incomplete')])
        self.assertEqual(value['starttime_ticks'], 456)
        self.assertEqual(value['rss_bytes'], 8 * 1024)
        self.assertEqual(value['cpu_ticks'], dict(user=7, system=8))
        self.assertEqual(value['proc_stat'], raw_stat)
        self.assertEqual(value['proc_status'], raw_status)
        with self.assertRaises(AssertionError):
            adapter.resource_bounds(dict(daemon=value, observer=sample(100, 1100)))


if __name__ == '__main__':
    unittest.main()
