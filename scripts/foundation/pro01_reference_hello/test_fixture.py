"""Direct regression checks of the evidence predicates; no daemon or socket I/O."""
import copy
import json
import struct
import unittest

from actor import send_signature, validate_barrier, validate_cases, validate_completion


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.identity = dict(pid=123, fd=7, inode=456, starttime_ticks=789)
        self.trace = [dict(direction='send', hex='00', monotonic=1.0, completed=1.01, outcome='sent')]
        def queue(started):
            return dict(connection=dict(self.identity), live=True, success=True, sole_writer=True,
                        duplicated_connection=False, error=None, units='transmit allocation accounting',
                        allocation=0, ioctl=21521, kernel='test-kernel', send_trace=send_signature(self.trace),
                        started=started, finished=started + 0.01)
        self.barrier = dict(started=1.02, finished=1.2, first=queue(1.03), second=queue(1.16),
                            health=dict(started=1.05, finished=1.15))

    def check(self, barrier=None, identity=None, trace=None):
        validate_barrier(self.barrier if barrier is None else barrier,
                         self.identity if identity is None else identity,
                         self.trace if trace is None else trace, 21521, 'test-kernel')

    def test_accepts_live_drained_health_live_drained(self):
        self.check()

    def test_rejects_wrong_socket(self):
        for field in ('pid', 'fd', 'inode', 'starttime_ticks'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.barrier)
                value['second']['connection'][field] += 1
                with self.assertRaises(AssertionError):
                    self.check(value)

    def test_rejects_undrained_or_closed_socket(self):
        for phase in ('first', 'second'):
            for field, wrong in (('allocation', 1), ('live', False)):
                with self.subTest(phase=phase, field=field):
                    value = copy.deepcopy(self.barrier)
                    value[phase][field] = wrong
                    with self.assertRaises(AssertionError):
                        self.check(value)

    def test_rejects_stale_or_late_queue_sample(self):
        value = copy.deepcopy(self.barrier)
        value['first']['started'] = 1.0
        with self.assertRaises(AssertionError):
            self.check(value)
        value = copy.deepcopy(self.barrier)
        value['finished'] = 2.1
        with self.assertRaises(AssertionError):
            self.check(value)

    def test_rejects_changed_send_trace(self):
        value = copy.deepcopy(self.barrier)
        trace = self.trace + [dict(direction='send', hex='01', monotonic=1.08, completed=1.09, outcome='sent')]
        value['second']['send_trace'] = send_signature(trace)
        with self.assertRaises(AssertionError):
            self.check(value)
        with self.assertRaises(AssertionError):
            self.check(trace=trace)

    def test_rejects_health_outside_queue_barrier(self):
        value = copy.deepcopy(self.barrier)
        value['health']['finished'] = 1.19
        with self.assertRaises(AssertionError):
            self.check(value)

    def test_rejects_reversed_registration_reply_order(self):
        name = ':1.2'
        body = (struct.pack('<I', len(name)) + name.encode() + b'\0').hex()
        fields = {6: name, 7: 'org.freedesktop.DBus', 8: 's'}
        hello = dict(type=2, fields={**fields, 5: 1}, body=body)
        get_id = dict(type=2, fields={**fields, 5: 2}, body='0102')
        acquired = dict(type=4, fields={3: 'NameAcquired', 6: name}, body=body)
        validate_completion([hello, acquired, get_id], name, '0102')
        validate_completion(json.loads(json.dumps([hello, acquired, get_id])), name, '0102')
        with self.assertRaises(AssertionError):
            validate_completion([get_id, acquired, hello], name, '0102')
        with self.assertRaises(AssertionError):
            validate_completion([hello, acquired, get_id, get_id], name, '0102')

    def test_requires_all_127_offsets_once_in_order(self):
        cases = [dict(split=i, result='PASS') for i in range(1, 128)]
        validate_cases(cases)
        for bad in (cases[:-1], cases[1:], cases + [cases[-1]], [cases[0]] + cases[:-1]):
            with self.subTest(length=len(bad)):
                with self.assertRaises(AssertionError):
                    validate_cases(bad)


if __name__ == '__main__':
    unittest.main()
