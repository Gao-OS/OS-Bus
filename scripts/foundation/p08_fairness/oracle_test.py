"""No bus traffic: disposition fault injection and independent wire vectors."""
import copy
import hashlib
import struct
import unittest

from actor import payload, pulse, request_name_body
from qualify import audit_dispositions, receiver_peer_map


class OracleTest(unittest.TestCase):
    def trace(self):
        rows, failures = [], []
        for target in ['peer%d' % n for n in range(8)]:
            for index, sender in enumerate([':1.1', ':1.2']):
                for n in range(64):
                    serial = 100000 + index * 1000 + n
                    if n == 0:
                        rows.append(dict(target=target, sender=sender, serial=serial,
                            member='FairPulse', bytes=65536,
                            sha256=hashlib.sha256(payload(sender, serial).encode()).hexdigest()))
                    else:
                        failures.append(dict(target=target, bytes=65680, fds=0,
                                             scope='peer', metric='egress_bytes'))
        return dict(rows=rows, failures=failures)

    def audit(self, trace):
        return audit_dispositions(trace, [':1.1', ':1.2'], {'peer%d' % n for n in range(8)})

    def test_complete_disposition(self):
        admitted, rejected = self.audit(self.trace())
        self.assertEqual((len(admitted), len(rejected)), (16, 1008))

    def test_receiver_targets_exclude_producers_observer_and_victim(self):
        peers = [dict(name=':1.%d' % n, peer='peer%d' % (n - 3)) for n in range(1, 13)]
        receiver_names = {':1.%d' % n for n in range(3, 11)}
        targets = receiver_peer_map(peers, receiver_names)
        self.assertEqual(set(targets), receiver_names)
        self.assertEqual(set(targets.values()), {'peer%d' % n for n in range(8)})
        admitted, rejected = audit_dispositions(self.trace(), [':1.1', ':1.2'], set(targets.values()))
        self.assertEqual((len(admitted), len(rejected)), (16, 1008))

    def test_missing_receiver_identity_fails(self):
        names = {':1.%d' % n for n in range(3, 11)}
        peers = [dict(name=name, peer=name) for name in sorted(names)[1:]]
        with self.assertRaisesRegex(AssertionError, 'receiver identity'):
            receiver_peer_map(peers, names)

    def test_duplicate_receiver_peer_fails(self):
        names = {':1.%d' % n for n in range(3, 11)}
        peers = [dict(name=name, peer='same-peer') for name in names]
        with self.assertRaisesRegex(AssertionError, 'receiver identity'):
            receiver_peer_map(peers, names)

    def test_duplicate_receiver_identity_fails(self):
        names = {':1.%d' % n for n in range(3, 11)}
        peers = [dict(name=name, peer=name) for name in sorted(names)]
        peers.append(dict(peers[0], peer='extra-peer'))
        with self.assertRaisesRegex(AssertionError, 'receiver identity'):
            receiver_peer_map(peers, names)

    def test_nonreceiver_delivery_fails(self):
        trace = self.trace()
        trace['rows'][0]['target'] = 'producer'
        with self.assertRaisesRegex(AssertionError, 'unintended'):
            self.audit(trace)

    def test_missing_disposition_fails(self):
        trace = self.trace()
        trace['failures'].pop()
        with self.assertRaisesRegex(AssertionError, 'unexplained'):
            self.audit(trace)

    def test_duplicate_admission_fails_even_if_totals_match(self):
        trace = self.trace()
        trace['rows'].append(copy.deepcopy(trace['rows'][0]))
        trace['failures'].pop()
        with self.assertRaisesRegex(AssertionError, 'duplicate'):
            self.audit(trace)

    def test_wrong_bytes_fail(self):
        trace = self.trace()
        trace['rows'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(AssertionError, 'bytes'):
            self.audit(trace)

    def test_unknown_sender_fails(self):
        trace = self.trace()
        trace['rows'][0]['sender'] = ':1.99'
        with self.assertRaisesRegex(AssertionError, 'unintended'):
            self.audit(trace)

    def test_control_enqueue_failure_fails(self):
        trace = self.trace()
        trace['failures'][0]['bytes'] = 128
        with self.assertRaisesRegex(AssertionError, 'control/call'):
            self.audit(trace)

    def test_receiver_misattribution_fails(self):
        trace = self.trace()
        trace['failures'][0]['target'] = 'peer7'
        with self.assertRaisesRegex(AssertionError, 'receiver'):
            self.audit(trace)

    def test_independent_string_and_header_vectors(self):
        # Independent primitive struct operations; do not derive expectation from helpers.
        packet = pulse(':1.42', 100007)
        order, kind, flags, version, body_size, serial, header_size = struct.unpack_from('<BBBBIII', packet)
        self.assertEqual((order, kind, flags, version, body_size, serial), (108, 4, 0, 1, 65541, 100007))
        body_start = 16 + ((header_size + 7) // 8) * 8
        body = packet[body_start:]
        prefix = b':1.42:100007:'
        self.assertEqual(body, struct.pack('<I', 65536) + prefix + b'x' * (65536 - len(prefix)) + b'\0')
        self.assertEqual(len(packet), body_start + body_size)
        self.assertEqual(request_name_body('ab'), b'\x02\0\0\0ab\0\0\0\0\0\0')
        self.assertEqual(request_name_body('abc'), b'\x03\0\0\0abc\0\0\0\0\0')


if __name__ == '__main__':
    unittest.main()
