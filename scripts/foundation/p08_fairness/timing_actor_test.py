"""No socket traffic; validate transparent I/O and stage/error chronology."""
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from timing_actor import ObservedSocket


class FakeSocket:
    def __init__(self):
        self.timeout, self.sent, self.received = 1.0, [], []

    def sendall(self, data, *args, **kwargs):
        self.sent.append((data, args, kwargs))
        return 'original-result'

    def recvmsg(self, size, *args, **kwargs):
        self.received.append((size, args, kwargs))
        return (b'payload-secret', [], 0, None)

    def gettimeout(self):
        return self.timeout


class TimingActorTest(unittest.TestCase):
    def setUp(self):
        self.worker, self.sock = SimpleNamespace(serial=28), FakeSocket()
        self.observed = ObservedSocket(self.sock, self.worker)
        self.rows = []
        self.patch = patch('timing_actor.record', side_effect=lambda worker, event, **fields: self.rows.append((event, fields)))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_original_bytes_options_results_and_timeout_are_preserved(self):
        self.assertEqual(self.observed.sendall(b'payload-secret', flags=0), 'original-result')
        result = self.observed.recvmsg(16, 1024)
        self.assertEqual(result, (b'payload-secret', [], 0, None))
        self.assertEqual(self.sock.sent, [(b'payload-secret', (), {'flags': 0})])
        self.assertEqual(self.sock.received, [(16, (1024,), {})])
        self.assertEqual(self.observed.gettimeout(), 1.0)
        self.assertNotIn('payload-secret', repr(self.rows))

    def test_timeout_is_rethrown_without_retry_and_persists_exact_stage(self):
        with patch.object(self.sock, 'recvmsg', side_effect=TimeoutError('timed out')) as operation:
            with self.assertRaisesRegex(TimeoutError, 'timed out'):
                self.observed.recvmsg(16, 1024)
            operation.assert_called_once_with(16, 1024)
        self.assertEqual(self.rows[-1], ('socket_error', {'stage': 'recvmsg', 'error_type': 'TimeoutError', 'errno': None}))


if __name__ == '__main__':
    unittest.main()
