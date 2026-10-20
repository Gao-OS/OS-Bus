"""Bounded exact-byte report saves; deterministic barriers, no bus or VM."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import packaged_diagnostics as implementation

BOUND = 64 * 1024


class RecordingDestination:
    def __init__(self, failure=None):
        self.chunks = []
        self.closed = False
        self.failure = failure

    def open(self, mode, encoding=None):
        assert mode == 'w' and encoding in (None, 'utf-8')
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def write(self, text):
        if self.failure is not None:
            raise self.failure
        self.chunks.append(text)
        return len(text)

    def write_text(self, text):
        with self.open('w'):
            return self.write(text)


class PackagedSaveTests(unittest.TestCase):
    def diagnostics(self):
        return implementation.Diagnostics('a' * 32)

    def expected(self, report):
        return (json.dumps(report, indent=2, sort_keys=True) + '\n').encode('utf-8')

    def test_nested_unicode_and_all_report_fields_have_exact_utf8_bytes(self):
        report = {'unicode': '雪 é 😀\n\t\\"', 'nested': [None, True, 1.25, {'z': '終', 'a': -3}],
                  'samples': [{'all': [1, 2]}], 'kills': [{'failed': False}],
                  'healthy': {'count': 1, 'observations': [{'due': 0.05, 'error': 'retained'}]},
                  'counts': {'failed': 1}, 'exclusions': [{'kind': 'health-regular'}]}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'report.json'
            self.diagnostics().save_report(report, target, 7)
            self.assertEqual(target.read_bytes(), self.expected(report))
            self.assertEqual(json.loads(target.read_bytes()), report)

    def test_large_escaped_string_writes_are_bounded_and_exact(self):
        report = {'large': ('雪\\\n"' * BOUND), 'last': '終'}
        destination = RecordingDestination()
        diagnostics = self.diagnostics()
        diagnostics.save_report(report, destination, 8)
        self.assertEqual(''.join(destination.chunks).encode('utf-8'), self.expected(report))
        self.assertTrue(destination.closed)
        self.assertGreater(len(destination.chunks), 1)
        self.assertLessEqual(max(map(len, destination.chunks)), BOUND)
        row = diagnostics.rows[-1]
        self.assertEqual(row['phase_schema'], 2)
        self.assertEqual(row['buffer_characters'], BOUND)
        self.assertEqual(row['payload_characters'], sum(map(len, destination.chunks)))
        self.assertEqual(row['write_chunks'], len(destination.chunks))
        self.assertEqual(row['max_write_characters'], max(map(len, destination.chunks)))

    def test_partial_persistence_before_whole_report_encoding_finishes(self):
        entered, release = threading.Event(), threading.Event()
        errors = []
        report = {'large': 'x' * (BOUND * 3), 'tail': [1, 2, 3]}
        expected = self.expected(report)
        original = json.JSONEncoder.iterencode

        def barrier(encoder, value, *args, **kwargs):
            total, paused = 0, False
            for chunk in original(encoder, value, *args, **kwargs):
                yield chunk
                total += len(chunk)
                if total >= BOUND and not paused:
                    paused = True
                    entered.set()
                    if not release.wait(3):
                        raise AssertionError('finite encoder barrier deadline')

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'report.json'
            def save():
                try:
                    self.diagnostics().save_report(report, target, 9)
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=save, name='bounded-report-save')
            with patch.object(json.JSONEncoder, 'iterencode', barrier):
                thread.start()
                try:
                    self.assertTrue(entered.wait(3), 'encoder barrier entry deadline')
                    self.assertTrue(target.exists(), 'no partial report persisted before encoding completed')
                    partial = target.read_bytes()
                    self.assertGreater(len(partial), 0)
                    self.assertLess(len(partial), len(expected))
                    self.assertTrue(expected.startswith(partial))
                finally:
                    release.set()
                    thread.join(4)
            self.assertFalse(thread.is_alive(), 'save thread not contained')
            self.assertEqual(errors, [])
            self.assertEqual(target.read_bytes(), expected)

    def test_write_failure_propagates_and_retains_receipt_and_closes_output(self):
        failure = OSError('bounded write failure')
        destination = RecordingDestination(failure)
        diagnostics = self.diagnostics()
        with self.assertRaises(OSError) as raised:
            diagnostics.save_report({'large': 'x' * BOUND}, destination, 10)
        self.assertIs(raised.exception, failure)
        self.assertTrue(destination.closed)
        row = diagnostics.rows[-1]
        self.assertEqual(row['error'], repr(failure))
        self.assertEqual(row['operation_index'], 10)
        self.assertEqual(row['phase_schema'], 2)
        self.assertIn('save_finished_ns', row['phases'])
        self.assertNotIn('encode_write_finished_ns', row['phases'])

    def test_encoder_failure_preserves_partial_output_error_and_cleanup(self):
        failure = ValueError('bounded encoder failure')
        destination = RecordingDestination()
        diagnostics = self.diagnostics()
        def broken(encoder, value, *args, **kwargs):
            yield 'x' * (BOUND + 3)
            raise failure
        with patch.object(json.JSONEncoder, 'iterencode', broken):
            with self.assertRaises(ValueError) as raised:
                diagnostics.save_report({'unused': True}, destination, 11)
        self.assertIs(raised.exception, failure)
        self.assertTrue(destination.closed)
        self.assertEqual(destination.chunks, ['x' * BOUND])
        row = diagnostics.rows[-1]
        self.assertEqual(row['error'], repr(failure))
        self.assertEqual(row['payload_characters'], BOUND)
        self.assertEqual(row['write_chunks'], 1)
        self.assertIn('save_finished_ns', row['phases'])
        self.assertNotIn('encode_write_finished_ns', row['phases'])


if __name__ == '__main__':
    unittest.main()
