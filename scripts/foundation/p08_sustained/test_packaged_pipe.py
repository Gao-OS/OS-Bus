"""Exercise real bounded pipes and teardown, without a bus or guest release."""
import json
import os
import signal
import select
import subprocess
import threading
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from packaged_console import Console


CHILD = r'''
import base64, json, os, re, signal, sys
mode = sys.argv[1]
if mode in ('closed_input', 'stalled_input'):
    if mode == 'closed_input': os.close(0)
    print('READY', flush=True)
    signal.pause()
if mode == 'closed_input_tail': os.close(0)
print('READY', flush=True)
if mode == 'continuous_noise':
    while True: os.write(1, b'noise\xff\n' * 1024)
if mode == 'closed_input_tail':
    sys.stdout.buffer.write(b'pending-tail\xff\n' * 40000)
    sys.stdout.flush()
    signal.pause()
for line in sys.stdin:
    if line == 'System.stop(0)\n':
        if mode == 'duplicate_at_stop':
            sys.stdout.write('\n' + payload)
            sys.stdout.flush()
        break
    request = json.loads(base64.b64decode(re.search(r'reply\("([A-Za-z0-9+/=]+)"\)', line)[1]))
    reply = dict(schema=1, nonce=request['nonce'], request_id=request['request_id'],
                 pid=123, ok=True, result={'event': 'snapshot'})
    if mode == 'stale': reply['request_id'] -= 1
    if mode == 'future': reply['request_id'] += 1
    if mode == 'spoof': reply['nonce'] = 'b' * 32
    if mode == 'missing': del reply['pid']
    if mode == 'eof':
        sys.stdout.buffer.write(b'iex(1)> unfinished\xff')
        sys.stdout.flush()
        break
    if mode == 'oversize':
        sys.stdout.buffer.write(b'x' * 4_259_840)
        sys.stdout.flush()
        continue
    sys.stdout.buffer.write(b'iex(1)> echo\nwarning: noisy console\xff\n')
    sys.stdout.flush()
    encoded = json.dumps(reply)
    if mode == 'invalid_json': encoded = '{broken'
    if mode == 'duplicate_key': encoded = encoded[:-1] + ',"pid":123}'
    payload = 'FIXTURE ' + encoded + '\n'
    if mode == 'duplicate': payload += payload
    sys.stdout.write(payload + ':ok\niex(2)> ')
    sys.stdout.flush()
'''


class PipeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='osbus-console-pipe-')
        self.log = Path(self.temporary.name) / 'console.raw'
        self.channels = []

    def tearDown(self):
        for console in self.channels:
            try:
                console.stop(grace=0.1)
            except (AssertionError, OSError, ValueError):
                # The test separately requires cleanup even when protocol fails.
                pass
            if console.process.poll() is None:
                os.killpg(console.process.pid, signal.SIGKILL)
                console.process.wait(timeout=3)
                console.process.stdin.close()
                console.process.stdout.close()
            self.assertIsNotNone(console.process.poll(), 'owned child not reaped')
        self.temporary.cleanup()

    def channel(self, mode):
        console = Console([sys.executable, '-u', '-c', CHILD, mode], self.log, 'a' * 32)
        self.channels.append(console)
        self.assertEqual(console.process.stdout.readline(), b'READY\n')
        console.bind_pid(123)
        return console

    def test_noisy_non_utf8_console_preserves_bytes_and_binds_each_reply(self):
        console = self.channel('valid')
        self.assertEqual(console.request('snapshot'), {'event': 'snapshot'})
        self.assertEqual(console.request('metrics'), {'event': 'snapshot'})
        logged = self.log.read_bytes()
        stopped = console.stop(grace=1)
        self.assertEqual((stopped['method'], stopped['returncode']), ('console-System.stop', 0))
        self.assertTrue(stopped['tail_eof'])
        self.assertTrue(stopped['service_cgroup_cleanup_required'])
        self.assertEqual(self.log.read_bytes(), logged, 'already logged buffer duplicated')
        self.assertIs(console.stop(), stopped, 'shutdown receipt was not memoized')
        self.assertIn(b'warning: noisy console\xff\n', self.log.read_bytes())

    def test_spoof_stale_future_and_missing_reply_fail(self):
        for mode in ('spoof', 'stale', 'future', 'missing'):
            with self.subTest(mode=mode):
                console = self.channel(mode)
                with self.assertRaises(AssertionError):
                    console.request('snapshot')

    def test_duplicate_response_in_same_pipe_chunk_fails(self):
        console = self.channel('duplicate')
        with self.assertRaisesRegex(AssertionError, 'duplicate|unconsumed'):
            console.request('snapshot')

    def test_delayed_duplicate_cannot_pass_shutdown(self):
        console = self.channel('duplicate_at_stop')
        self.assertEqual(console.request('snapshot'), {'event': 'snapshot'})
        original = os.read
        with patch('packaged_console.os.read', side_effect=lambda fd, size: original(fd, min(size, 3))):
            stopped = console.stop(grace=1)
        self.assertEqual(stopped['protocol_error'], 'unconsumed console reply')
        self.assertEqual(console.process.returncode, 0)

    def test_fragmented_noise_and_response_are_reassembled(self):
        console = self.channel('valid')
        original = os.read
        with patch('packaged_console.os.read', side_effect=lambda fd, size: original(fd, min(size, 3))):
            self.assertEqual(console.request('snapshot'), {'event': 'snapshot'})
        self.assertIn(b'warning: noisy console\xff\n', self.log.read_bytes())

    def test_silent_open_channel_read_has_absolute_deadline(self):
        console = self.channel('stalled_input')
        started = time.monotonic()
        with self.assertRaisesRegex(AssertionError, 'deadline'):
            console.read_reply(time.monotonic() + 0.1)
        self.assertLess(time.monotonic() - started, 1)

    def test_invalid_json_and_duplicate_json_keys_fail(self):
        for mode in ('invalid_json', 'duplicate_key'):
            with self.subTest(mode=mode):
                console = self.channel(mode)
                with self.assertRaises((AssertionError, json.JSONDecodeError)):
                    console.request('snapshot')

    def test_incomplete_eof_is_logged_and_child_reaped(self):
        console = self.channel('eof')
        with self.assertRaisesRegex(AssertionError, 'exited|EOF'):
            console.request('snapshot')
        console.stop(grace=1)
        self.assertIn(b'unfinished\xff', self.log.read_bytes())
        self.assertEqual(console.process.returncode, 0)

    def test_oversize_output_fails_and_raw_prefix_is_saved(self):
        console = self.channel('oversize')
        with self.assertRaisesRegex(AssertionError, 'too large'):
            console.request('snapshot')
        self.assertGreaterEqual(self.log.stat().st_size, 4_194_304)

    def test_closed_input_cannot_bypass_owned_cleanup(self):
        console = self.channel('closed_input')
        try:
            console.stop(grace=0.1)
        except (AssertionError, BrokenPipeError):
            pass
        self.assertIsNotNone(console.process.poll(), 'broken pipe escaped cleanup')

    def test_stalled_input_write_has_absolute_deadline(self):
        console = self.channel('stalled_input')
        self.assertTrue(hasattr(console, 'send_line'), 'no bounded writer')
        started = time.monotonic()
        with self.assertRaisesRegex(AssertionError, 'deadline'):
            console.send_line('x' * 1_048_576, time.monotonic() + 0.1)
        self.assertLess(time.monotonic() - started, 1)

    def test_continuously_readable_noise_uses_original_request_deadline(self):
        console = self.channel('continuous_noise')
        real_select, real_read = select.select, os.read
        clock = [100.0]
        def ready(reads, writes, errors, timeout):
            return real_select(reads, writes, errors, .5 if reads else timeout)
        def advancing_read(fd, size):
            result = real_read(fd, size)
            clock[0] += 1
            return result
        with patch('packaged_console.time.monotonic', side_effect=lambda: clock[0]), \
             patch('packaged_console.select.select', side_effect=ready), \
             patch('packaged_console.os.read', side_effect=advancing_read):
            with self.assertRaisesRegex(AssertionError, 'drain deadline'):
                console.request('snapshot')
        self.assertLessEqual(clock[0], 111, 'drain restarted the original budget')
        self.assertGreater(self.log.stat().st_size, 0, 'observed noise was lost')

    def test_outside_wrapper_group_writer_cannot_extend_shutdown_tail(self):
        console = self.channel('valid')
        read_fd, write_fd = os.pipe()
        writer = subprocess.Popen([sys.executable, '-u', '-c',
            "import os;\nwhile True: os.write(1,b'tail\\xff\\n'*1024)"],
            stdin=subprocess.DEVNULL, stdout=write_fd, stderr=subprocess.DEVNULL,
            start_new_session=True)
        os.close(write_fd)
        console.process.stdout.close()
        console.process.stdout = os.fdopen(read_fd, 'rb', buffering=0)
        completed, errors, result = threading.Event(), [], []
        real_read, real_select = os.read, select.select
        def pipe_read(fd, size):
            if fd == read_fd:
                real_select([fd], [], [], .2)
            return real_read(fd, size)
        def shutdown():
            try:
                result.append(console.stop(grace=.1))
            except BaseException as error:
                errors.append(error)
            finally:
                completed.set()
        try:
            with patch('packaged_console.os.read', side_effect=pipe_read):
                thread = threading.Thread(target=shutdown)
                thread.start()
                bounded = completed.wait(timeout=.5)
                writer.terminate()
                writer.wait(timeout=3)
                thread.join(timeout=3)
            self.assertFalse(thread.is_alive(), 'owned shutdown thread not reaped')
            self.assertTrue(bounded, 'outside-group output escaped the absolute shutdown budget')
            self.assertEqual(errors, [])
            self.assertEqual(result[0]['tail_error'], 'stdout drain deadline')
            self.assertFalse(result[0]['tail_eof'])
            self.assertNotEqual(result[0]['method'], 'console-System.stop')
            self.assertIsNotNone(console.process.poll(), 'owned wrapper not reaped')
            self.assertIn(b'tail\xff\n', self.log.read_bytes(), 'observed final bytes lost')
        finally:
            if writer.poll() is None:
                writer.kill()
            writer.wait(timeout=3)
            if 'thread' in locals():
                thread.join(timeout=3)

    def test_broken_live_stdin_preserves_pending_tail_without_whole_log_read(self):
        console = self.channel('closed_input_tail')
        with patch.object(Path, 'read_bytes', side_effect=AssertionError('whole raw log read')):
            stopped = console.stop(grace=.2)
        self.assertIn('shutdown_error', stopped)
        self.assertIsNotNone(console.process.poll(), 'broken live input escaped wrapper reaping')
        self.assertGreater(self.log.stat().st_size, 0, 'pending raw output was discarded')
        self.assertIn(b'pending-tail\xff\n', self.log.read_bytes())


if __name__ == '__main__':
    unittest.main()
