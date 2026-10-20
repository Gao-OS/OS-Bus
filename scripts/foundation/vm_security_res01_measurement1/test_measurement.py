"""Inert focused controls. Root owns execution; no target runner/actor import."""
import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

from measurement import Recorder, apply_recipe

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'vm_security_res01'


def extract_function(name):
    source = (BASE / 'run.py').read_text()
    recipes = json.loads((HERE / 'recipe1.json').read_text())
    transformed = apply_recipe(source, recipes['runner'])
    main = next(n for n in ast.parse(transformed).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    return next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == name)


def load_read(recorder, fake_time, fake_select, fake_os):
    recipe = json.loads((HERE / 'recipe1.json').read_text())['channel'][0]
    namespace = dict(measurement=recorder, time=fake_time, select=fake_select, os=fake_os, json=json)
    exec(compile(recipe['after'], 'inert-measured-Channel-read', 'exec'), namespace)
    return namespace['read']


class MeasurementControls(unittest.TestCase):
    def test_return_identity_and_snapshot_unchanged(self):
        recorder = Recorder(clock=iter([1.0, 1.1]).__next__)
        snapshot = {'state': {'res01': {'accounting': {'peers': {}}}}}
        before = json.dumps(snapshot, sort_keys=True)
        self.assertIs(recorder.timed('snapshot', lambda: snapshot), snapshot)
        self.assertEqual(json.dumps(snapshot, sort_keys=True), before)
        self.assertEqual(len(recorder.events), 1)

    def test_exception_finally_and_original_exception(self):
        recorder = Recorder(clock=iter([1.0, 1.1]).__next__)
        original = AssertionError('original deadline')
        def fail():
            raise original
        with self.assertRaises(AssertionError) as caught:
            recorder.timed('failed_read', fail, deadline=1.05)
        self.assertIs(caught.exception, original)
        self.assertEqual(recorder.events[0]['error']['type'], 'AssertionError')
        self.assertEqual(recorder.events[0]['deadline'], 1.05)

    def test_context_restored_on_failure(self):
        recorder = Recorder()
        recorder.context = dict(dimension='uid_authenticating', trial='1101', phase='trial')
        with self.assertRaises(ValueError):
            with recorder.contextual(phase='reused', attempt=2):
                with recorder.span('failed_capture'):
                    raise ValueError('read')
        self.assertEqual(recorder.context['phase'], 'trial')
        self.assertEqual(recorder.events[0]['phase'], 'reused')
        self.assertEqual(recorder.events[0]['attempt'], 2)

    def test_exact_synchronous_raw_line_logging_and_parse(self):
        writes = []
        class Log:
            def open(self, mode):
                class Output:
                    def __enter__(self):
                        writes.append(('open', mode))
                        return self
                    def write(self, line):
                        writes.append(('write', line))
                    def __exit__(self, *args):
                        writes.append(('close', mode))
                return Output()
        recorder = Recorder(clock=lambda: 0.0)
        read = load_read(recorder, SimpleNamespace(monotonic=lambda: 0.0), None, None)
        channel = SimpleNamespace(buffer=b'noise\nFIXTURE {"event":"snapshot","full":{"peer":"#PID<0.1.0>"}}\n',
            prefix='FIXTURE ', log=Log(), process=SimpleNamespace(pid=55), command=['unchanged'])
        result = read(channel, timeout=0.4)
        self.assertEqual(result, dict(event='snapshot', full={'peer': '#PID<0.1.0>'}))
        self.assertEqual(writes, [('open', 'a'), ('write', 'noise\n'), ('close', 'a'),
            ('open', 'a'), ('write', 'FIXTURE {"event":"snapshot","full":{"peer":"#PID<0.1.0>"}}\n'), ('close', 'a')])
        self.assertEqual(channel.buffer, b'')
        self.assertEqual([e['boundary'] for e in recorder.events],
            ['channel_line_log_append', 'channel_line_log_append', 'channel_json_parse', 'channel_read'])

    def test_failed_parse_retains_raw_log_and_timing(self):
        stream = io.StringIO()
        class Log:
            def open(self, mode):
                class Output:
                    def __enter__(self):
                        return stream
                    def __exit__(self, *args):
                        pass
                return Output()
        recorder = Recorder(clock=lambda: 0.0)
        read = load_read(recorder, SimpleNamespace(monotonic=lambda: 0.0), None, None)
        channel = SimpleNamespace(buffer=b'FIXTURE invalid-json\n', prefix='FIXTURE ', log=Log(),
            process=SimpleNamespace(pid=55), command=['unchanged'])
        with self.assertRaises(json.JSONDecodeError):
            read(channel, timeout=0.4)
        self.assertEqual(stream.getvalue(), 'FIXTURE invalid-json\n')
        self.assertEqual([e['boundary'] for e in recorder.events],
            ['channel_line_log_append', 'channel_json_parse', 'channel_read'])
        self.assertEqual(recorder.events[-1]['error']['type'], 'JSONDecodeError')

    def test_original_channel_deadline_still_fails_without_transport(self):
        recorder = Recorder(clock=lambda: 0.0)
        clock = iter([0.0, 0.5]).__next__
        read = load_read(recorder, SimpleNamespace(monotonic=clock), None, None)
        channel = SimpleNamespace(buffer=b'FIXTURE {}\n', prefix='FIXTURE ', process=SimpleNamespace(pid=55), command=['unchanged'])
        with self.assertRaises(AssertionError):
            read(channel, timeout=0.4)
        self.assertEqual(recorder.events[-1]['channel_deadline'], 0.4)
        self.assertEqual(recorder.events[-1]['error']['type'], 'AssertionError')
        self.assertEqual(channel.buffer, b'FIXTURE {}\n')

    def test_failed_request_retains_begin_read_boundaries(self):
        recorder = Recorder(clock=lambda: 0.0)
        calls = []
        def begin(**values):
            calls.append(('begin', values))
        def read(timeout):
            calls.append(('read', timeout))
            raise AssertionError('held deadline')
        actor = dict(identity=dict(pid=123), channel=SimpleNamespace(begin=begin, read=read))
        namespace = dict(measurement=recorder, authority_deadline=60,
            time=SimpleNamespace(monotonic=lambda: 0), remaining=lambda deadline: deadline,
            report=dict(receipts=[]), persist=lambda: self.fail('must not persist absent receipt'))
        exec(compile(ast.Module(body=[extract_function('request')], type_ignores=[]), 'inert-request', 'exec'), namespace)
        with self.assertRaises(AssertionError):
            namespace['request'](actor, op='complete', deadline=0.4)
        self.assertEqual(calls, [('begin', dict(op='complete', deadline=0.4)), ('read', 0.4)])
        self.assertEqual([e['boundary'] for e in recorder.events], ['request_begin', 'request_read', 'request'])
        self.assertEqual(namespace['report']['receipts'], [])

    def test_original_remaining_held_and_authority_deadlines(self):
        for authority, deadline, now in [(60, 0.4, 0.401), (0.3, 0.4, 0.301)]:
            with self.subTest(authority=authority):
                namespace = dict(authority_deadline=authority, time=SimpleNamespace(monotonic=lambda: now))
                exec(compile(ast.Module(body=[extract_function('remaining')], type_ignores=[]), 'inert-remaining', 'exec'), namespace)
                with self.assertRaises(AssertionError):
                    namespace['remaining'](deadline)


if __name__ == '__main__':
    unittest.main(verbosity=2)
