"""Pure adapter controls; never import or execute the guest fixture or its gates."""
import ast
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import textwrap
import unittest
import xml.etree.ElementTree as ET

from normalize import NEW_REQUEST_BOUNDARY, OLD_REQUEST_BOUNDARY
import normalize


class RequestDeadlineTest(unittest.TestCase):
    def boundary(self, source, *, ok=True, response_time=0.011921627):
        clock = SimpleNamespace(value=response_time)
        writes = []

        class Journal:
            def __enter__(self):
                clock.value += 1.25
                return self

            def write(self, value):
                writes.append(json.loads(value))

            def __exit__(self, *_):
                return False

        class Directory:
            def __truediv__(self, name):
                self.assert_name = name
                return self

            def open(self, mode):
                assert self.assert_name == 'requests.jsonl' and mode == 'a'
                return Journal()

        row = dict(elapsed_ms=response_time * 1000, response=dict(ok=ok))
        context = dict(time=SimpleNamespace(monotonic=lambda: clock.value), limit=1,
                       response=row['response'], directory=Directory(), json=json, row=row)
        return lambda: exec(textwrap.dedent(source), context), row, writes

    def test_original_failure_is_after_a_timely_response(self):
        run, row, writes = self.boundary(OLD_REQUEST_BOUNDARY)
        with self.assertRaises(AssertionError):
            run()
        self.assertEqual(writes, [row])

    def test_timely_response_survives_slow_journaling(self):
        run, row, writes = self.boundary(NEW_REQUEST_BOUNDARY)
        run()
        self.assertEqual(writes, [row])

    def test_late_response_still_fails_and_is_journaled(self):
        run, row, writes = self.boundary(NEW_REQUEST_BOUNDARY, response_time=1.001)
        with self.assertRaises(AssertionError):
            run()
        self.assertEqual(writes, [row])

    def test_error_response_still_fails_and_is_journaled(self):
        run, row, writes = self.boundary(NEW_REQUEST_BOUNDARY, ok=False)
        with self.assertRaises(AssertionError):
            run()
        self.assertEqual(writes, [row])


class PersistenceTest(unittest.TestCase):
    def sources(self, name):
        root = Path(__file__).absolute().parents[3]
        fixture = root / ('test/reports/foundation/continuation-20261011-full-goal/'
                          'environment/m1-sec09-sec12-complete1/source1/fixture1')
        source = (fixture / name).read_text()
        if name == 'run.py':
            for before, after in [
                (normalize.OLD_NATIVE_SERIAL_COUNT, normalize.OLD_NATIVE_SERIAL_COUNT + " if backend=='gao_bus' else 'UNSUPPORTED'"),
                (OLD_REQUEST_BOUNDARY, NEW_REQUEST_BOUNDARY),
                (normalize.OLD_BACKEND_PERSIST, normalize.NEW_BACKEND_PERSIST)]:
                source = source.replace(before, after)
            expected_sha = 'ef2779f6775eb7761127c141d2a459631d16ceab5648fba7f3f47d055930a226'
        else:
            source = source.replace(normalize.OLD_REPORT_PERSIST, normalize.NEW_REPORT_PERSIST)
            expected_sha = '0532c58af3f372726c283c94bee6e8e3a7b7229c29d0d9dc10702cc9f59f02e5'
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(), expected_sha)
        self.assertTrue(hasattr(normalize, 'defer_persistence'), 'revision5 persistence correction missing')
        changes = (normalize.RUN_PERSIST_CHANGES if name == 'run.py' else normalize.COLLECT_PERSIST_CHANGES)
        return source, normalize.defer_persistence(source, changes)

    def main(self, source):
        return next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'main')

    def test_only_four_accumulating_writes_are_removed(self):
        class RemoveAccumulatingWrites(ast.NodeTransformer):
            def generic_visit(self, node):
                super().generic_visit(node)
                for key, value in ast.iter_fields(node):
                    if not isinstance(value, list):
                        continue
                    kept = []
                    for statement in value:
                        previous = ast.unparse(kept[-1]) if kept and isinstance(kept[-1], ast.stmt) else ''
                        accumulating = (previous in ("current['operations'].append(record)", "current['cases'].append(value)",
                                                     "report['corpus_pairs'] += len(row['cases'])", "row['gate_commands'][req] = command"))
                        if isinstance(statement, ast.Expr) and ast.unparse(statement) == 'persist()' and accumulating:
                            continue
                        kept.append(statement)
                    setattr(node, key, kept)
                return node

        for name, retained in [('run.py', 4), ('collect.py', 3)]:
            with self.subTest(name=name):
                original, corrected = self.sources(name)
                expected = RemoveAccumulatingWrites().visit(ast.parse(original))
                self.assertEqual(ast.dump(ast.parse(corrected)), ast.dump(expected))
                calls = [n for n in ast.walk(ast.parse(corrected)) if isinstance(n, ast.Call)
                         and isinstance(n.func, ast.Name) and n.func.id == 'persist']
                self.assertEqual(len(calls), retained)

    def test_backend_success_and_failure_keep_final_values(self):
        _, source = self.sources('run.py')
        main = self.main(source)
        persist = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'persist')
        runtime = next(n for n in main.body if isinstance(n, ast.Try))
        append_lines = [line.strip() for line in source.splitlines()
                        if "current['operations'].append(record)" in line or "current['cases'].append(value)" in line]
        for fail in (False, True):
            with self.subTest(fail=fail):
                current = dict(status='running', operations=[], cases=[], authority_deadline=360)
                context, writes = self.persistence_context('current', current, persist)
                context.update(record=dict(result='unchanged'), value=dict(checks=dict(allowed=False)), probes={}, fail=fail,
                               time=SimpleNamespace(monotonic=lambda: 20), started=0)
                body = ast.parse('\n'.join(append_lines) + '\nif fail: raise ValueError("control failure")').body
                controlled = ast.Try(body=body, handlers=deepcopy(runtime.handlers), orelse=[],
                                     finalbody=[deepcopy(runtime.finalbody[-1])])
                module = ast.fix_missing_locations(ast.Module(body=[deepcopy(main.body[
                    next(i for i, n in enumerate(main.body) if isinstance(n, ast.Expr) and ast.unparse(n) == 'persist()')
                ]), controlled] + deepcopy(main.body[main.body.index(runtime) + 1:main.body.index(runtime) + 3]), type_ignores=[]))
                if fail:
                    with self.assertRaisesRegex(ValueError, 'control failure'):
                        exec(compile(module, '<pure-backend-persistence>', 'exec'), context)
                else:
                    exec(compile(module, '<pure-backend-persistence>', 'exec'), context)
                self.assertEqual(len(writes), 3)
                self.assertEqual(writes[-1], current)
                self.assertEqual(current['operations'], [dict(result='unchanged', probes={})])
                self.assertEqual(current['cases'], [dict(checks=dict(allowed=False))])
                self.assertEqual(current['authority_deadline'], 360)
                if fail:
                    self.assertEqual(writes[-1]['status'], 'failed_unexpected')
                    self.assertIn('control failure', writes[-1]['failure'])
                else:
                    self.assertEqual(writes[-1]['authority_elapsed_ms'], 20000)

    def test_collector_success_and_failure_keep_gate_counts(self):
        _, source = self.sources('collect.py')
        main = self.main(source)
        persist = next(n for n in main.body if isinstance(n, ast.FunctionDef) and n.name == 'persist')
        runtime = next(n for n in main.body if isinstance(n, ast.Try))
        append = next(line.strip() for line in source.splitlines() if "report['backends'].append(row)" in line)
        gate = next(line.strip() for line in source.splitlines() if "row['gate_commands'][req]=command" in line)
        final = next(line.strip() for line in source.splitlines() if "report['collection_complete']=True" in line)
        for fail in (False, True):
            with self.subTest(fail=fail):
                report = dict(backends=[], corpus_pairs=0, collection_complete=False, authority_deadline=360)
                context, writes = self.persistence_context('report', report, persist)
                context.update(row=dict(cases=[1, 2]), collection=dict(exit=0), req='SEC-09', command=dict(exit=1),
                               time=SimpleNamespace(monotonic=lambda: 20), started=0, fail=fail,
                               validate_complete=lambda value: self.assertEqual(value['counts']['failed'], 1))
                body = ast.parse(append + '\n' + gate + '\nif fail: raise ValueError("control failure")\n' + final).body
                controlled = ast.Try(body=body, handlers=deepcopy(runtime.handlers), orelse=[], finalbody=[])
                module = ast.fix_missing_locations(ast.Module(body=[ast.Expr(value=ast.Call(
                    func=ast.Name(id='persist', ctx=ast.Load()), args=[], keywords=[])), controlled], type_ignores=[]))
                if fail:
                    with self.assertRaisesRegex(ValueError, 'control failure'):
                        exec(compile(module, '<pure-collector-persistence>', 'exec'), context)
                else:
                    exec(compile(module, '<pure-collector-persistence>', 'exec'), context)
                self.assertEqual(len(writes), 2)
                self.assertEqual(writes[-1], report)
                self.assertEqual(report['counts'], dict(selected=8, executed=1, passed=0, failed=1, blocked=7, skipped=0))
                self.assertEqual(report['corpus_pairs'], 2)
                self.assertEqual(report['authority_deadline'], 360)
                self.assertEqual(report['collection_complete'], not fail)
                if fail:
                    self.assertIn('control failure', report['collection_failure'])

    def persistence_context(self, key, value, definition):
        writes = []

        class MemoryPath:
            def __truediv__(self, _):
                return self

            def write_text(self, text):
                self.text = text

            def replace(self, _):
                writes.append(json.loads(self.text))

        path = MemoryPath()
        context = {key: value, 'directory': path, 'evidence': path, 'json': json}
        module = ast.fix_missing_locations(ast.Module(body=[deepcopy(definition)], type_ignores=[]))
        exec(compile(module, '<pure-persist-function>', 'exec'), context)
        return context, writes


class XmlSafetyTest(unittest.TestCase):
    def fixture(self, name):
        root = Path(__file__).absolute().parents[3]
        return (root / ('test/reports/foundation/continuation-20261011-full-goal/'
                        'environment/m1-sec09-sec12-complete1/source1/fixture1') / name).read_text()

    def test_same_xml_startup_omits_legacy_limits_and_reports_live_limits(self):
        source = self.fixture('transformed-daemon.exs')
        self.assertTrue(hasattr(normalize, 'patch_xml_daemon'), 'XML safety correction missing')
        corrected = normalize.patch_xml_daemon(source)
        injection = 'Application.put_env(:gao_bus, :resource_limits, GaoBus.Limits.defaults())'
        clearing = 'Application.delete_env(:gao_bus, :resource_limits)'
        reporting = 'resource_limits: elem(GaoBus.Limits.snapshot(), 1).limits'
        self.assertNotIn(injection, corrected)
        self.assertNotIn('GaoBus.Limits.defaults()', corrected)
        self.assertEqual(corrected.count(clearing), 1)
        self.assertLess(corrected.index(clearing), corrected.index('Application.ensure_all_started'))
        self.assertEqual(corrected.count(reporting), 1)
        self.assertGreater(corrected.index(reporting), corrected.index('Application.ensure_all_started'))
        for before, after in reversed(normalize.SNAPSHOT_DAEMON_CHANGES):
            corrected = corrected.replace(after, before)
        self.assertEqual(corrected.replace(clearing, injection).replace(
            reporting, 'resource_limits: GaoBus.Limits.defaults()'), source)

    def test_changed_or_already_patched_xml_fixture_is_rejected(self):
        self.assertTrue(hasattr(normalize, 'patch_xml_daemon'), 'XML safety correction missing')
        source = self.fixture('transformed-daemon.exs')
        for invalid in [source + '\n', source.replace(':system', ':session'),
                        normalize.patch_xml_daemon(source)]:
            with self.subTest(sha=hashlib.sha256(invalid.encode()).hexdigest()):
                with self.assertRaises(AssertionError):
                    normalize.patch_xml_daemon(invalid)

    def test_launcher_provenance_and_expected_event_follow_effective_source(self):
        self.assertTrue(hasattr(normalize, 'patch_xml_daemon'), 'XML safety correction missing')
        corrected = normalize.patch_xml_daemon(self.fixture('transformed-daemon.exs'))
        digest = hashlib.sha256(corrected.encode()).hexdigest()
        launcher = normalize.patch_launcher(self.fixture('launcher.exs'))
        self.assertEqual(launcher.count(digest), 2)
        self.assertNotIn(normalize.XML_DAEMON_SHA, launcher)
        expected = json.loads(self.fixture('PROVENANCE_EXPECTED1.json'))
        expected['transformed_sha256'] = digest
        self.assertEqual(json.loads(normalize.patch_provenance(
            self.fixture('PROVENANCE_EXPECTED1.json'))), expected)


class RequestedReplyPolicyTest(unittest.TestCase):
    def test_only_uid1102_reply_denies_gain_two_explicit_attributes(self):
        source = XmlSafetyTest().fixture('rules.conf').encode()
        self.assertTrue(hasattr(normalize, 'patch_requested_reply_denies'),
                        'explicit requested-reply deny correction missing')
        corrected = normalize.patch_requested_reply_denies(source)
        before, after = ET.fromstring(source), ET.fromstring(corrected)
        changes = []
        for old_policy, policy in zip(before, after):
            self.assertEqual(old_policy.attrib, policy.attrib)
            self.assertEqual(len(old_policy), len(policy))
            for old_rule, rule in zip(old_policy, policy):
                self.assertEqual(old_rule.tag, rule.tag)
                if old_rule.attrib != rule.attrib:
                    self.assertEqual(policy.attrib, {'user': '1102'})
                    self.assertEqual(rule.tag, 'deny')
                    self.assertEqual(rule.attrib, old_rule.attrib | {'receive_requested_reply': 'true'})
                    changes.append(rule.attrib['receive_type'])
        self.assertEqual(changes, ['method_return', 'error'])
        for kind in changes:
            corrected = corrected.replace(
                f'<deny receive_type="{kind}" receive_requested_reply="true"/>'.encode(),
                f'<deny receive_type="{kind}"/>'.encode(), 1)
        self.assertEqual(corrected, source)

    def test_missing_duplicate_or_already_patched_targets_are_rejected(self):
        self.assertTrue(hasattr(normalize, 'patch_requested_reply_denies'))
        source = XmlSafetyTest().fixture('rules.conf').encode()
        target = b'<deny receive_type="method_return"/>'
        for invalid in [source.replace(target, b'', 1), source.replace(target, target * 2, 1),
                        normalize.patch_requested_reply_denies(source)]:
            with self.subTest(source=hashlib.sha256(invalid).hexdigest()):
                with self.assertRaises(AssertionError):
                    normalize.patch_requested_reply_denies(invalid)


class CopiedHelperConstructionTest(unittest.TestCase):
    def test_read_only_copied_directory_is_restored_after_helper_creation(self):
        self.assertTrue(hasattr(normalize, 'write_daemon_channel'), 'read-only copy construction missing')
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name) / 'copied-fixtures'
            folder.mkdir(mode=0o555)
            try:
                helper, original_mode = normalize.write_daemon_channel(folder)
                self.assertEqual(original_mode, 0o555)
                self.assertEqual(folder.stat().st_mode & 0o777, 0o555)
                self.assertEqual(helper.stat().st_mode & 0o777, 0o444)
                self.assertEqual(helper.read_text(), normalize.DAEMON_CHANNEL_SOURCE)
            finally:
                folder.chmod(0o755)

    def test_failed_helper_creation_restores_exact_copied_directory_mode(self):
        self.assertTrue(hasattr(normalize, 'write_daemon_channel'), 'read-only copy construction missing')
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name) / 'copied-fixtures'
            folder.mkdir()
            (folder / 'daemon_channel.py').mkdir()
            folder.chmod(0o550)
            try:
                with self.assertRaises(IsADirectoryError):
                    normalize.write_daemon_channel(folder)
                self.assertEqual(folder.stat().st_mode & 0o777, 0o550)
            finally:
                folder.chmod(0o755)


class DaemonFileChannelTest(unittest.TestCase):
    """Harmless Python stdout stubs only; no bus, actor, guest program or gate."""
    STUB = '''import os,sys
from pathlib import Path
os.write(1,b'FIXTURE {"event":"ready"}\\n')
for command in sys.stdin.buffer:
    if command == b'snapshot\\n':
        data=Path(sys.argv[1]).read_bytes()
        for offset in range(0,len(data),8191):
            view=memoryview(data[offset:offset+8191])
            while view:
                view=view[os.write(1,view):]
    elif command == b'finish\\n':
        os.write(1,b'1}\\nFIXTURE {"event":"next"}\\n')
    elif command == b'quit\\n':
        break
'''

    def legacy(self):
        source = XmlSafetyTest().fixture('inherited/security/run.py')
        channel = next(n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name == 'Channel')
        context = dict(os=os, select=select, signal=signal, subprocess=subprocess, time=time, json=json)
        exec(compile(ast.fix_missing_locations(ast.Module(body=[channel], type_ignores=[])),
                     '<isolated-legacy-channel>', 'exec'), context)
        return SimpleNamespace(Channel=context['Channel'])

    def channel_class(self):
        self.assertTrue(hasattr(normalize, 'DAEMON_CHANNEL_SOURCE'), 'daemon file transport missing')
        context = {}
        exec(normalize.DAEMON_CHANNEL_SOURCE, context)
        return context['channel_class'](self.legacy())

    def cleanup(self, channel):
        context = {}
        exec(XmlSafetyTest().fixture('cleanup.py'), context)
        return context['stop_channel'](channel, {'pid': channel.process.pid})

    def retain(self, label, folder, result):
        target = os.environ.get('OSBUS_CHANNEL_CONTROL_EVIDENCE')
        if target:
            directory = Path(target)
            (directory / (label + '.raw.log')).write_bytes((folder / 'daemon.log').read_bytes())
            (directory / (label + '.json')).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')

    def large_payload(self):
        root = Path(__file__).absolute().parents[3]
        log = root / ('test/reports/foundation/resume-20261019/runtime-authorization/vm10/'
                      'out/authorization-current-evidence/sec09-sec12-complete/gao_bus/daemon.log')
        lines = log.read_bytes().splitlines(keepends=True)
        self.assertEqual(len(lines[13]), 367850)
        return b'ordinary log\n' + lines[12] + lines[13] + b'FIXTURE {"event":"end"}\n'

    def start(self, folder, payload, cls):
        data = folder / 'payload'
        data.write_bytes(payload)
        return cls([sys.executable, '-B', '-c', self.STUB, str(data)], folder / 'daemon.log', 'FIXTURE ')

    def send(self, channel, command):
        channel.process.stdin.write(command + b'\n')
        channel.process.stdin.flush()

    def test_legacy_pipe_reproduces_failed_five_second_natural_retirement(self):
        with tempfile.TemporaryDirectory() as name:
            channel = self.start(Path(name), self.large_payload(), self.legacy().Channel)
            try:
                self.assertEqual(channel.read(), {'event': 'ready'})
                self.send(channel, b'snapshot')
                self.send(channel, b'quit')
                result = self.cleanup(channel)
                self.assertTrue(result['before_containment']['timed_out'])
                self.assertFalse(result['before_containment']['wrapper_waited'])
                self.assertGreaterEqual(result['before_containment']['elapsed_ms'], 5000)
                self.assertNotEqual(result['method'], 'eof')
                self.assertTrue(result['pid_absent'] and result['group_absent'])
                self.retain('legacy-pipe-natural-retirement', Path(name), result)
            finally:
                if channel.process.poll() is None:
                    channel.stop()

    def test_unread_large_output_retires_naturally_and_retains_exact_raw_bytes(self):
        cls = self.channel_class()
        payload = self.large_payload()
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            channel = self.start(folder, payload, cls)
            try:
                self.assertEqual(channel.read(), {'event': 'ready'})
                self.send(channel, b'snapshot')
                self.send(channel, b'quit')
                result = self.cleanup(channel)
                self.assertTrue(result['before_containment']['wrapper_waited'])
                self.assertFalse(result['before_containment']['timed_out'])
                self.assertEqual((result['method'], result['returncode']), ('eof', 0))
                self.assertEqual((folder / 'daemon.log').read_bytes(), b'FIXTURE {"event":"ready"}\n' + payload)
                self.retain('file-unread-natural-retirement', folder, result)
            finally:
                if channel.process.poll() is None:
                    channel.stop()

    def test_large_frames_keep_order_remainder_and_raw_bytes(self):
        cls = self.channel_class()
        payload = self.large_payload()
        expected = [json.loads(line[8:]) for line in payload.splitlines() if line.startswith(b'FIXTURE ')]
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            channel = self.start(folder, payload, cls)
            try:
                channel.read()
                self.send(channel, b'snapshot')
                self.assertEqual([channel.read(timeout=1) for _ in expected], expected)
                self.send(channel, b'quit')
                result = self.cleanup(channel)
                self.assertEqual(result['returncode'], 0)
                self.assertEqual((folder / 'daemon.log').read_bytes(), b'FIXTURE {"event":"ready"}\n' + payload)
                self.retain('file-frame-order', folder, result)
            finally:
                if channel.process.poll() is None:
                    channel.stop()

    def test_deadline_retains_partial_frame_then_resumes_in_order(self):
        cls = self.channel_class()
        payload = b'ordinary\nFIXTURE {"value":'
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            channel = self.start(folder, payload, cls)
            try:
                channel.read()
                self.send(channel, b'snapshot')
                with self.assertRaisesRegex(AssertionError, 'channel deadline'):
                    channel.read(timeout=0.05)
                self.assertEqual(channel.buffer, b'FIXTURE {"value":')
                self.send(channel, b'finish')
                self.assertEqual(channel.read(timeout=1), {'value': 1})
                self.assertEqual(channel.read(timeout=1), {'event': 'next'})
                self.send(channel, b'quit')
                result = self.cleanup(channel)
                self.assertEqual((folder / 'daemon.log').read_bytes(),
                                 b'FIXTURE {"event":"ready"}\n' + payload + b'1}\nFIXTURE {"event":"next"}\n')
                self.retain('file-partial-deadline-resume', folder, result)
            finally:
                if channel.process.poll() is None:
                    channel.stop()

    def test_line_limit_and_eof_remain_failures(self):
        cls = self.channel_class()
        for payload, message in [(b'x' * 4194305, 'fixture output line too large'),
                                 (b'FIXTURE {"partial":', 'process exited')]:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as name:
                folder = Path(name)
                channel = self.start(folder, payload, cls)
                try:
                    channel.read()
                    self.send(channel, b'snapshot')
                    self.send(channel, b'quit')
                    with self.assertRaisesRegex(AssertionError, message):
                        channel.read(timeout=1)
                    result = self.cleanup(channel)
                    self.assertEqual(result['returncode'], 0)
                    self.assertEqual((folder / 'daemon.log').read_bytes(), b'FIXTURE {"event":"ready"}\n' + payload)
                    self.retain('file-' + message.replace(' ', '-'), folder, result)
                finally:
                    if channel.process.poll() is None:
                        channel.stop()

    def test_read_zero_deadline_still_rejects_buffered_data(self):
        cls = self.channel_class()
        with tempfile.TemporaryDirectory() as name:
            channel = self.start(Path(name), b'', cls)
            try:
                channel.read()
                channel.buffer = b'FIXTURE {"already":"buffered"}\n'
                with self.assertRaisesRegex(AssertionError, 'channel deadline'):
                    channel.read(timeout=0)
            finally:
                self.cleanup(channel)

    def test_genuinely_stalled_writer_still_fails_natural_retirement(self):
        cls = self.channel_class()
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            stub = 'import os,signal\nos.write(1,b\'FIXTURE {"partial":\')\nsignal.pause()\n'
            channel = cls([sys.executable, '-B', '-c', stub], folder / 'daemon.log', 'FIXTURE ')
            try:
                with self.assertRaisesRegex(AssertionError, 'channel deadline'):
                    channel.read(timeout=0.05)
                result = self.cleanup(channel)
                self.assertTrue(result['before_containment']['timed_out'])
                self.assertFalse(result['before_containment']['wrapper_waited'])
                self.assertEqual((result['method'], result['returncode']), ('terminate', -signal.SIGTERM))
                self.assertEqual((folder / 'daemon.log').read_bytes(), b'FIXTURE {"partial":')
                self.retain('file-genuine-stall', folder, result)
            finally:
                if channel.process.poll() is None:
                    channel.stop()

    def test_stop_wait_signal_sequence_and_default_deadlines_match_legacy(self):
        self.assertTrue(hasattr(normalize, 'DAEMON_CHANNEL_SOURCE'))
        original = ast.parse(XmlSafetyTest().fixture('inherited/security/run.py'))
        patched = ast.parse(normalize.DAEMON_CHANNEL_SOURCE)
        old = next(n for n in ast.walk(original) if isinstance(n, ast.FunctionDef) and n.name == 'stop')
        new = next(n for n in ast.walk(patched) if isinstance(n, ast.FunctionDef) and n.name == 'stop')
        self.assertEqual(ast.dump(old.args), ast.dump(new.args))
        # The shared method/close/wait/TERM/KILL/group-containment block is exact.
        self.assertEqual([ast.dump(n) for n in old.body[:4]], [ast.dump(n) for n in new.body[:4]])


class SnapshotObservationTest(unittest.TestCase):
    def test_actual_emitters_preserve_saved_unicode_and_nested_events(self):
        self.assertTrue(hasattr(normalize, 'NEW_EMIT'), 'iodata emitter missing')
        root = Path(__file__).absolute().parents[3]
        raw = root / ('test/reports/foundation/resume-20261019/runtime-authorization/vm11/'
                      'out/authorization-current-evidence/sec09-sec12-complete/gao_bus/daemon.log')
        events = [json.loads(line[8:]) for line in raw.read_bytes().splitlines()
                  if line.startswith(b'FIXTURE ')]
        events.append({'event': 'synthetic', 'unicode': '中文 café 😀',
                       'escaped': 'quote" slash\\ newline\n tab\t control\x00',
                       'nested': [None, True, False, 0, -12, 1.25, [], {}, {'x': [1, 'λ']} ]})
        original = XmlSafetyTest().fixture('transformed-daemon.exs')
        corrected = normalize.patch_xml_daemon(original)
        old = next(line for line in original.splitlines() if line.startswith('emit ='))
        new = next(line for line in corrected.splitlines() if line.startswith('emit ='))
        self.assertEqual(new, normalize.NEW_EMIT)
        runtime = json.loads(Path('/nix/store/3i9qh231qir81ib0l92dhi3y0943bp9a-osbus-authorization-runtime.json').read_text())['runtime']
        script = r'''
[events_path, old_path, new_path, timing_path, daemon_path, output] = System.argv()
Code.string_to_quoted!(File.read!(daemon_path))
events = :json.decode(File.read!(events_path))
capture = fn source, values ->
  {:ok, device} = StringIO.open("")
  previous = Process.group_leader()
  Process.group_leader(self(), device)
  try do
    {emit, _} = Code.eval_string(source)
    Enum.each(values, fn value ->
      case emit.(value) do
        {:snapshot_timing, sample} ->
          true = Enum.sort(Map.keys(sample)) == [:capture_ns, :encode_ns, :write_ns]
          true = Enum.all?(Map.values(sample), &(is_integer(&1) and &1 >= 0))
        :ok -> :ok
      end
    end)
    {_, bytes} = StringIO.contents(device)
    bytes
  after
    Process.group_leader(self(), previous)
    StringIO.close(device)
  end
end
old = capture.(File.read!(old_path), events)
new = capture.(File.read!(new_path), events)
true = old == new
File.write!(Path.join(output, "old.raw"), old)
File.write!(Path.join(output, "new.raw"), new)
# Execute only the extracted timing closure, with pure snapshot data.
timed = File.read!(timing_path)
timing_source = "fn event ->\nsafe_snapshot = fn -> event end\n" <> timed <> "\ntimed_snapshot.()\nend"
timed_bytes = capture.(timing_source, events)
true = timed_bytes == old
File.write!(Path.join(output, "timed.raw"), timed_bytes)
{failed_capture, _} = Code.eval_string(timed, safe_snapshot: fn -> raise "unchanged capture failure" end)
try do
  failed_capture.()
  raise "capture failure was swallowed"
rescue
  exception in RuntimeError -> "unchanged capture failure" = exception.message
end
IO.puts("exact old/new/timed emitter output equivalence passed")
'''
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            (folder / 'events.json').write_text(json.dumps(events, ensure_ascii=False))
            (folder / 'old.exs').write_text(old)
            (folder / 'new.exs').write_text(new)
            (folder / 'timing.exs').write_text(normalize.TIMED_SNAPSHOT)
            (folder / 'daemon.exs').write_text(corrected)
            (folder / 'original-daemon.exs').write_text(original)
            (folder / 'check.exs').write_text(script)
            env = os.environ.copy()
            env['PATH'] = runtime['otp_store'] + '/bin:' + env['PATH']
            baseline_command = [runtime['elixir_store'] + '/bin/elixir', '--erl', '+S 2:2',
                                '-e', 'Code.string_to_quoted!(File.read!(hd(System.argv())))',
                                str(folder / 'original-daemon.exs')]
            baseline = subprocess.run(baseline_command, env=env, capture_output=True, timeout=30)
            command = [runtime['elixir_store'] + '/bin/elixir', '--erl', '+S 2:2',
                       str(folder / 'check.exs'), str(folder / 'events.json'), str(folder / 'old.exs'),
                       str(folder / 'new.exs'), str(folder / 'timing.exs'), str(folder / 'daemon.exs'), str(folder)]
            completed = subprocess.run(command, env=env, capture_output=True, timeout=30)
            retained = os.environ.get('OSBUS_CHANNEL_CONTROL_EVIDENCE')
            if retained:
                for label, result in [('original-parser', baseline), ('copied-emitter', completed)]:
                    (Path(retained) / (label + '.stderr.log')).write_bytes(result.stderr)
                    (Path(retained) / (label + '.stdout.log')).write_bytes(result.stdout)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual(baseline.returncode, 0, baseline.stderr.decode())
            self.assertEqual(baseline.stdout, b'')
            # The complete inherited daemon has a charlist parser warning. Keep
            # it visible, and allow only line relocation of the same source text.
            location = r'(?m)^└─ nofile:(\d+):(\d+)$'
            original_locations = re.findall(location, baseline.stderr.decode())
            copied_locations = re.findall(location, completed.stderr.decode())
            self.assertEqual(len(original_locations), len(copied_locations))
            for (old_line, old_column), (new_line, new_column) in zip(original_locations, copied_locations):
                self.assertEqual(old_column, new_column)
                self.assertEqual(original.splitlines()[int(old_line) - 1],
                                 corrected.splitlines()[int(new_line) - 1])
            normalize_location = lambda value: re.sub(location, r'└─ nofile:<source-line>:\2', value.decode())
            self.assertEqual(normalize_location(baseline.stderr), normalize_location(completed.stderr))
            self.assertEqual((folder / 'old.raw').read_bytes(), (folder / 'new.raw').read_bytes())
            decoded = [json.loads(line[8:]) for line in (folder / 'new.raw').read_bytes().splitlines()]
            self.assertEqual(decoded, events)
            if retained:
                for filename in ('old.raw', 'new.raw', 'timed.raw', 'check.exs'):
                    (Path(retained) / ('emitter-' + filename)).write_bytes((folder / filename).read_bytes())
                (Path(retained) / 'emitter-command.json').write_text(json.dumps(dict(
                    argv=command, exit=completed.returncode, stdout=completed.stdout.decode(),
                    stderr=completed.stderr.decode(), events=len(events),
                    baseline_argv=baseline_command, baseline_exit=baseline.returncode,
                    baseline_stderr=baseline.stderr.decode()), indent=2) + '\n')

    def test_runner_timing_preserves_values_errors_assertions_and_numeric_constants(self):
        self.assertTrue(hasattr(normalize, 'RUN_TIMING_CHANGES'), 'snapshot phase timing missing')
        original = XmlSafetyTest().fixture('run.py')
        corrected = normalize.defer_persistence(original, normalize.RUN_TIMING_CHANGES)
        old_tree, tree = ast.parse(original), ast.parse(corrected)
        assertions = lambda value: [ast.dump(node) for node in ast.walk(value) if isinstance(node, ast.Assert)]
        numbers = lambda value: [node.value for node in ast.walk(value)
                                 if isinstance(node, ast.Constant) and type(node.value) in (int, float)]
        self.assertEqual(assertions(old_tree), assertions(tree))
        self.assertEqual(numbers(old_tree), numbers(tree))
        for before, after in reversed(normalize.RUN_TIMING_CHANGES):
            corrected = corrected.replace(after, before)
        self.assertEqual(corrected, original)
        definition = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                          and n.name == 'measure_snapshot_phase')
        clock = iter([10, 30, 40, 70])
        context = dict(time=SimpleNamespace(monotonic_ns=lambda: next(clock)),
                       phase_timings=[], current={'snapshots': [object()]})
        exec(compile(ast.fix_missing_locations(ast.Module(body=[definition], type_ignores=[])),
                     '<pure-measured-phase>', 'exec'), context)
        value = {'full': ['state']}
        self.assertIs(context['measure_snapshot_phase']('external_fds', lambda v: v, value), value)
        def fail(_):
            raise ValueError('unchanged failure')
        with self.assertRaisesRegex(ValueError, 'unchanged failure'):
            context['measure_snapshot_phase']('state_key', fail, value)
        self.assertEqual(context['phase_timings'], [
            dict(phase='external_fds', snapshot_count=1, elapsed_ns=20),
            dict(phase='state_key', snapshot_count=1, elapsed_ns=30)])

    def test_timing_persistence_is_separate_from_backend_values(self):
        self.assertTrue(hasattr(normalize, 'RUN_TIMING_CHANGES'), 'separate timing persistence missing')
        source = normalize.defer_persistence(XmlSafetyTest().fixture('run.py'), normalize.RUN_TIMING_CHANGES)
        definition = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef)
                          and n.name == 'persist')
        with tempfile.TemporaryDirectory() as name:
            current = {'snapshots': [{'complete': True, 'full': ['unchanged']}]}
            context = dict(directory=Path(name), json=json, current=current,
                           phase_timings=[{'phase': 'state_key', 'elapsed_ns': 9}],
                           daemon=SimpleNamespace(phase_timings=[{'read_ns': 7, 'decode_ns': 2}]))
            exec(compile(ast.fix_missing_locations(ast.Module(body=[definition], type_ignores=[])),
                         '<isolated-persist>', 'exec'), context)
            context['persist']()
            self.assertEqual(json.loads((Path(name) / 'backend.json').read_text()), current)
            self.assertEqual(json.loads((Path(name) / 'phase-timings.json').read_text()),
                             dict(controller=context['phase_timings'], daemon_reads=context['daemon'].phase_timings))

    def test_channel_timings_keep_success_decode_errors_and_expired_deadline(self):
        self.assertIn('self.phase_timings', normalize.DAEMON_CHANNEL_SOURCE, 'read/decode timing missing')
        old = Path('/nix/store/xlk7l242c4fnsyfqk65qblp9j9ds8lxw-osbus-authorization-current-inputs/fixtures/daemon_channel.py').read_text()
        old_tree, new_tree = ast.parse(old), ast.parse(normalize.DAEMON_CHANNEL_SOURCE)
        assertions = lambda tree: [ast.dump(n) for n in ast.walk(tree) if isinstance(n, ast.Assert)]
        numbers = lambda tree: [n.value for n in sorted(ast.walk(tree), key=lambda n: (
            getattr(n, 'lineno', -1), getattr(n, 'col_offset', -1)))
            if isinstance(n, ast.Constant) and type(n.value) in (int, float)]
        self.assertEqual(assertions(old_tree), assertions(new_tree))
        self.assertEqual(numbers(old_tree), numbers(new_tree))
        for raw, timeout, expected in [(b'FIXTURE {"event":"snapshot","full":[1]}\n', 1, None),
                                       (b'FIXTURE {broken}\n', 1, json.JSONDecodeError),
                                       (b'FIXTURE {}\n', 0, AssertionError)]:
            with self.subTest(expected=expected):
                clock = iter([10, 20, 30])
                namespace = {}
                exec(normalize.DAEMON_CHANNEL_SOURCE, namespace)
                namespace['time'] = SimpleNamespace(monotonic=lambda: 0,
                                                    monotonic_ns=lambda: next(clock))
                cls = namespace['channel_class'](SimpleNamespace(Channel=object))
                channel = cls.__new__(cls)
                channel.buffer, channel.prefix, channel.command = raw, 'FIXTURE ', ['never executed']
                channel.phase_timings = []
                if expected:
                    with self.assertRaises(expected):
                        channel.read(timeout=timeout)
                else:
                    self.assertEqual(channel.read(timeout=timeout), {'event': 'snapshot', 'full': [1]})
                sample, = channel.phase_timings
                self.assertEqual(sample['decoded'], expected is None)
                self.assertEqual(sample['read_ns'], 10)
                self.assertEqual(sample['decode_ns'], None if timeout == 0 else 10)
                self.assertEqual(sample['total_ns'], 10 if timeout == 0 else 20)


if __name__ == '__main__':
    unittest.main()
