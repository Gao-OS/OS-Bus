"""Data-only reference launcher checks; no sockets, actors or daemons."""
import copy
import importlib.util
from pathlib import Path
import unittest
import xml.etree.ElementTree as ET


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name('run_reference.py')
        self.assertTrue(path.is_file(), 'reference launcher is not implemented')
        spec = importlib.util.spec_from_file_location('whole_stream_reference', path)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        identity = dict(pid=31, starttime_ticks=400, uid=1000, euid=1000, gid=100, egid=100)
        connection = dict(pid=31, starttime_ticks=400, fd=4, device=9, inode=50)
        common = dict(observer=':1.0', bus_id='bus-id')
        self.events = [dict(event='ready', identity=identity, **common),
                       dict(event='opened', connection=connection, peer_credentials=[30, 1000, 100]),
                       dict(event='completed', identity=copy.deepcopy(identity),
                            connection=copy.deepcopy(connection), peer_credentials=[30, 1000, 100],
                            source=':1.1', **common),
                       dict(event='closed', source=':1.1', **common),
                       dict(event='result', result='PASS', cases=1, **common)]
        self.process = dict(pid=31, starttime_ticks=400)

    def validate(self):
        # Shared actor owns wire/health semantics. These tests isolate launcher
        # binding to independently captured process and daemon identities.
        self.module.validate_transcript(self.events, lambda events: None,
                                        self.process, 30, 1000, 100)

    def test_complete_transcript_is_bound_without_mutation(self):
        before = copy.deepcopy(self.events)
        self.validate()
        self.assertEqual(self.events, before)

    def test_missing_duplicate_or_reordered_event_is_rejected(self):
        original = copy.deepcopy(self.events)
        for events in (original[:-1], original + [original[-1]], list(reversed(original))):
            with self.subTest(events=events):
                self.events = events
                with self.assertRaises(AssertionError):
                    self.validate()

    def test_process_pid_starttime_and_uid_are_bound(self):
        for index, key, value in ((0, 'pid', 32), (0, 'starttime_ticks', 401),
                                  (2, 'uid', 0), (2, 'egid', 101)):
            with self.subTest(key=key):
                original = self.events[index]['identity'][key]
                self.events[index]['identity'][key] = value
                with self.assertRaises(AssertionError):
                    self.validate()
                self.events[index]['identity'][key] = original

    def test_connected_process_and_kernel_daemon_credentials_are_bound(self):
        for index, key, value in ((1, 'connection', dict(pid=32, starttime_ticks=400)),
                                  (2, 'connection', dict(pid=31, starttime_ticks=401)),
                                  (1, 'peer_credentials', [32, 1000, 100]),
                                  (2, 'peer_credentials', [30, 0, 100])):
            with self.subTest(index=index, key=key):
                original = self.events[index][key]
                self.events[index][key] = value
                with self.assertRaises(AssertionError):
                    self.validate()
                self.events[index][key] = original

    def test_close_and_result_cannot_change_case_or_observer(self):
        for index, key, value in ((3, 'source', ':1.2'), (3, 'observer', ':1.3'),
                                  (4, 'bus_id', 'changed'), (4, 'cases', 0),
                                  (4, 'result', 'FAIL')):
            with self.subTest(index=index, key=key):
                original = self.events[index][key]
                self.events[index][key] = value
                with self.assertRaises(AssertionError):
                    self.validate()
                self.events[index][key] = original

    def test_reference_xml_has_only_explicit_endpoint_and_external_policy(self):
        xml = self.module.reference_config(Path('/tmp/private-c/bus'), 1000)
        root = ET.fromstring(xml)
        self.assertEqual(root.findtext('type'), 'system')
        self.assertEqual([n.text for n in root.findall('listen')], ['unix:path=/tmp/private-c/bus'])
        self.assertEqual([n.text for n in root.findall('auth')], ['EXTERNAL'])
        self.assertEqual([n.tag for n in root], ['type', 'listen', 'auth', 'policy', 'policy'])
        policy = root.find("policy[@user='1000']")
        self.assertEqual([n.attrib for n in policy],
                         [{'send_destination': 'org.freedesktop.DBus'},
                          {'receive_sender': 'org.freedesktop.DBus'}])


if __name__ == '__main__':
    unittest.main()
