"""Inert marker/resource-validator controls: no socket, pipe, broker or VM."""
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREDECESSOR = '--predecessor' in sys.argv
if PREDECESSOR:
    sys.argv.remove('--predecessor')
path = HERE.parents[2] / 'scripts/foundation/p08_fd03_different_bundles/actor.py' if PREDECESSOR else HERE / 'actor.py'
spec = importlib.util.spec_from_file_location('fd03_mixed_actor_controls', path)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)
wire = A.load_wire(HERE.parents[2] / 'apps/gao_bus/test/fixtures')

def marker():
    fields = {1: '/foundation', 2: 'org.foundation.Transport', 3: 'Marker', 6: ':1.2', 7: ':1.1', 8: ''}
    raw = wire.frame(4, 101, [(k, 'g' if k == 8 else 'o' if k == 1 else 's', v) for k, v in fields.items()])
    message = dict(type=4, serial=101, fields=fields, body=b'', fds=[])
    event = dict(wire_hex=raw.hex(), rights=0, fd_targets=[])
    return SimpleNamespace(name=':1.2', events=[event]), message

class MarkerControls(unittest.TestCase):
    def setUp(self):
        self.assertTrue(callable(getattr(A, 'validate_marker', None)), 'predecessor lacks strict mixed marker validation')
    def test_marker_no_body_no_header9_no_installed_right(self):
        client, message = marker()
        self.assertEqual(A.validate_marker(client, message, ':1.1'), client.events[-1])
    def test_middle_frame_never_skips_wrong_serial_or_kind(self):
        for change in ({'serial': 100}, {'serial': 102}, {'type': 2}):
            with self.subTest(change=change):
                client, message = marker(); message.update(change)
                with self.assertRaises(AssertionError): A.validate_marker(client, message, ':1.1')
    def test_marker_rejects_even_zero_header9_and_wrong_identity(self):
        for field, value in ((9, 0), (9, 1), (7, ':1.99'), (6, ':1.99'), (3, 'Resource'), (8, 'h')):
            with self.subTest(field=field, value=value):
                client, message = marker(); message['fields'][field] = value
                with self.assertRaises(AssertionError): A.validate_marker(client, message, ':1.1')
    def test_marker_rejects_body_or_any_installed_fd(self):
        for change in ({'body': b'X'}, {'fds': [99]}):
            client, message = marker(); message.update(change)
            with self.assertRaises(AssertionError): A.validate_marker(client, message, ':1.1')
    def test_marker_rejects_raw_flags_and_ancillary_report_disagreement(self):
        for flags, rights, targets in ((1, 0, []), (0, 1, []), (0, 0, [{}])):
            client, message = marker(); raw = bytearray.fromhex(client.events[-1]['wire_hex']); raw[2] = flags
            client.events[-1].update(wire_hex=raw.hex(), rights=rights, fd_targets=targets)
            with self.assertRaises(AssertionError): A.validate_marker(client, message, ':1.1')
    def test_marker_packet_uses_original_encoder_and_omits_count(self):
        expected = wire.frame(4, 101, [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'),
                                     (3, 's', 'Marker'), (6, 's', ':1.2'), (8, 'g', '')], b'')
        self.assertEqual(A.marker_packet(wire, ':1.2'), expected)
    def test_second_resource_serial102_uses_preserved_pipe_validator(self):
        original = dict(fd=10, mode=0o10600, dev=1, ino=20, target='pipe:[20]')
        received = {**original, 'fd': 11}
        client = SimpleNamespace(name=':1.2', wire=wire, events=[{'wire_hex': '6c040001'}])
        message = dict(type=4, serial=102, fields={1:'/foundation',2:'org.foundation.Transport',3:'Resource',6:':1.2',7:':1.1',8:'h',9:1}, body=wire.u32(0), fds=[11])
        with patch.dict(A.frozen_ns, fd_record=lambda fd: original if fd == 10 else received,
                        read_payload=lambda fd, content: (content, [content.hex(), ''])):
            self.assertEqual(A.validate_transfer(client, message, ':1.1', 10, 1)['serial'], 102)
            message['serial'] = 101
            with self.assertRaises(AssertionError): A.validate_transfer(client, message, ':1.1', 10, 1)

if __name__ == '__main__':
    unittest.main(verbosity=2)
