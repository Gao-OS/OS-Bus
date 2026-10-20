"""Inert missing-destination receive/cleanup controls; no native I/O."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fd07_actor_controls', HERE / 'actor.py')
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)


class ActorControls(unittest.TestCase):
    def client(self):
        client = Mock(name='source'); client.name = ':1.1'
        client.events = {'received': [{'wire_hex': '', 'fd_targets': []}]}
        client.receive.return_value = dict(type=3, serial=91, body=b'', fds=[],
            fields={4: A.ERROR, 5: 100, 6: ':1.1', 7: A.BUS, 8: 's'})
        return client
    def test_exact_first_missing_reply_is_accepted(self):
        client = self.client()
        with patch.object(A, 'close_received'):
            result = A.missing_reply(client)
        self.assertEqual(result, dict(error_name=A.ERROR, error_reply_serial=100))
        client.receive.assert_called_once_with()
    def test_wrong_first_reply_or_installed_rights_cannot_be_skipped(self):
        for change in ({'type':2}, {'fds':[9]}, {'fields':{4:A.ERROR,5:101,6:':1.1',7:A.BUS,8:'s'}},
                       {'fields':{4:A.ERROR,5:100,6:':1.1',7:A.BUS,8:'s',9:0}},
                       {'fields':{4:A.ERROR,5:100,6:':1.1',7:'untrusted',8:'s'}}):
            client = self.client(); client.receive.return_value.update(change)
            with patch.object(A, 'close_received') as close:
                with self.assertRaises(AssertionError): A.missing_reply(client)
            close.assert_called_once_with(client.receive.return_value['fds'])
            client.receive.assert_called_once_with()
    def test_owned_close_requires_actual_ebadf(self):
        client = self.client()
        with patch.object(A.S, 'fd_record', return_value={'fd':9}), patch.object(A.os,'fstat',return_value=object()):
            with self.assertRaises(AssertionError): A.close_owned('source',9,Mock())
    def test_resource_probe_requires_content_and_actual_end(self):
        before = dict(fd=9,target='/memfd:foundation-broadcast-200 (deleted)',dev=1,ino=2,
            mode=0o100600,size=len(A.CONTENTS),contents_hex=A.CONTENTS.hex(),contents_sha256=A.digest(A.CONTENTS),closed=False)
        with patch.object(A, 'original_resource_receipt', return_value=before), \
                patch.object(A.S,'fd_record',return_value=dict(pid=200,uid=1100,gid=1100)), \
                patch.object(A.os,'pread',side_effect=[A.CONTENTS,b'']):
            result = A.resource_receipt(9,A.CONTENTS,'source')
        self.assertTrue(result['eof'])
        with patch.object(A, 'original_resource_receipt', return_value=before), \
                patch.object(A.S,'fd_record',return_value={}), patch.object(A.os,'pread',side_effect=[A.CONTENTS,b'X']):
            with self.assertRaises(AssertionError): A.resource_receipt(9,A.CONTENTS,'source')


if __name__ == '__main__': unittest.main(verbosity=2)
