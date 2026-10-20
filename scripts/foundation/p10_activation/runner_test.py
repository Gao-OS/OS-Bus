"""Offline boundary regressions; no bus, privileged helper, VM or child launch."""
from contextlib import ExitStack
import copy
import array
import socket
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import patch
from bridge_probe import read_record
from guest import Runner, owned_group, group_empty, occurrences, package_inventory, terminate_witness, verify_capture
from protocol import accounting, fd_reply

RECORD=struct.pack('>4sBBHII',b'GHB\1',3,0,0,7,0)


class RunnerTest(unittest.TestCase):
    def pipes(self,stack,raw,stderr=b'',keep_open=False):
        streams=[]
        for data in (raw,stderr):
            r,w=os.pipe();stream=stack.enter_context(os.fdopen(r,'rb'));streams.append(stream)
            os.write(w,data)
            if keep_open:stack.callback(os.close,w)
            else:os.close(w)
        return streams

    def test_exact_record_requires_eof(self):
        with ExitStack() as stack:
            self.assertEqual(read_record(*self.pipes(stack,RECORD),time.monotonic()+1),RECORD)

    def test_extra_truncated_and_stderr_fail(self):
        for data,error in ((RECORD+b'x',b''),(RECORD[:-1],b''),(RECORD,b'error')):
            with self.subTest(data=data,error=error),ExitStack() as stack:
                with self.assertRaises(AssertionError):read_record(*self.pipes(stack,data,error),time.monotonic()+1)

    def test_withheld_record_or_eof_has_independent_deadline(self):
        for data in (b'',RECORD):
            with self.subTest(data=data),ExitStack() as stack:
                with self.assertRaises(TimeoutError):read_record(*self.pipes(stack,data,keep_open=True),time.monotonic()+.02)

    def test_no_root_or_foreign_cgroup(self):
        unit='osbus-p10-A3-dac.service'
        self.assertEqual(owned_group(unit,''),Path('/sys/fs/cgroup/system.slice/'+unit))
        for value in ('/','/system.slice','/system.slice/dbus.service'):
            with self.assertRaises(AssertionError):owned_group(unit,value)
        self.assertFalse(group_empty({'pids':[],'events':'populated 1\nfrozen 0\n'}))
        self.assertFalse(group_empty({'pids':[42],'events':'populated 0\n'}))
        self.assertTrue(group_empty({'pids':[],'events':'populated 0\nfrozen 0\n'}))

    def test_cleanup_failure_cannot_be_erased(self):
        runner=Runner.__new__(Runner);runner.active={'osbus-p10-A1.service':{}}
        runner.report={'cleanup':[],'cleanup_errors':[]}
        def denied(*args,**kwargs):raise RuntimeError('owned unit stop failed')
        runner.command=denied
        self.assertEqual(len(runner.cleanup()),1)
        runner.active={}
        self.assertEqual(runner.cleanup(),[])
        self.assertEqual(len(runner.report['cleanup_errors']),1)

    def test_directory_and_filename_occurrences_are_exact(self):
        original=[{'path':'/old/a/system-services/A.service','sha256':'one'},
                  {'path':'/old/b/system-services/A.service','sha256':'one'}]
        new=[dict(row,path=row['path'].replace('/old','/new')) for row in original]
        self.assertEqual(occurrences(original,['/old/a','/old/b']),occurrences(new,['/new/a','/new/b']))
        renamed=copy.deepcopy(new);renamed[0]['path']='/new/a/system-services/B.service'
        moved=copy.deepcopy(new);moved[0]['path']='/new/b/system-services/A.service'
        for rows in (renamed,moved):self.assertNotEqual(occurrences(original,['/old/a','/old/b']),occurrences(rows,['/new/a','/new/b']))
        with self.assertRaises(AssertionError):occurrences(new,['/new/a'])

    def test_package_content_and_permissions_are_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);p=root/'artifact';p.write_bytes(b'old');before=package_inventory(root)
            p.write_bytes(b'new');self.assertNotEqual(package_inventory(root),before)
            p.chmod(0o4755)
            with self.assertRaises(AssertionError):package_inventory(root)

    def test_nix_mode_normalization_is_exact_without_losing_byte_link_path_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);directory=root/'bin';directory.mkdir()
            binary=directory/'actor';binary.write_bytes(b'ordinary executable');binary.chmod(0o755)
            plain=root/'data';plain.write_bytes(b'fixed data');plain.chmod(0o644)
            link=root/'alias';link.symlink_to('bin/actor')
            expected=package_inventory(root)
            binary.chmod(0o555);plain.chmod(0o444);directory.chmod(0o555)
            self.assertTrue(verify_capture(root,expected))
            binary.chmod(0o554)
            with self.assertRaises(AssertionError):verify_capture(root,expected)
            binary.chmod(0o555);plain.chmod(0o644);plain.write_bytes(b'changed')
            with self.assertRaises(AssertionError):verify_capture(root,expected)
            plain.write_bytes(b'fixed data');plain.chmod(0o444);link.unlink();link.symlink_to('data')
            with self.assertRaises(AssertionError):verify_capture(root,expected)
            link.unlink();link.symlink_to('bin/actor');extra=root/'extra';extra.write_bytes(b'x')
            with self.assertRaises(AssertionError):verify_capture(root,expected)
            extra.unlink();binary.chmod(0o755);directory.chmod(0o755)
            binary.unlink()
            with self.assertRaises(AssertionError):verify_capture(root,expected)

    def test_pidfd_rejects_reused_witness_before_signal_and_closes(self):
        row={'pid':42,'stat':'42 (fixture) S '+'0 '*18+'7 0'}
        with patch('guest.os.pidfd_open',return_value=123),patch('guest.os.close') as close,patch('guest.Path.read_text',return_value='42 (other) S '+'0 '*18+'8 0'),patch('guest.signal.pidfd_send_signal') as send:
            with self.assertRaises(AssertionError):terminate_witness(row)
            send.assert_not_called();close.assert_called_once_with(123)

    def test_actual_rights_reply_retains_object_contents_and_exact_payload(self):
        resource=b'independent-fd-witness';fd=os.memfd_create('p10-offline',os.MFD_CLOEXEC)
        left,right=socket.socketpair()
        received=[]
        try:
            os.write(fd,resource);identity=os.fstat(fd)
            left.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))])
            _,controls,_,_=right.recvmsg(1,socket.CMSG_SPACE(4))
            rights=array.array('i');rights.frombytes(controls[0][2]);received=list(rights)
            reply={'type':2,'fields':{8:'hs'},'fds':received,'body':struct.pack('<II',0,len(resource))+resource+b'\0'}
            fd_reply(reply,identity,resource)
            for body in (reply['body']+b'extra',struct.pack('<I',1)+reply['body'][4:]):
                with self.assertRaises(AssertionError):fd_reply(dict(reply,body=body),identity,resource)
            os.pwrite(fd,b'X',0)
            with self.assertRaises(AssertionError):fd_reply(reply,identity,resource)
        finally:
            for number in received:os.close(number)
            os.close(fd);left.close();right.close()

    def test_non_boolean_execution_is_not_acceptance(self):
        rows=[{'id':'A%d'%i,'executed':True,'result':'passed'} for i in range(8)]
        rows[0]['executed']=2
        self.assertFalse(accounting(rows)['accepted']);self.assertEqual(accounting(rows)['executed'],7)

if __name__=='__main__':unittest.main()
