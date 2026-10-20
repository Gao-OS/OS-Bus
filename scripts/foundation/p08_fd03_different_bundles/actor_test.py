"""Native offline two-pipe association controls, without a broker or VM."""
import array,importlib.util,os,socket,stat,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def load(path):
    s=importlib.util.spec_from_file_location('fd03_native_actor',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class NativeAssociation(unittest.TestCase):
    def setUp(self):
        # RED uses the unchanged predecessor: its singleton contract cannot
        # establish different-bundle association. GREEN executes the new actor.
        self.actor=load(HERE/'actor.py' if (HERE/'actor.py').exists() else HERE.parent/'p08_fd01_singleton_resources/actor.py')
        self.wire=self.actor.load_wire(ROOT/'apps/gao_bus/test/fixtures');a,b=socket.socketpair();self.addCleanup(a.close);self.addCleanup(b.close)
        self.client=self.actor.Client(a,'target',self.wire);self.client.name=':1.2';self.client.phase='active';self.peer=b
    def pipe(self,content):
        r,w=os.pipe();self.addCleanup(self.close,r);self.assertEqual(os.write(w,content),len(content));os.close(w);return r
    def close(self,fd):
        try:os.close(fd)
        except OSError as e:self.assertEqual(e.errno,9)
    def send(self,fd,serial=100,changes=None,rights=None,body=None,flags=0):
        fields=[(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','Resource'),(6,'s',':1.2'),(7,'s',':1.1'),(8,'g','h'),(9,'u',1)]
        fields=[(code,sig,(changes or {}).get(code,value)) for code,sig,value in fields]
        raw=self.wire.frame(4,serial,fields,self.wire.u32(0) if body is None else body,flags);fds=[fd] if rights is None else rights
        control=[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))] if fds else []
        self.assertEqual(self.peer.sendmsg([raw],control),len(raw))
        m=self.client.receive();self.addCleanup(lambda:self.wire.close_fds(m['fds']));return m
    def test_two_distinct_bundles_match_their_serial_and_reader(self):
        originals=[self.pipe(b'FD-A'),self.pipe(b'FD-B')];results=[]
        for i,r in enumerate(originals):
            m=self.send(r,100+i)
            try:
                result=self.actor.validate_transfer(self.client,m,':1.1',r) if i==0 else self.actor.validate_transfer(self.client,m,':1.1',r,ordinal=1)
            except AssertionError as e:self.fail('different-bundle association is absent: '+str(e))
            results.append(result)
        self.assertEqual([r['content'] for r in results],['FD-A','FD-B']);self.assertNotEqual(results[0]['source_fd']['ino'],results[1]['source_fd']['ino'])
        for r in originals:self.assertEqual(os.read(r,1),b'')
    def test_swapped_and_duplicate_reader_association_is_rejected(self):
        for expected,payload in ((0,b'FD-B'),(1,b'FD-A')):
            with self.subTest(expected=expected):
                a=self.pipe(b'FD-A');b=self.pipe(b'FD-B');sent=b if expected==0 else a;m=self.send(sent,100+expected)
                with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',[a,b][expected],expected)
    def test_reordered_or_duplicate_serial_is_rejected(self):
        for ordinal,serial in ((0,101),(1,100),(0,99)):
            with self.subTest(ordinal=ordinal,serial=serial):
                r=self.pipe((b'FD-A',b'FD-B')[ordinal]);m=self.send(r,serial)
                with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',r,ordinal)
    def test_wrong_raw_headers_flags_index_and_rights_are_rejected(self):
        cases=[dict(changes={7:':1.999'}),dict(changes={6:':1.999'}),dict(changes={1:'/other'}),dict(changes={2:'org.other'}),dict(changes={3:'Other'}),dict(changes={8:'u'}),dict(body=self.wire.u32(1)),dict(flags=1),dict(changes={9:0},rights=[])]
        for changes in cases:
            with self.subTest(changes=changes):
                r=self.pipe(b'FD-A');m=self.send(r,**changes)
                with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',r)
    def test_two_actual_installed_rights_are_rejected_and_closed(self):
        a=self.pipe(b'FD-A');b=self.pipe(b'FD-B');m=self.send(a,changes={9:2},rights=[a,b]);self.assertEqual(len(m['fds']),2)
        with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',a)
    def test_wrong_content_short_trailing_and_eof_are_rejected(self):
        for content in (b'FD-B',b'FD-',b'FD-AX',b''):
            with self.subTest(content=content):
                r=self.pipe(content);m=self.send(r)
                with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',r)
    def test_fifo_kind_and_identity_are_actual(self):
        r=self.pipe(b'FD-A');m=self.send(r);other=self.pipe(b'FD-A')
        with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',other)
        with self.assertRaises(AssertionError):self.actor.validate_transfer(self.client,m,':1.1',self.peer.fileno())
    def test_no_receive_filter_skips_the_first_wrong_frame(self):
        a=self.pipe(b'FD-A');b=self.pipe(b'FD-B');first=self.send(b,101)
        with self.assertRaisesRegex(AssertionError,'unexpected first active resource frame'):self.actor.validate_transfer(self.client,first,':1.1',a)
    def test_partial_resource_reads_consume_all_bytes_through_eof(self):
        from unittest.mock import patch
        r=self.pipe(b'FD-A');read=os.read
        with patch.object(self.actor.os,'read',side_effect=lambda fd,length:read(fd,min(length,1))):content,chunks=self.actor.read_payload(r,b'FD-A')
        self.assertEqual(content,b'FD-A');self.assertEqual(chunks,['46','44','2d','41',''])
    def test_absolute_pipe_deadline_is_not_reset(self):
        from unittest.mock import patch
        r=self.pipe(b'FD-A')
        with patch.object(self.actor.time,'monotonic',side_effect=[0,4]):
            with self.assertRaisesRegex(AssertionError,'absolute resource pipe deadline'):self.actor.read_payload(r,b'FD-A')
    def test_writer_and_readers_close_with_actual_ebadf(self):
        r,w=os.pipe();closed=self.actor.close_descriptor('writer',w,lambda:os.close(w));self.assertTrue(closed['closed']);self.close(r)
        r=self.pipe(b'FD-A')
        with self.assertRaisesRegex(AssertionError,'owned descriptor remained open'):self.actor.close_descriptor('original',r,lambda:None)
    def test_all_four_readers_close_and_eof_cleanup_is_empty(self):
        worker=self.actor.Workload('/offline-no-broker',self.wire)
        readers=[os.pipe() for unused in range(2)]
        for r,w in readers:os.close(w)
        worker.original_fds=[r for r,w in readers];worker.received_fds=[os.dup(r) for r,w in readers]
        self.addCleanup(worker.close,'cleanup');before=worker.original_fds+worker.received_fds
        closed=worker.close('close');self.assertEqual([c['role'] for c in closed['closure']],['received-0','received-1','original-0','original-1'])
        self.assertTrue(closed['baseline_equal']);self.assertEqual(closed['fd_growth'],0)
        for fd in before:
            with self.assertRaises(OSError) as error:os.fstat(fd)
            self.assertEqual(error.exception.errno,9)
        eof=worker.close('eof');self.assertEqual(eof['closure'],[]);self.assertTrue(eof['baseline_equal'])
    def test_exercise_failure_tracks_every_received_descriptor_for_cleanup(self):
        # Direct native socket pair has no broker to add a sender header.
        # Exercise must fail immediately and still retain all owned FDs for
        # the normal error close; this is never a compatibility positive.
        raw_source,raw_target=socket.socketpair();worker=self.actor.Workload('/offline-no-broker',self.wire)
        source=self.actor.Client(raw_source,'source',self.wire);source.name=':1.1';source.phase='active'
        target=self.actor.Client(raw_target,'target',self.wire);target.name=':1.2';target.phase='active'
        worker.clients={'source':source,'target':target};worker.state='open';self.addCleanup(worker.close,'cleanup')
        with self.assertRaisesRegex(AssertionError,'resource identity/header mismatch'):worker.exercise()
        self.assertEqual(len(worker.original_fds),2);self.assertEqual(len(worker.received_fds),1)
        closed=worker.close('error');self.assertEqual(len(closed['closure']),5)
if __name__=='__main__':unittest.main()
