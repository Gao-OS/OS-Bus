"""Native offline partial-prefix controls; no broker or runtime qualification."""
import array,importlib.util,os,select,socket,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
P=load(HERE.parent/'p08_fd01_singleton_resources/actor.py','accepted_pipe_actor_test')
class PartialActor(unittest.TestCase):
 def setUp(self):
  path=HERE/'actor.py';self.actor=load(path,'partial_actor_test') if path.exists() else P
  self.assertTrue(hasattr(self.actor.Workload,'prefix'),'partial-prefix protocol missing')
  self.wire=P.load_wire(ROOT/'apps/gao_bus/test/fixtures')
  self.pairs=[socket.socketpair(),socket.socketpair()]
  for pair in self.pairs:
   for sock in pair:self.addCleanup(sock.close)
  self.worker=self.actor.Workload('/offline-control',self.wire)
  self.worker.clients={role:P.Client(pair[0],role,self.wire) for role,pair in zip(('source','target'),self.pairs)}
  for role,c in self.worker.clients.items():c.phase='active';c.name=':1.1' if role=='source' else ':1.2'
  self.worker.state='open';self.addCleanup(lambda:self.worker.close('cleanup'))
 def check_prefix(self,mode):
  prefix=self.worker.command(dict(op='prefix',mode=mode))
  with self.assertRaises(OSError) as e:os.fstat(prefix['writer_close']['fd'])
  self.assertEqual(e.exception.errno,9)
  expected=bytes.fromhex(prefix['packet_hex'])[:-1]
  if mode=='last-byte-right':
   plain,early,flags,_=self.pairs[0][1].recvmsg(len(expected)-1,socket.CMSG_SPACE(4))
   self.assertEqual(plain,expected[:-1]);self.assertEqual(early,[],'rights on earlier plain send')
   final,controls,flags,_=self.pairs[0][1].recvmsg(1,socket.CMSG_SPACE(4));raw=plain+final
  else:raw,controls,flags,_=self.pairs[0][1].recvmsg(len(expected),socket.CMSG_SPACE(4))
  self.assertEqual(flags,0);self.assertEqual(len(controls),1,'actual final send rights missing')
  fds=array.array('i');fds.frombytes(controls[0][2]);self.addCleanup(lambda fds=fds:[os.close(fd) for fd in fds])
  self.assertEqual(raw,bytes.fromhex(prefix['prefix_hex']));self.assertEqual(len(raw),len(self.wire.signal(100,self.worker.clients['target'].name,1,self.wire.u32(0),'h'))-1)
  self.assertEqual(len(fds),1);self.assertEqual(os.fstat(fds[0]).st_ino,prefix['source_fd']['ino'])
  self.assertFalse(select.select([self.pairs[0][1]],[],[],0)[0],'suffix prematurely sent')
  self.assertEqual([r['bytes'] for r in prefix['sends']],[len(raw)] if mode=='prefix-right' else [len(raw)-1,1])
  self.assertEqual([r['rights'] for r in prefix['sends']],[1] if mode=='prefix-right' else [0,1])
  self.assertEqual(prefix['writer_close']['closed'],True)
 def test_prefix_holds_suffix_and_right(self):self.check_prefix('prefix-right')
 def test_last_prefix_byte_carries_right(self):
  self.worker.mode_index=1;self.check_prefix('last-byte-right')
 def test_body_offset_tracks_destination_header_length(self):
  self.worker.clients['target'].name=':1.12345678901234567890'
  packet=self.wire.signal(100,self.worker.clients['target'].name,1,self.wire.u32(0),'h')
  self.assertNotEqual(len(packet)-1,139)
  self.check_prefix('prefix-right')
 def test_finish_requires_explicit_retained_barrier(self):
  self.worker.command(dict(op='prefix',mode='prefix-right'))
  with self.assertRaisesRegex(AssertionError,'retained'):self.worker.command(dict(op='finish'))
 def test_premature_target_resource_fails_strict_hold_health(self):
  self.worker.command(dict(op='prefix',mode='prefix-right'))
  peer=self.pairs[1][1]
  peer.sendmsg([self.wire.signal(100,':1.2')],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.worker.original_fd]))])
  with self.assertRaisesRegex(AssertionError,'unexpected first healthy frame'):self.worker.command(dict(op='retained'))
  self.assertEqual(self.pairs[0][1].recv(len(self.wire.signal(100,self.worker.clients['target'].name,1,self.wire.u32(0),'h'))-1),self.wire.signal(100,self.worker.clients['target'].name,1,self.wire.u32(0),'h')[:-1])
  self.assertFalse(select.select([self.pairs[0][1]],[],[],0)[0],'source health appended while incomplete')
 def test_dropped_actual_final_ancillary_send_is_detected(self):
  source=(HERE/'actor.py').read_text()
  needle='if rights:count=source.sock.sendmsg'
  self.assertEqual(source.count(needle),1)
  mutated=source.replace(needle,"if rights and mode!='last-byte-right':count=source.sock.sendmsg")
  namespace=dict(self.actor.__dict__);exec(compile(mutated,str(HERE/'actor.py')+'::dropped-final-right-control','exec'),namespace)
  self.worker.__class__=namespace['Workload'];self.worker.mode_index=1
  with self.assertRaisesRegex(AssertionError,'actual final send rights missing'):self.check_prefix('last-byte-right')
 def test_retained_then_finish_consumes_pipe_eof_and_closes(self):self.complete('prefix-right')
 def test_last_byte_retained_finish_and_closes(self):
  self.worker.mode_index=1;self.complete('last-byte-right')
 def complete(self,mode):
  own={c.sock.fileno() for c in self.worker.clients.values()}
  self.worker.baseline['fds']=[f for f in self.worker.baseline['fds'] if f['fd'] not in own];self.worker.baseline['count']=len(self.worker.baseline['fds'])
  prefix=self.worker.command(dict(op='prefix',mode=mode))
  source_peer=self.pairs[0][1];target_peer=self.pairs[1][1]
  raw,controls,flags,_=source_peer.recvmsg(len(self.wire.signal(100,self.worker.clients['target'].name,1,self.wire.u32(0),'h'))-1,socket.CMSG_SPACE(4));rights=array.array('i');rights.frombytes(controls[0][2])
  self.addCleanup(lambda:[self.close_fd(fd) for fd in rights])
  self.assertEqual(raw,bytes.fromhex(prefix['prefix_hex']))
  self.assertFalse(select.select([source_peer],[],[],0)[0])
  def reply(peer,serial,name):peer.sendall(self.wire.frame(2,30,[(5,'u',serial),(6,'s',name),(7,'s','org.freedesktop.DBus'),(8,'g','s')],self.wire.string(name)))
  reply(target_peer,112,':1.2')
  held=self.worker.command(dict(op='retained'));self.assertTrue(held['target_unreadable']);self.assertEqual(held['active_events']['source'],[])
  self.assertFalse(select.select([source_peer],[],[],0)[0],'source health before suffix')
  source=self.worker.clients['source'];underlying=source.sock.raw;wire=self.wire;test=self
  class ExplicitUnitRelay:
   def __getattr__(self,name):return getattr(underlying,name)
   def sendall(self,data):
    underlying.sendall(data);test.assertEqual(source_peer.recv(len(data)),data)
    if data==bytes.fromhex(prefix['packet_hex'])[-1:]:
     forwarded=wire.frame(4,100,[(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','Resource'),(6,'s',':1.2'),(7,'s',':1.1'),(8,'g','h'),(9,'u',1)],wire.u32(0))
     target_peer.sendmsg([forwarded],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,rights)])
     for fd in rights:os.close(fd)
     rights[:]=array.array('i')
     reply(target_peer,111,':1.2');reply(source_peer,110,':1.1')
  source.sock.raw=ExplicitUnitRelay()
  finished=self.worker.command(dict(op='finish'))
  self.assertEqual(finished['transfer']['content'],'PIPE');self.assertEqual(finished['transfer']['source_fd']['ino'],finished['transfer']['received_fd']['ino'])
  self.assertEqual(os.read(self.worker.original_fd,1),b'')
  for key in ('source_fd','received_fd'):os.fstat(finished['transfer'][key]['fd'])
  closed=self.worker.command(dict(op='close'));self.assertTrue(closed['baseline_equal']);self.assertEqual(len(closed['closure']),4)
  for f in closed['closure']:
   with self.assertRaises(OSError) as error:os.fstat(f['fd'])
   self.assertEqual(error.exception.errno,9)
 def close_fd(self,fd):
  try:os.close(fd)
  except OSError as error:self.assertEqual(error.errno,9)
if __name__=='__main__':unittest.main(verbosity=2)
