"""Prepared native socketpair controls; execution is held, no broker evidence."""
import array,importlib.util,os,select,socket,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
class BoundaryActor(unittest.TestCase):
 def setUp(self):
  self.assertTrue((HERE/'actor.py').is_file(),'all-boundaries actor missing')
  self.actor=load(HERE/'actor.py','all_boundary_actor_test');self.wire=self.actor.P.load_wire(ROOT/'apps/gao_bus/test/fixtures')
 def prefix(self,offset,mode,target=':1.2',actor=None):
  actor=actor or self.actor;worker=actor.Workload('/offline-control',self.wire);pairs=[socket.socketpair(),socket.socketpair()]
  try:
   worker.clients={role:actor.P.Client(pair[0],role,self.wire) for role,pair in zip(('source','target'),pairs)}
   for role,client in worker.clients.items():client.phase='active';client.name=':1.1' if role=='source' else target
   worker.state='open';worker.mode_index=actor.MODES.index(mode)
   row=worker.command(dict(op='prefix',mode=mode,offset=offset));packet=bytes.fromhex(row['packet_hex']);expected=packet[:offset]
   # Check closure before recvmsg can reuse the writer's numeric FD slot.
   with self.assertRaises(OSError) as error:os.fstat(row['writer_close']['fd'])
   self.assertEqual(error.exception.errno,9)
   installed=[]
   try:
    raw=b''
    for piece in row['sends']:
     data,controls,flags,_=pairs[0][1].recvmsg(piece['bytes'],socket.CMSG_SPACE(4));self.assertEqual(flags,0);self.assertEqual(data,bytes.fromhex(piece['wire_hex']));raw+=data
     rights=[]
     for level,kind,value in controls:
      self.assertEqual((level,kind),(socket.SOL_SOCKET,socket.SCM_RIGHTS));fds=array.array('i');fds.frombytes(value);rights+=list(fds);installed+=list(fds)
     self.assertEqual(len(rights),piece['rights'],'actual final ancillary send missing or duplicated')
    self.assertEqual(raw,expected);self.assertEqual(len(installed),1);self.assertEqual(os.fstat(installed[0]).st_ino,row['source_fd']['ino'])
    self.assertFalse(select.select([pairs[0][1]],[],[],0)[0],'suffix sent before retained barrier')
    self.assertEqual(os.read(installed[0],5),b'PIPE');self.assertEqual(os.read(installed[0],1),b'')
    self.assertTrue(all(piece['bytes']>0 for piece in row['sends']));self.assertEqual(row['geometry']['frame_bytes'],len(packet))
    return row
   finally:
    for fd in installed:os.close(fd)
  finally:
   worker.close('unit-cleanup')
   for pair in pairs:
    for sock in pair:sock.close()
 def test_every_nonempty_split_and_both_real_ancillary_positions(self):
  packet=self.wire.signal(100,':1.2',1,self.wire.u32(0),'h')
  for offset in range(1,len(packet)):
   for mode in self.actor.MODES:
    with self.subTest(offset=offset,mode=mode):self.prefix(offset,mode)
 def test_geometry_tracks_longer_destination_and_final_body_boundary(self):
  name=':1.12345678901234567890';packet=self.wire.signal(100,name,1,self.wire.u32(0),'h')
  for mode in self.actor.MODES:
   row=self.prefix(len(packet)-1,mode,name);self.assertEqual(row['geometry']['body_bytes'],4);self.assertEqual(row['offset'],row['geometry']['body_start']+3)
 def test_offset_one_does_not_issue_empty_plain_send(self):
  row=self.prefix(1,'last-byte-right');self.assertEqual([(s['bytes'],s['rights']) for s in row['sends']],[(1,1)])
 def test_dropped_actual_last_prefix_byte_right_is_detected(self):
  source=(HERE/'actor.py').read_text();needle='if rights:count=source.sock.sendmsg';self.assertEqual(source.count(needle),1)
  altered=source.replace(needle,"if rights and mode!='last-byte-right':count=source.sock.sendmsg")
  namespace=dict(self.actor.__dict__);exec(compile(altered,str(HERE/'actor.py')+'::actual-final-send-negative','exec'),namespace)
  module=type('UnitMutatedActor',(),namespace)
  with self.assertRaisesRegex(AssertionError,'actual final ancillary send'):self.prefix(15,'last-byte-right',actor=module)
 def test_invalid_offsets_are_rejected_before_allocating_a_pipe(self):
  for offset in (0,-1,True,1.0,1000000):
   worker=self.actor.Workload('/offline-control',self.wire);worker.state='open'
   # Offset type/range validation precedes descriptor creation; actual packet
   # construction still needs source/target identities for integer bounds.
   if type(offset) is int and offset>=1:
    with self.assertRaises(AssertionError):self.prefix(offset,'prefix-right')
    continue
   with self.assertRaises(AssertionError):worker.command(dict(op='prefix',mode='prefix-right',offset=offset))
   self.assertIsNone(worker.original_fd)
 def test_inherited_payload_helper_requires_real_eof(self):
  reader,writer=os.pipe()
  try:
   os.write(writer,b'PIPE')
   with self.assertRaisesRegex(AssertionError,'absolute resource pipe deadline'):self.actor.P.read_payload(reader)
  finally:os.close(reader);os.close(writer)
 def test_inherited_payload_helper_rejects_extra_byte(self):
  reader,writer=os.pipe()
  try:
   os.write(writer,b'PIPEX');os.close(writer);writer=None
   with self.assertRaisesRegex(AssertionError,'resource content mismatch'):self.actor.P.read_payload(reader)
  finally:
   os.close(reader)
   if writer is not None:os.close(writer)
 def test_inherited_closure_helper_requires_actual_ebadf(self):
  reader,writer=os.pipe()
  try:
   with self.assertRaisesRegex(AssertionError,'owned descriptor remained open'):self.actor.P.close_descriptor('writer',writer,lambda:None)
  finally:os.close(reader);os.close(writer)
if __name__=='__main__':unittest.main(verbosity=2)
