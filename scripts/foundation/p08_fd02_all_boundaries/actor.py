"""Independent real SCM_RIGHTS at every incomplete-frame boundary."""
import array,importlib.util,json,os,select,socket,struct,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
REUSE=Path(os.environ.get('FD02_PIPE_FIXTURES',str(HERE.parent/'p08_fd01_singleton_resources')))
def load(path):
 spec=importlib.util.spec_from_file_location('fd02_all_readonly_pipe_actor',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
P=load(REUSE/'actor.py');MODES=('prefix-right','last-byte-right');RUN_ROOT=Path('/run/osbus-fd02-all-boundaries')
def geometry(packet):
 assert packet[:4]==b'l\x04\x00\x01' and len(packet)>=16
 body,serial,header=struct.unpack_from('<III',packet,4);end=16+header;start=end+(-header%8)
 assert serial==100 and body==4 and len(packet)==start+body and packet[start:]==b'\0'*4 and not any(packet[end:start])
 return dict(fixed_header_bytes=16,header_fields_bytes=header,header_end=end,alignment_bytes=start-end,body_start=start,body_bytes=body,frame_bytes=len(packet),boundaries=len(packet)-1)
class Workload(P.Workload):
 def __init__(self,path,wire):
  super().__init__(path,wire);self.partial=None;self.mode_index=0;self.batch_offset=None;self.batch_geometry=None
 def prefix(self,mode,offset):
  assert type(offset) is int and offset>=1,'nonempty integer boundary required'
  assert self.state=='open' and self.partial is None,'prefix requires open'
  assert self.mode_index<len(MODES) and mode==MODES[self.mode_index],'wrong arrival mode/order'
  source,target=self.clients['source'],self.clients['target'];packet=self.wire.signal(100,target.name,1,self.wire.u32(0),'h');layout=geometry(packet)
  assert offset<len(packet),'boundary must precede complete resource frame'
  if self.batch_offset is None:self.batch_offset,self.batch_geometry=offset,layout
  assert offset==self.batch_offset and layout==self.batch_geometry,'fresh invocation mode geometry/boundary drift'
  self.original_fd,writer=os.pipe()
  try:os.set_blocking(writer,False);written=os.write(writer,b'PIPE');assert written==4
  finally:writer_close=P.close_descriptor('writer',writer,lambda:os.close(writer))
  prefix=packet[:offset];sends=[];pieces=[(prefix,1)] if mode==MODES[0] or offset==1 else [(prefix[:-1],0),(prefix[-1:],1)]
  for data,rights in pieces:
   assert data,'empty ancillary-prefix send forbidden'
   with source.deadline(P.WRITER_MS):
    if rights:count=source.sock.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[self.original_fd]))])
    else:source.sock.sendall(data);count=len(data)
   assert count==len(data),'short prefix send'
   sends.append(dict(bytes=count,wire_hex=data.hex(),sha256=P.digest(data),rights=rights))
  self.partial=dict(mode=mode,offset=offset,geometry=layout,prefix_hex=prefix.hex(),prefix_sha256=P.digest(prefix),sends=sends,packet_hex=packet.hex(),packet_sha256=P.digest(packet),suffix_bytes=len(packet)-offset,suffix_sent=False,source_fd=P.fd_record(self.original_fd),writer_close=writer_close,written_bytes=written)
  self.state='partial'
  return dict(op='prefix',**P.identity(),**self.partial,held=True,connections=[c.receipt() for c in self.clients.values()],fd_state=P.fd_state())
 def retained(self):
  assert self.state=='partial' and self.partial is not None,'retained requires prefix'
  source,target=self.clients['source'],self.clients['target']
  assert not select.select([source.sock],[],[],0)[0],'premature source output before healthy probe'
  assert not select.select([target.sock],[],[],0)[0],'premature target output before healthy probe'
  health=P.healthy(target,112)
  assert not select.select([target.sock],[],[],0)[0],'premature target output after healthy probe'
  assert not select.select([source.sock],[],[],0)[0],'premature source output after healthy probe'
  assert not [row for row in source.events if row['phase']=='active'],'source health appended to incomplete frame'
  self.state='retained'
  return dict(op='retained',**P.identity(),mode=self.partial['mode'],offset=self.partial['offset'],suffix_sent=False,health=health,target_unreadable=True,source_unreadable=True,target_unreadable_before_probe=True,source_unreadable_before_probe=True,active_events={role:[row.copy() for row in client.events if row['phase']=='active'] for role,client in self.clients.items()},fd_state=P.fd_state())
 def finish(self):
  assert self.state=='retained' and self.partial is not None,'finish requires retained barrier'
  source,target=self.clients['source'],self.clients['target'];packet=bytes.fromhex(self.partial['packet_hex']);suffix=packet[self.partial['offset']:]
  with source.deadline(P.WRITER_MS):source.sock.sendall(suffix)
  message=target.receive();self.received_fd=message['fds'][0] if len(message['fds'])==1 else None
  try:
   transfer=P.validate_transfer(target,message,source.name,self.original_fd);transfer.update(written_bytes=self.partial['written_bytes'],writer_close=self.partial['writer_close'])
   transfer['sent']=dict(role='source',phase='active',direction='sent',type=4,serial=100,fields={'1':'/foundation','2':'org.foundation.Transport','3':'Resource','6':target.name,'8':'h','9':1},body_hex='00000000',wire_hex=packet.hex(),wire_sha256=P.digest(packet),wire_bytes=len(packet),rights=1)
   health=[P.healthy(source,110),P.healthy(target,111)]
  except BaseException:
   if self.received_fd is None:self.wire.close_fds(message['fds'])
   raise
  self.state='checked'
  return dict(op='exercise',**P.identity(),mode=self.partial['mode'],offset=self.partial['offset'],transfer=transfer,health=health,suffix=dict(bytes=len(suffix),wire_hex=suffix.hex(),sha256=P.digest(suffix),rights=0),held=True,connections=[client.receipt() for client in self.clients.values()],fd_state=P.fd_state())
 def close(self,op):
  selected=self.partial is not None;result=super().close(op);self.partial=None
  if op=='close' and selected:self.mode_index+=1;self.state='warmed'
  return result
 def command(self,row):
  if row.get('op')=='prefix':assert set(row)=={'op','mode','offset'};return self.prefix(row['mode'],row['offset'])
  assert set(row)=={'op'}
  if row['op']=='retained':return self.retained()
  if row['op']=='finish':return self.finish()
  if row['op']=='close':
   assert self.state=='checked','close requires completed mode';result=self.close('close');assert result['baseline_equal'] and result['fd_growth']==0;return result
  assert row['op'] in ('warmup','open'),'unknown partial operation'
  return super().command(row)
def main():
 assert len(sys.argv)==3 and Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n' and os.getuid()==1100
 path=Path(sys.argv[1]);assert path.parent.parent==RUN_ROOT and path.parent.name.startswith('case-') and path.name=='bus'
 assert path.parent.name[5:].isdigit() and int(path.parent.name[5:])>=1
 worker=Workload(str(path),P.load_wire(sys.argv[2]));print(json.dumps(dict(ok=True,result=dict(**P.identity(),op='ready',fd_state=worker.baseline,connections=[]))),flush=True);P.serve(worker,sys.stdin,sys.stdout)
if __name__=='__main__':main()
