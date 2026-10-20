"""FD03 different bundles: two consecutive frames, four actually held readers."""
import array,hashlib,importlib.util,json,os,select,stat,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
SHARED=Path(sys.argv[3]) if __name__=='__main__' and len(sys.argv)==4 else HERE.parent/'p08_fd01_singleton_resources'
ORIGINAL_SHA='1abe51b28ed36e57711ac2d181c8645d384228c8f37f7a25f115067ce545ff95'
assert hashlib.sha256((SHARED/'actor.py').read_bytes()).hexdigest()==ORIGINAL_SHA,'shared actor drift'
spec=importlib.util.spec_from_file_location('fd03_frozen_actor',SHARED/'actor.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
Client,load_wire,fd_record,fd_state,identity,close_descriptor,healthy=S.Client,S.load_wire,S.fd_record,S.fd_state,S.identity,S.close_descriptor,S.healthy
digest=S.digest
CONTENTS=(b'FD-A',b'FD-B')
def read_payload(fd,expected):
    deadline=time.monotonic()+S.SOCKET_MS/1000;content=b'';chunks=[]
    while True:
        remaining=deadline-time.monotonic();assert remaining>0,'absolute resource pipe deadline'
        readable,_,_=select.select([fd],[],[],remaining);assert readable,'absolute resource pipe deadline'
        piece=os.read(fd,5-len(content));chunks.append(piece.hex())
        if not piece:break
        content+=piece;assert len(content)<=4,'resource content mismatch'
    assert time.monotonic()<=deadline and content==expected,'resource content mismatch'
    return content,chunks
def validate_transfer(client,message,sender,source_fd,ordinal=0):
    assert type(ordinal) is int and ordinal in (0,1)
    serial=100+ordinal;event=client.events[-1];fields=message['fields']
    assert bytes.fromhex(event['wire_hex'])[:4]==b'l\x04\x00\x01','invalid Resource fixed header'
    assert message['type']==4 and message['serial']==serial,'unexpected first active resource frame'
    assert fields=={1:'/foundation',2:'org.foundation.Transport',3:'Resource',6:client.name,7:sender,8:'h',9:1},'resource identity/header mismatch'
    assert message['body']==client.wire.u32(0) and len(message['fds'])==1,'resource index/right count mismatch'
    original,received=map(fd_record,(source_fd,message['fds'][0]))
    assert all(stat.S_ISFIFO(fd['mode']) for fd in (original,received)),'wrong resource kind'
    assert all(original[k]==received[k] for k in ('dev','ino','mode','target')),'transferred endpoint identity mismatch'
    assert original['fd']!=received['fd'],'duplicate numeric reader'
    content,chunks=read_payload(message['fds'][0],CONTENTS[ordinal])
    return dict(serial=serial,sender=sender,target=client.name,signature='h',index=0,header9=1,rights=1,
        content=content.decode(),content_hex=content.hex(),content_sha256=digest(content),read_chunks_hex=chunks,eof=True,
        source_fd=original,received_fd=received,received=event.copy())
class Workload(S.Workload):
    def __init__(self,path,wire):
        super().__init__(path,wire);self.original_fds=[];self.received_fds=[]
    def open(self):
        assert not self.original_fds and not self.received_fds
        return super().open()
    def exercise(self):
        assert self.state=='open' and set(self.clients)=={'source','target'} and not self.original_fds and not self.received_fds
        source,target=self.clients['source'],self.clients['target'];prepared=[];sent=[];transfers=[]
        for content in CONTENTS:
            original,writer=os.pipe();self.original_fds.append(original)
            try:
                os.set_blocking(writer,False);written=os.write(writer,content);assert written==4,'short pipe write'
            finally:closed=close_descriptor('writer',writer,lambda:os.close(writer))
            prepared.append(dict(written_bytes=written,writer_close=closed))
        originals=[fd_record(fd) for fd in self.original_fds]
        assert len({(r['dev'],r['ino']) for r in originals})==2,'same pipe for different bundles'
        # Complete sends are consecutive. This makes no coalesced-read claim.
        for i,original in enumerate(self.original_fds):
            packet=self.wire.signal(100+i,target.name,1,self.wire.u32(0),'h')
            with source.deadline(S.WRITER_MS):
                count=source.sock.sendmsg([packet],[(S.socket.SOL_SOCKET,S.socket.SCM_RIGHTS,array.array('i',[original]))])
                assert 0<count<=len(packet),'invalid actual send byte count'
                source.sock.sendall(packet[count:])
            sent.append(dict(role='source',phase='active',direction='sent',type=4,serial=100+i,
                fields={'1':'/foundation','2':'org.foundation.Transport','3':'Resource','6':target.name,'8':'h','9':1},
                body_hex=self.wire.u32(0).hex(),wire_hex=packet.hex(),wire_sha256=digest(packet),wire_bytes=len(packet),rights=1,
                sendmsg_bytes=count,completed_bytes=len(packet),right_fd=originals[i]))
        for i,original in enumerate(self.original_fds):
            message=target.receive()  # First two active receives, no filter/skip.
            self.received_fds.extend(message['fds'])
            transfer=validate_transfer(target,message,source.name,original,i)
            transfer.update(prepared[i],sent=sent[i]);transfers.append(transfer)
        assert len(set(self.original_fds+self.received_fds))==4,'four actual readers required'
        health=[healthy(source,110),healthy(target,111)];self.state='checked'
        return dict(op='exercise',**identity(),transfers=transfers,health=health,held=True,
            connections=[c.receipt() for c in self.clients.values()],fd_state=fd_state())
    def close(self,op):
        started=time.monotonic();events={r:c.events.copy() for r,c in self.clients.items()};owners=[]
        owners.extend((f'received-{i}',fd,lambda fd=fd:os.close(fd)) for i,fd in enumerate(self.received_fds))
        owners.extend((f'original-{i}',fd,lambda fd=fd:os.close(fd)) for i,fd in enumerate(self.original_fds))
        owners.extend((r,c.sock.fileno(),c.close) for r,c in self.clients.items())
        closure=[close_descriptor(r,fd,close) for r,fd,close in owners]
        self.received_fds,self.original_fds,self.clients=[],[],{};self.state='closed';after=fd_state();elapsed=(time.monotonic()-started)*1000
        assert elapsed<=S.CLEANUP_MS,'absolute actor cleanup deadline'
        return dict(op=op,**identity(),closure=closure,connections=[],held=False,events=events,fd_state=after,
            fd_growth=after['count']-self.baseline['count'],baseline_equal=after==self.baseline,latency_ms=elapsed)
def main():
    assert len(sys.argv)==4
    path,wire,shared=sys.argv[1:];assert Path(shared)==SHARED
    assert Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n' and path=='/run/osbus-fd-quotas/bus' and os.getuid()==1100
    worker=Workload(path,load_wire(wire));print(json.dumps(dict(ok=True,result=dict(**identity(),op='ready',fd_state=worker.baseline,connections=[]))),flush=True)
    S.serve(worker,sys.stdin,sys.stdout)
if __name__=='__main__':main()
