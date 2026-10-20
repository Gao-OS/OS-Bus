"""FD07 named-memfd actor; frozen FD05 transport and usable warmup."""
import array
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import time

HERE=Path(__file__).resolve().parent
FD05=Path(sys.argv[3]) if __name__=='__main__' else HERE.parent/'p08_fd_nonnegotiation'
SHARED=Path(sys.argv[4]) if __name__=='__main__' else HERE.parent/'p08_fd01_singleton_resources'
PINS={'actor.py':'69d001f20e17637d98d0f9bd90b454486c12158dad57faab21067958195e6ab1'}
assert hashlib.sha256((FD05/'actor.py').read_bytes()).hexdigest()==PINS['actor.py']
assert hashlib.sha256((SHARED/'actor.py').read_bytes()).hexdigest()=='1abe51b28ed36e57711ac2d181c8645d384228c8f37f7a25f115067ce545ff95'
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
A=load('fd07_frozen_memfd_actor',FD05/'actor.py')
S=load('fd07_frozen_ownership_actor',SHARED/'actor.py')
WORKLOAD=json.loads((HERE/'workload.json').read_text());BUS=A.BUS
ERROR=WORKLOAD['missing']['error'];CONTENTS=WORKLOAD['missing']['contents'].encode();digest=A.digest
LIVE={};CLOSURES=[]

def close_owned(role,fd,close):
    row=S.close_descriptor(role,fd,close);CLOSURES.append(row)
    for receipt in LIVE.pop(fd,[]): receipt.update(closed=True,ebadf=True)
    return row

def close_received(fds):
    for fd in fds: close_owned('target',fd,lambda fd=fd:os.close(fd))

original_resource_receipt=A.resource_receipt
def resource_receipt(fd,contents,role,pipe=False):
    assert not pipe
    receipt=original_resource_receipt(fd,contents,role)
    receipt.update(S.fd_record(fd))
    actual=os.pread(fd,len(contents)+1,0);end=os.pread(fd,1,len(contents))
    assert actual==contents and end==b'', 'memfd content/end mismatch'
    receipt.update(eof=True,read_chunks_hex=[actual.hex(),end.hex()],ebadf=False)
    LIVE.setdefault(fd,[]).append(receipt)
    return receipt

class ObservedClient(A.ObservedClient):
    def record_sent(self,data,rights):
        super().record_sent(data,rights);self.events['sent'][-1]['direction']='sent'
    def send_fds(self,data,fds):
        assert len(fds)==1
        with self.deadline(WORKLOAD['writer_ms']):
            count=self.sock.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))])
            assert 0<count<=len(data)
            self.sock.bounded();self.sock.raw.sendall(data[count:])
        self.events['sent'][-1].update(sendmsg_bytes=count,completed_bytes=len(data),right_fd=S.fd_record(fds[0]))
    def receive(self):
        message=super().receive();self.events['received'][-1]['direction']='received'
        return message
    def close(self):
        fd=self.sock.fileno()
        if fd>=0: close_owned(self.role,fd,self.sock.close)
    def receipt(self):
        return {**super().receipt(),'socket':S.fd_record(self.sock.fileno())}

def missing_reply(client):
    message=client.receive()  # Exact first frame. No reply loop or drain.
    try:
        fields=message['fields']
        assert message['type']==3 and fields.get(5)==100
        assert fields=={4:ERROR,5:100,6:client.name,7:BUS,8:'s'}
        assert not message['fds'], 'resource-bearing missing-destination error'
        return dict(error_name=ERROR,error_reply_serial=100)
    finally: close_received(message['fds'])

# Retain the original usable memfd warmup, adding only actual owned-close proof.
source=(FD05/'actor.py').read_text();tree=ast.parse(source)
classes=[node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='Workload'];assert len(classes)==1
functions=[node for node in classes[0].body if isinstance(node,ast.FunctionDef) and node.name=='warmup'];assert len(functions)==1
warm=copy.deepcopy(functions[0]);before=ast.dump(warm,include_attributes=False)
replacements={ast.dump(ast.parse('os.close(fd)').body[0],include_attributes=False):"close_owned('source',fd,lambda:os.close(fd))",
    ast.dump(ast.parse("wire.close_fds(message['fds'])").body[0],include_attributes=False):"close_received(message['fds'])"}
counts={key:0 for key in replacements}
class Adapt(ast.NodeTransformer):
    def visit(self,node):
        if isinstance(node,ast.stmt):
            key=ast.dump(node,include_attributes=False)
            if key in replacements: counts[key]+=1;return ast.parse(replacements[key]).body[0]
        return super().visit(node)
warm=Adapt().visit(warm);assert list(counts.values())==[1,1]
ns=dict(vars(A));ns.update(WORKLOAD=WORKLOAD,resource_receipt=resource_receipt,close_owned=close_owned,close_received=close_received)
exec(compile(ast.fix_missing_locations(ast.Module(body=[warm],type_ignores=[])),str(HERE/'actor.py'),'exec'),ns)
ACTOR_ADAPTATION=dict(original_sha256=PINS['actor.py'],original_ast_sha256=hashlib.sha256(before.encode()).hexdigest(),
    executed_ast_sha256=hashlib.sha256(ast.dump(warm,include_attributes=False).encode()).hexdigest())

class Workload(A.Workload):
    warmup=ns['warmup']
    def __init__(self,path):
        super().__init__(path);self.baseline=S.fd_state();self.warmed=False;self.phase='initial'
    def connect(self,role,negotiate=True):
        client=ObservedClient(self.path,role,self.events,negotiate);self.clients.append(client);return client
    def result(self,**details):
        return {**super().result(**details),'fd_state':S.fd_state(),'closure':copy.deepcopy(CLOSURES)}
    def open(self,case):
        assert self.warmed and not self.clients and case=='missing-destination'
        CLOSURES.clear();self.reset_events();self.case=case
        self.connect('source');self.connect('target');self.connect('ordinary',False)
        return self.result(case=case)
    def exercise(self):
        assert self.case=='missing-destination' and len(self.clients)==3 and not LIVE
        self.reset_events();CLOSURES.clear();before=S.fd_state();source=self.clients[0]
        fd=os.memfd_create('foundation-broadcast-%d'%os.getpid(),os.MFD_CLOEXEC)
        try:
            assert os.write(fd,CONTENTS)==len(CONTENTS)
            receipt=resource_receipt(fd,CONTENTS,'source');self.events['resources'].append(receipt)
            packet=A.wire.frame(1,100,[(1,'o','/broadcast'),(2,'s',A.mixed.INTERFACE),(3,'s','Resource'),
                (6,'s','org.foundation.Absent'),(8,'g','h'),(9,'u',1)],A.wire.u32(0),flags=2)
            source.send_fds(packet,[fd])
        finally: close_owned('source',fd,lambda:os.close(fd))
        details=missing_reply(source)
        for base in (110,210):
            for i,client in enumerate(self.clients): A.healthy(client,base+i)
        after=S.fd_state();assert after==before and not LIVE,'active cancellation retained actor descriptors'
        return self.result(case=self.case,assertions=dict(resource_deliveries=0,rights0_deliveries=0,healthy_replies=6,
            actor_fd_growth=0,strict_first_message=True,returned_rights=0,delivered_rights=0),**details)
    def close(self):
        if self.phase!='initial': CLOSURES.clear()
        result=super().close()
        result['closure']=copy.deepcopy(CLOSURES)
        assert result['close_ms']<=WORKLOAD['cleanup_ms']
        return result
    def command(self,row):
        assert set(row)==({'op','case'} if row['op']=='open' else {'op'})
        if row['op']=='warmup':
            assert self.phase=='initial';CLOSURES.clear()
            # close() preserves socket proofs; collect resource proofs separately.
            result=self.warmup();self.warmed=True;self.phase='warmed'
            assert S.fd_state()==self.baseline and not LIVE
            return result
        if row['op']=='open': self.phase='open';return self.open(row['case'])
        if row['op']=='exercise': assert self.phase=='open';self.phase='checked';return self.exercise()
        if row['op']=='close':
            assert self.phase in ('open','checked');self.phase='closed';return self.close()
        raise AssertionError('unexpected actor operation')

def main():
    assert len(sys.argv)==5
    path,directory,fd05,shared=sys.argv[1:];assert Path(fd05)==FD05 and Path(shared)==SHARED
    assert Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n' and path==WORKLOAD['socket'] and os.getuid()==1100
    A.load_wire(directory);ns.update(wire=A.wire,mixed=A.mixed);worker=Workload(path)
    print(json.dumps(dict(ok=True,result=worker.result(actor_adaptation=ACTOR_ADAPTATION))),flush=True)
    try:
        for line in sys.stdin:
            try: response=dict(ok=True,result=worker.command(json.loads(line)))
            except Exception as error: response=dict(ok=False,error=repr(error),result=worker.close())
            print(json.dumps(response),flush=True)
    finally:
        closed=worker.close();closed.update(fd_growth=closed['fd_state']['count']-worker.baseline['count'],baseline_equal=closed['fd_state']==worker.baseline)
        print(json.dumps(dict(ok=closed['baseline_equal'] and not LIVE,result=closed)),flush=True)

if __name__=='__main__': main()
