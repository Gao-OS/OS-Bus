"""Explicitly synthetic full-report controls; zero broker/VM executions."""
import copy,hashlib,importlib.util,json,struct,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,p):
    s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
Q=load('fd03_controller_controls',HERE/'qualify.py')
O=load('fd03_frozen_synthetic_helpers',Q.SHARED/'oracle_test.py')
def exercise(old):
    ex=copy.deepcopy(old);del ex['transfer'];source,target=ex['connections'];transfers=[]
    fields=[(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','Resource'),(6,'s',target['name']),(8,'g','h'),(9,'u',1)]
    for i,content in enumerate((b'FD-A',b'FD-B')):
        original=O.fd(5+i,9001+i,target=f'pipe:[{9001+i}]',mode=0o10600)
        received={**original,'fd':7+i};writer={**original,'fd':6+i,'role':'writer','closed':True}
        sent=O.message('source','sent',4,100+i,fields,bytes(4),1)
        sent.update(sendmsg_bytes=sent['wire_bytes'],completed_bytes=sent['wire_bytes'],right_fd=original)
        transfers.append(dict(serial=100+i,sender=source['name'],target=target['name'],signature='h',index=0,header9=1,rights=1,
            content=content.decode(),content_hex=content.hex(),content_sha256=hashlib.sha256(content).hexdigest(),read_chunks_hex=[content.hex(),''],eof=True,
            written_bytes=4,writer_close=writer,source_fd=original,received_fd=received,sent=sent,
            received=O.message('target','received',4,100+i,fields+[(7,'s',source['name'])],bytes(4),1,targets=[received])))
    ex['transfers']=transfers;ex['fd_state']=O.fd_state(sorted(O.BASE+[c['socket'] for c in ex['connections']]+Q.resources(ex),key=lambda r:r['fd']))
    return ex
def closed(ex,op='close'):
    ts=ex['transfers'];owners=[(f'received-{i}',t['received_fd']) for i,t in enumerate(ts)]+[(f'original-{i}',t['source_fd']) for i,t in enumerate(ts)]
    owners += [(c['role'],c['socket']) for c in ex['connections']]
    events={c['role']:copy.deepcopy(c['setup']) for c in ex['connections']};events['source'].append(ex['health'][0]['received']);events['target'] += [t['received'] for t in ts]+[ex['health'][1]['received']]
    return dict(op=op,**O.IDENTITY,closure=[{**r,'role':role,'closed':True} for role,r in owners],events=events,connections=[],held=False,fd_state=O.fd_state(O.BASE),fd_growth=0,baseline_equal=True,latency_ms=1)
def valid_report():
    r=O.valid_report();r.update(requirement='FD-03',subcase='different-bundles',workload=copy.deepcopy(Q.WORKLOAD),selection=Q.SELECTION,result=Q.PASS,adapter_provenance=copy.deepcopy(Q.ADAPTER_PROVENANCE),synthetic=True,runtime_execution=dict(broker=0,vm=0))
    for key,file in Q.SHARED_FILES.items():r['inputs_before'][key]=dict(path=str(Q.SHARED/file),sha256=Q.sha(Q.SHARED/file))
    r['inputs_after']=copy.deepcopy(r['inputs_before'])
    for c in r['combinations']:
        ex=exercise(c['exercise']);c['exercise']=ex;c['close']=closed(ex)
        warm=exercise(c['warmup']['exercise']);c['warmup']['exercise']=warm;c['warmup']['close']=closed(warm,'warmup-close')
        c['checked']['actor']=O.inventory(ex['fd_state']['fds'])
        for phase in ('warmed','connected','checked','closed'):c[phase+'_attempts'][-1]['sample']=c[phase]
        for op,key in zip(c['operations'],('warmup','open','exercise','close')):op['response']={'ok':True,'result':c[key]}
    return r
def replace_value(v,old,new):
    if v==old:return copy.deepcopy(new)
    if isinstance(v,dict):return {k:replace_value(c,old,new) for k,c in v.items()}
    if isinstance(v,list):return [replace_value(c,old,new) for c in v]
    return v
def coherent(r,old,new):
    updated=replace_value(r,old,new);r.clear();r.update(updated)
def transfer(r,index=0):return r['combinations'][0]['exercise']['transfers'][index]
def wrong_wire(r,key,value,direction='received',index=0):
    old=transfer(r,index)[direction];new=copy.deepcopy(old)
    if key=='flags':O.raw_flags(new,value)
    elif key=='fields':
        new['fields'].update(value);types={1:'o',2:'s',3:'s',5:'u',6:'s',7:'s',8:'g',9:'u'}
        raw=O.frame(new['type'],new['serial'],[(int(k),types[int(k)],v) for k,v in new['fields'].items()],bytes.fromhex(new['body_hex']))
        new.update(wire_hex=raw.hex(),wire_sha256=O.digest(raw),wire_bytes=len(raw))
    elif key=='serial':
        raw=bytearray.fromhex(new['wire_hex']);struct.pack_into('<I',raw,8,value);new.update(serial=value,wire_hex=raw.hex(),wire_sha256=O.digest(raw))
    elif key=='body':
        raw=bytes.fromhex(new['wire_hex'])[:-4]+struct.pack('<I',value);new.update(body_hex=struct.pack('<I',value).hex(),wire_hex=raw.hex(),wire_sha256=O.digest(raw))
    coherent(r,old,new)
MUTATIONS={
 'swapped-readers':lambda r:coherent(r,transfer(r)['received_fd'],transfer(r,1)['received_fd']),
 'duplicated-reader':lambda r:coherent(r,transfer(r,1)['received_fd'],transfer(r)['received_fd']),
 'missing-transfer':lambda r:r['combinations'][0]['exercise']['transfers'].pop(),
 'reordered-transfer':lambda r:r['combinations'][0]['exercise']['transfers'].reverse(),
 'duplicate-transfer':lambda r:r['combinations'][0]['exercise']['transfers'].__setitem__(1,copy.deepcopy(transfer(r))),
 'same-pipe':lambda r:coherent(r,transfer(r,1)['source_fd'],{**transfer(r,1)['source_fd'],**{k:transfer(r)['source_fd'][k] for k in ('dev','ino','mode','target')}}),
 'coherent-content':lambda r:coherent(r,transfer(r),{**transfer(r),'content':'FAKE','content_hex':b'FAKE'.hex(),'content_sha256':O.digest(b'FAKE'),'read_chunks_hex':[b'FAKE'.hex(),'']}),
 'wrong-eof':lambda r:transfer(r).update(eof=False),
 'missing-eof-read':lambda r:transfer(r).update(read_chunks_hex=[b'FD-A'.hex()]),
 'wrong-read-bytes':lambda r:transfer(r).update(read_chunks_hex=[b'FD-B'.hex(),'']),
 'early-eof':lambda r:transfer(r).update(read_chunks_hex=['',b'FD-A'.hex(),'']),
 'writer-open':lambda r:coherent(r,transfer(r)['writer_close'],{**transfer(r)['writer_close'],'closed':False}),
 'writer-original':lambda r:transfer(r)['writer_close'].update(fd=transfer(r)['source_fd']['fd']),
 'writer-inode':lambda r:transfer(r)['writer_close'].update(ino=99999),
 'writer-role':lambda r:transfer(r)['writer_close'].update(role='reader'),
 'short-write':lambda r:transfer(r).update(written_bytes=3),
 'missing-right':lambda r:transfer(r)['received'].update(rights=0,fd_targets=[]),
 'extra-right':lambda r:transfer(r)['received'].update(rights=2,fd_targets=[transfer(r)['received_fd'],transfer(r,1)['received_fd']]),
 'serial':lambda r:wrong_wire(r,'serial',101),
 'duplicate-serial':lambda r:wrong_wire(r,'serial',100,index=1),
 'sender':lambda r:wrong_wire(r,'fields',{'7':':1.999'}),
 'destination':lambda r:wrong_wire(r,'fields',{'6':':1.999'}),
 'path':lambda r:wrong_wire(r,'fields',{'1':'/other'}),
 'interface':lambda r:wrong_wire(r,'fields',{'2':'org.other.Transport'}),
 'member':lambda r:wrong_wire(r,'fields',{'3':'Other'}),
 'signature':lambda r:wrong_wire(r,'fields',{'8':'u'}),
 'header-count':lambda r:wrong_wire(r,'fields',{'9':2}),
 'index':lambda r:wrong_wire(r,'body',1),
 'received-flags':lambda r:wrong_wire(r,'flags',1),
 'sent-flags':lambda r:wrong_wire(r,'flags',1,direction='sent'),
 'wire-digest':lambda r:transfer(r)['received'].update(wire_sha256='0'*64),
 'send-identity':lambda r:transfer(r)['sent'].update(right_fd=transfer(r,1)['source_fd']),
 'sendmsg-count':lambda r:transfer(r)['sent'].update(sendmsg_bytes=0),
 'incomplete-send':lambda r:transfer(r)['sent'].update(completed_bytes=1),
 'held':lambda r:r['combinations'][0]['exercise'].update(held=False),
 'held-descriptor':lambda r:r['combinations'][0]['checked']['actor']['fds'].pop(),
 'broker-retention':lambda r:coherent(r,r['combinations'][0]['checked']['broker'],O.inventory(r['combinations'][0]['checked']['broker']['fds']+[{**transfer(r)['source_fd'],'fd':99,'pid':100,'uid':0,'gid':0}],100,0)),
 'numeric-recovery':lambda r:r['combinations'][0]['closed'].update(broker=O.inventory([{**r['combinations'][0]['closed']['broker']['fds'][0],'fd':99}],100,0)),
 'missing-reader-closure':lambda r:r['combinations'][0]['close']['closure'].pop(0),
 'unclosed-reader':lambda r:r['combinations'][0]['close']['closure'][0].update(closed=False),
 'reordered-receives':lambda r:r['combinations'][0]['close']['events']['target'].reverse(),
 'skipped-active-frame':lambda r:r['combinations'][0]['close']['events']['target'].insert(4,copy.deepcopy(transfer(r)['received'])),
 'duplicate-active-frame':lambda r:r['combinations'][0]['close']['events']['target'].insert(5,copy.deepcopy(transfer(r)['received'])),
 'adapter-binding':lambda r:r['adapter_provenance'].update(original_source_sha256='0'*64),
 'source-binding':lambda r:r['inputs_before']['shared_qualify'].update(sha256='0'*64),
}
# Reuse unchanged independent controls for the complete preserved lifecycle.
BASE_CONTROLS=['hello_setup_destination','listnames_setup_destination','hello_setup_sender','listnames_setup_sender','hello_setup_body','listnames_no_array_length','listnames_trailing_body','listnames_duplicate','listnames_missing_self','failed_result','missing_backend','duplicate_backend','failed_backend','fabricated_counts','input_mutated','candidate_mutated','extended_deadline','report_deadline','kernel_uid','launcher_as_actor','executable_binding','credit_leak','open_connection_credits','closed_connection_credits','credential_mismatch','authority_restart','pending_retained','match_retained','capability_retained','queue_retained','output_retained','normalized_cap_changed','normalized_cap_missing','xml_unknown_key','xml_completed_leak','xml_incomplete_leak','xml_uid_leak','xml_queue_enabled','health_sent_flags','setup_sent_flags','reference_fake_telemetry','reference_admission_wildcard','reference_config_export_mutated','reference_config_hash_mutated','reference_static_only','reference_startup_failed','missing_startup_attempt','missing_observation','late_observation','cleanup_late','operations_missing','operation_failure','actor_killed','actor_nonzero','gao_nonzero','reference_killed','actor_eof_bad','eof_leak','process_remains','group_remains','socket_remains','unsafe_unlink']
MUTATIONS.update({'preserved-'+name:O.MUTATIONS[name] for name in BASE_CONTROLS})
class OracleControls(unittest.TestCase):
    def test_complete_synthetic_report(self):Q.assert_report(valid_report())
    def test_frozen_original_still_accepts_original_report(self):O.Q.assert_report(O.valid_report())
    def test_workload_caps_bounds_and_26_guest_input_roles(self):
        self.assertEqual(len(Q.INPUT_KEYS),26);self.assertEqual(Q.CAPS['uid']['egress_fds'],2);self.assertEqual(Q.CAPS['global']['egress_fds'],3)
        self.assertEqual([Q.WORKLOAD[k] for k in ('writer_ms','healthy_ms','cleanup_ms','socket_ms','startup_ms','guest_seconds')],[5000,1000,1000,3000,10000,120])
    def test_exact_shape_transformation_fails_on_drift(self):
        with self.assertRaises(AssertionError):Q.replace_statement(Q.function('assert_report'),"assert x==1","assert x==2")
    def test_two_resource_frames_are_not_selected_twice(self):self.assertEqual(Q.counts(valid_report()['combinations']),dict(selected=2,executed=2,passed=2,failed=0,blocked=0,skipped=0))
def mutation_test(change):
    def test(self):
        r=valid_report();Q.assert_report(r);change(r)
        with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError,struct.error)):Q.assert_report(r)
    return test
for name,change in MUTATIONS.items():setattr(OracleControls,'test_reject_'+name.replace('-','_'),mutation_test(change))
if __name__=='__main__':unittest.main()
