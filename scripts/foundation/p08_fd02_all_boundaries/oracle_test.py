"""Complete synthetic offline reports; never broker or runtime qualification.

Requires a parent-prepared 19-role input map and freeze whose files exist in the
offline environment. Pin verification is real; process/transfer reports below
are deliberately synthetic controls, including all adverse cases.
"""
import argparse,copy,hashlib,importlib.util,io,json,stat,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
Q=load(HERE/'qualify.py','fd02_all_oracle');O=load(Q.REUSE/'oracle_test.py','fd02_all_readonly_singleton_controls');PLAN=load(HERE/'plan.py','fd02_all_plan_controls')
BATCH=load(HERE/'batch.py','fd02_all_batch_deadline_controls')
CONTEXT=None
def held_health(ex):
 target=ex['connections'][1];name=target['name'];bus=Q.P.BUS
 sent=O.message('target','sent',1,112,[(1,'o','/org/freedesktop/DBus'),(2,'s',bus),(3,'s','GetNameOwner'),(6,'s',bus),(8,'g','s')],Q.P.string(name))
 received=O.message('target','received',2,31,[(5,'u',112),(6,'s',name),(7,'s',bus),(8,'g','s')],Q.P.string(name))
 return dict(role='target',serial=112,reply_serial=112,owner=name,rights=0,latency_ms=1,sent=sent,received=received)
def split(m,offset):
 p=m['prefix'];packet=bytes.fromhex(p['packet_hex']);prefix=packet[:offset];suffix=packet[offset:]
 m['boundary']=offset;p.update(offset=offset,geometry=Q.geometry(packet),prefix_hex=prefix.hex(),prefix_sha256=O.digest(prefix),suffix_bytes=len(suffix))
 pieces=[(prefix,1)] if m['mode']==Q.MODES[0] or offset==1 else [(prefix[:-1],0),(prefix[-1:],1)]
 p['sends']=[dict(bytes=len(raw),wire_hex=raw.hex(),sha256=O.digest(raw),rights=rights) for raw,rights in pieces]
 m['held']['offset']=m['exercise']['offset']=offset
 m['exercise']['suffix']=dict(bytes=len(suffix),wire_hex=suffix.hex(),sha256=O.digest(suffix),rights=0)
 m['operations'][1]['command']['offset']=offset
 for phase in ('retained','held_checked'):
  if 'telemetry' in m[phase]:
   state=m[phase]['telemetry'];peer=next(peer for peer in state['peers'] if peer['name']==p['connections'][0]['name']);peer['buffer_bytes']=offset
   for owner in (state['usage']['global'],state['usage']['uids']['1100'],state['usage']['peers'][peer['peer']]):owner['frame_bytes']=offset
def mode(c,name,boundary):
 m={key:copy.deepcopy(c[key]) for key in ('open','exercise','close','connected','checked','closed','connected_attempts','checked_attempts','closed_attempts','cleanup_elapsed_ms')}
 m.update(mode=name,boundary=boundary,phase_order=['open','connected','prefix','retained-observed','retained','held_checked-observed','finish','checked','close','closed'],retained_before_health=True,held_checked_before_finish=True)
 ex=m['exercise'];ex['mode']=name;t=ex['transfer'];packet=bytes.fromhex(t['sent']['wire_hex']);state=copy.deepcopy(m['open']['fd_state']);state['fds'].append(t['source_fd']);state['fds'].sort(key=lambda row:row['fd']);state['count']+=1
 m['prefix']=dict(op='prefix',pid=ex['pid'],uid=ex['uid'],gid=ex['gid'],mode=name,packet_hex=packet.hex(),packet_sha256=O.digest(packet),suffix_sent=False,held=True,connections=ex['connections'],source_fd=t['source_fd'],writer_close=t['writer_close'],written_bytes=4,fd_state=state)
 sample=copy.deepcopy(m['connected']);sample['actor'].update(fds=copy.deepcopy(state['fds']),count=state['count']);sample['broker']['fds'].append(dict(t['source_fd'],fd=99,pid=c['broker']['pid'],uid=0,gid=0));sample['broker']['count']+=1
 if c['backend']=='gao':
  peer=next(peer for peer in sample['telemetry']['peers'] if peer['name']==ex['connections'][0]['name'])
  for owner in (sample['telemetry']['usage']['global'],sample['telemetry']['usage']['uids']['1100'],sample['telemetry']['usage']['peers'][peer['peer']]):owner['frame_fds']=1
 for phase in ('retained','held_checked'):m[phase]=copy.deepcopy(sample);m[phase+'_attempts']=[dict(sample=m[phase],success=True,elapsed_ms=1)]
 health=held_health(ex);m['held']=dict(op='retained',pid=ex['pid'],uid=ex['uid'],gid=ex['gid'],mode=name,suffix_sent=False,target_unreadable=True,source_unreadable=True,target_unreadable_before_probe=True,source_unreadable_before_probe=True,health=health,active_events=dict(source=[],target=[health['received']]),fd_state=copy.deepcopy(state))
 m['close']['events']['target'].insert(len(m['open']['target']['setup']),health['received'])
 m['operations']=[dict(command=command,response=dict(ok=True,result=m[key]),elapsed_ms=1) for command,key in (({'op':'open'},'open'),({'op':'prefix','mode':name},'prefix'),({'op':'retained'},'held'),({'op':'finish'},'exercise'),({'op':'close'},'close'))]
 split(m,boundary);return m
def valid_report(boundary=1):
 assert CONTEXT is not None,'parent-prepared --inputs and --freeze are required'
 r=O.valid_report();r.update(copy.deepcopy(CONTEXT));r.update(requirement='FD-02',subcase='each-relevant-boundary',result=Q.PASS,selection=Q.SELECTION,workload=Q.WORKLOAD,mode_observations=4,boundary=boundary,socket=str(Q.socket_path(boundary)),lifecycle_source_sha256=Q.BASE_SHA,active_node_sha256=Q.ACTIVE_NODE_SHA,preflight_verified=True,synthetic_offline_control=True)
 r['observer'].update(executable=r['inputs_before']['python']['path'],executable_sha256=r['inputs_before']['python']['sha256'])
 r['observer']['starttime_ticks']=100*boundary
 for backend_index,c in enumerate(r['combinations']):
  for key,role in (('actor','python'),('broker','beam' if c['backend']=='gao' else 'reference_executable'),('launcher','runuser')):c[key].update(executable=r['inputs_before'][role]['path'],executable_sha256=r['inputs_before'][role]['sha256'])
  for key in ('actor','broker','launcher'):c[key]['starttime_ticks']=100*boundary+backend_index
  for key,role in (('actor','python'),('broker','elixir' if c['backend']=='gao' else 'reference_executable')):c['versions'][key]['command'][0]=r['inputs_before'][role]['path']
  namespace=Q.private_namespace(boundary)
  if c['backend']=='gao':c['effective_config']=namespace['native_config']()
  else:
   config=namespace['reference_config'](r['socket']);c.update(reference_config=config,reference_config_exported=config,reference_config_sha256=O.digest(config.encode()),reference_config_path=str(Q.socket_path(boundary).parent/'reference/reference.conf'))
   c['backend_command']=[r['inputs_before']['reference_executable']['path'],'--nofork','--nopidfile','--config-file='+c['reference_config_path']]
  c['modes']=[mode(c,name,boundary) for name in Q.MODES];c['operations']=[c['operations'][0]]+[op for m in c['modes'] for op in m['operations']]
 r['geometry']=r['combinations'][0]['modes'][0]['prefix']['geometry'];return r
def fifo_fault(m,fault):
 for phase in ('retained','held_checked'):
  inv=m[phase]['broker']
  if fault=='lost':inv['fds'].pop()
  elif fault=='duplicate':inv['fds'].append(dict(inv['fds'][-1],fd=100))
  else:inv['fds'][-1].update(ino=12345,target='pipe:[12345]')
  inv['count']=len(inv['fds'])
def coherent_bad_index(m):
 # Rewrite actual full frames and all split bytes; copied expected/actual
 # booleans cannot turn index1 into this singleton's required h/index0.
 p=m['prefix'];raw=bytes.fromhex(p['packet_hex'])[:-4]+b'\x01\0\0\0';p.update(packet_hex=raw.hex(),packet_sha256=O.digest(raw))
 transfer=m['exercise']['transfer'];transfer['index']=1
 for key in ('sent','received'):
  row=transfer[key];packet=bytes.fromhex(row['wire_hex'])[:-4]+b'\x01\0\0\0';row.update(body_hex='01000000',wire_hex=packet.hex(),wire_sha256=O.digest(packet))
 # Avoid calling the valid-geometry builder on the deliberately invalid body.
 offset=p['offset'];prefix=raw[:offset];suffix=raw[offset:];p.update(prefix_hex=prefix.hex(),prefix_sha256=O.digest(prefix))
 pieces=[(prefix,1)] if m['mode']==Q.MODES[0] or offset==1 else [(prefix[:-1],0),(prefix[-1:],1)]
 p['sends']=[dict(bytes=len(piece),wire_hex=piece.hex(),sha256=O.digest(piece),rights=rights) for piece,rights in pieces]
 m['exercise']['suffix']=dict(bytes=len(suffix),wire_hex=suffix.hex(),sha256=O.digest(suffix),rights=0)
MODE_FAULTS={
 'coherent_empty_prefix':lambda m:split(m,0),
 'coherent_complete_frame':lambda m:split(m,len(bytes.fromhex(m['prefix']['packet_hex']))),
 'wrong_boundary':lambda m:m.update(boundary=m['boundary']+1),
 'wrong_geometry':lambda m:m['prefix']['geometry'].update(body_start=1),
 'wrong_mode':lambda m:m['prefix'].update(mode='wrong'),
 'missing_final_right':lambda m:m['prefix']['sends'][-1].update(rights=0),
 'duplicate_final_right':lambda m:m['prefix']['sends'][-1].update(rights=2),
 **{'coherent_'+fault+'_fifo':lambda m,fault=fault:fifo_fault(m,fault) for fault in ('lost','duplicate','swapped')},
 'premature_suffix':lambda m:(m['prefix'].update(suffix_sent=True),m['held'].update(suffix_sent=True)),
 'premature_delivery':lambda m:m['held']['active_events']['target'].append(m['exercise']['transfer']['received']),
 'premature_source_output':lambda m:m['held'].update(source_unreadable_before_probe=False),
 'premature_target_output':lambda m:m['held'].update(target_unreadable_before_probe=False),
 'source_health':lambda m:m['held']['active_events']['source'].append(m['exercise']['health'][0]['received']),
 'bad_health112':lambda m:m['held']['health'].update(reply_serial=999),
 'suffix_right':lambda m:m['exercise']['suffix'].update(rights=1),
 'bad_index':lambda m:m['exercise']['transfer'].update(index=1),
 'coherent_bad_index':coherent_bad_index,
 'bad_body':lambda m:m['exercise']['transfer']['received'].update(body_hex='01000000'),
 'wrong_kind':lambda m:m['exercise']['transfer']['received_fd'].update(mode=0o100600),
 'bad_content':lambda m:m['exercise']['transfer'].update(content='FAKE',content_hex=b'FAKE'.hex(),content_sha256=O.digest(b'FAKE')),
 'bad_sender':lambda m:m['exercise']['transfer'].update(sender=':1.999'),
 'writer_open':lambda m:m['prefix']['writer_close'].update(closed=False),
 'reader_open':lambda m:m['close']['closure'][0].update(closed=False),
 'bad_numeric_recovery':lambda m:m['closed']['broker']['fds'][0].update(fd=999),
 'no_hold_barrier':lambda m:m.update(held_checked_before_finish=False),
 'bad_order':lambda m:m['phase_order'].reverse(),
 'observer_identity':lambda m:m['retained']['broker'].update(pid=999),
 'wrong_open_source':lambda m:m['open'].update(source=m['open']['target']),
 'wrong_open_target':lambda m:m['open'].update(target=m['open']['source']),
 'wrong_open_op':lambda m:m['open'].update(op='finish'),
}
class AllBoundaryOracle(unittest.TestCase):
 def test_every_offset_both_modes_and_backends(self):
  n=valid_report()['geometry']['boundaries']
  for boundary in range(1,n+1):Q.assert_report(valid_report(boundary))
 def test_complete_report_adverse_controls_every_backend_mode(self):
  for backend in range(2):
   for arrival in range(2):
    for name,change in MODE_FAULTS.items():
     with self.subTest(backend=backend,arrival=arrival,fault=name):
      r=valid_report(15);change(r['combinations'][backend]['modes'][arrival])
      with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError)):Q.assert_report(r)
 def test_scalar_config_provenance_teardown_and_freeze(self):
  changes=[lambda r:r['combinations'][0]['modes'][0]['retained']['telemetry']['usage']['global'].update(frame_fds=0),lambda r:r['combinations'][0]['effective_config'].update(socket='/wrong'),lambda r:r['combinations'][1].update(reference_config_exported='wrong'),lambda r:r['combinations'][0]['teardown'].update(groups_absent=False),lambda r:r.update(preflight_verified=False),lambda r:r['freeze']['guest_inputs']['actor'].update(mode=0),lambda r:r['freeze']['guest_inputs'].pop('plan'),lambda r:r['freeze']['reused_inputs']['actor.py'].update(sha256='b'*64),lambda r:r['extra_inputs_after']['batch'].update(sha256='b'*64),lambda r:r['inputs_after']['scope'].update(sha256='b'*64)]
  for change in changes:
   r=valid_report();change(r)
   with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError)):Q.assert_report(r)
 def test_private_configuration_keeps_all_policy_and_limit_bytes(self):
  original=Q.P.reference_config(Q.P.WORKLOAD['socket'])
  for boundary in (1,9,139):
   namespace=Q.private_namespace(boundary);path=str(Q.socket_path(boundary));self.assertEqual(namespace['native_config']()['socket'],path)
   self.assertEqual(namespace['reference_config'](path).replace('unix:path='+path,'unix:path='+Q.P.WORKLOAD['socket']),original)
 def test_lifecycle_adapts_only_the_pinned_active_nodes(self):
  runner=Q.lifecycle(1);self.assertTrue(callable(runner));self.assertIn('run_modes',runner.__code__.co_names)
  self.assertNotEqual(runner.__code__,Q.P.run_backend.__code__)
 def test_actual_mode_loop_replays_complete_transcript(self):
  r=valid_report(15)
  for c in r['combinations']:
   fixtures=copy.deepcopy(c['modes']);c['operations']=c['operations'][:1]
   class OfflineActorTranscript:
    def begin(self,**command):self.command=command
    def read(self,timeout=10):
     current=c['modes'][-1];fixture=fixtures[Q.MODES.index(current['mode'])];key={'open':'open','prefix':'prefix','retained':'held','finish':'exercise','close':'close'}[self.command['op']]
     if key=='prefix':assert self.command==dict(op='prefix',mode=current['mode'],offset=15)
     return dict(ok=True,result=copy.deepcopy(fixture[key]))
   def sample(empty=False):
    current=c['modes'][-1];fixture=fixtures[Q.MODES.index(current['mode'])];phase=current['phase_order'][-1].removesuffix('-observed');return copy.deepcopy(fixture[phase])
   args=type('OfflineArgs',(),{'boundary':15})()
   Q.run_modes(args,r,c,OfflineActorTranscript(),object() if c['backend']=='gao' else None,sample,lambda:None)
  Q.assert_report(r)
 def test_complete_batch_and_exact_coverage_with_short_final(self):
  entries=self.entries();counts=PLAN.assert_coverage(entries,Q.assert_report)
  n=entries[0][0]['geometry']['boundaries'];self.assertEqual(counts['mode_observations'],4*n);self.assertIsNone(counts['physical_vm_count'])
  self.assertEqual(entries[-1][0]['count'],min(8,n-entries[-1][0]['first']+1))
 def entries(self):
  geometry=valid_report()['geometry'];entries=[]
  for spec in PLAN.batches(geometry):
   reports=[valid_report(boundary) for boundary in range(spec['first'],spec['first']+spec['count'])]
   rows=[dict(boundary=r['boundary'],result='passed',returncode=0,controller_reaped=True,report_sha256=O.digest((json.dumps(r,indent=2,sort_keys=True)+'\n').encode())) for r in reports]
   batch=dict(schema=1,scope='FD02/all-boundaries/core/batch',result='passed',**spec,geometry=geometry,guest_seconds=120,elapsed_seconds=1,cases=rows,controller_invocations=spec['count'],backend_invocations=2*spec['count'],mode_observations=4*spec['count'],physical_vm_count=None)
   entries.append((batch,reports))
  return entries
 def test_missing_duplicate_extra_batches_and_forged_vm_counts(self):
  entries=self.entries()
  controls=[entries[:-1],entries+[entries[-1]],entries[1:]]
  for value in controls:
   with self.assertRaises(AssertionError):PLAN.assert_coverage(value,Q.assert_report)
  for key,value in (('physical_vm_count',1),('guest_seconds',121),('mode_observations',2),('backend_invocations',1),('elapsed_seconds',121),('count',9)):
   altered=copy.deepcopy(entries);altered[0][0][key]=value
   with self.assertRaises(AssertionError):PLAN.assert_coverage(altered,Q.assert_report)
 def test_reused_process_instance_and_unsealed_host_receipts_rejected(self):
  entries=self.entries();altered=copy.deepcopy(entries)
  for c in altered[0][1][1]['combinations']:
   for key in ('broker','actor','launcher'):c[key]['starttime_ticks']-=100
  # Re-seal the synthetic report hash to expose the actual identity predicate.
  altered[0][0]['cases'][1]['report_sha256']=O.digest((json.dumps(altered[0][1][1],indent=2,sort_keys=True)+'\n').encode())
  with self.assertRaisesRegex(AssertionError,'reused'):PLAN.assert_coverage(altered,Q.assert_report)
  receipts=[dict(vm_id=str(i),sealed=True,shutdown_confirmed=True,host_seconds=900,elapsed_seconds=1,batch_first=batch['first'],batch_sha256=O.digest((json.dumps(batch,indent=2,sort_keys=True)+'\n').encode())) for i,(batch,_) in enumerate(entries)]
  counts=PLAN.assert_coverage(entries,Q.assert_report,receipts);self.assertEqual(counts['physical_vm_count'],len(entries))
  receipts[0]['sealed']=False
  with self.assertRaises(AssertionError):PLAN.assert_coverage(entries,Q.assert_report,receipts)
class BatchDeadlineFlow(unittest.TestCase):
 """Mocked controller/clock flow only; no full-oracle or broker qualification.

 The complete real oracle controls above remain separate. These controls drive
 the actual run_batch path and real temporary JSON persistence, with fake child
 transcripts only to select when synchronous validation crosses the deadline.
 """
 def exercise(self,late_phase=None):
  with tempfile.TemporaryDirectory(prefix='fd02-deadline-control-') as directory:
   root=Path(directory);output=root/'batch.json';clock=types.SimpleNamespace(now=119.0);seen=[];oracle_calls=[];writes=[]
   geometry=dict(frame_bytes=2,boundaries=1)
   case=dict(boundary=1,geometry=geometry,counts=dict(executed=2),mode_observations=4)
   names=('candidate','fixtures','wire_dir','helpers','quota_daemon','collector','reference_executable','scope','reuse_fixtures','freeze')
   args=types.SimpleNamespace(first=1,count=1,**{key:root/key for key in names})
   def oracle(report):
    oracle_calls.append(report)
    if late_phase=='case_oracle' and len(oracle_calls)==1:clock.now=121.0
   def replay(candidate,reports,check):
    seen.append(json.loads(output.read_text())['result']);self.assertEqual(candidate['result'],'passed');check(reports[-1])
    if late_phase=='batch_replay':clock.now=121.0
   controller=types.SimpleNamespace(socket_path=lambda boundary:root/('case-'+str(boundary))/'bus',assert_report=oracle)
   plan=types.SimpleNamespace(assert_batch=replay)
   original_dumps=json.dumps;original_write=Path.write_text;original_read=Path.read_text
   def dumps(value,*args,**kwargs):
    raw=original_dumps(value,*args,**kwargs)
    if isinstance(value,dict) and value.get('result')=='passed':
     if late_phase=='report_serialization' and value.get('scope')=='FD02/all-boundaries/core/batch':clock.now=121.0
     if late_phase=='return_serialization' and 'scope' not in value:clock.now=121.0
    return raw
   def write(path,raw,*args,**kwargs):
    result=original_write(path,raw,*args,**kwargs)
    if path==output:
     payload=json.loads(raw);writes.append(payload['result'])
     if late_phase=='report_persistence' and payload['result']=='passed':clock.now=121.0
    return result
   def read(path,*args,**kwargs):
    raw=original_read(path,*args,**kwargs)
    if late_phase=='persisted_readback' and path==output and json.loads(raw)['result']=='passed':clock.now=121.0
    return raw
   class OfflineController:
    pid=12345
    def __init__(self,command,**kwargs):
     self.assertions=kwargs;self.returncode=None;evidence=Path(command[command.index('--evidence')+1]);(evidence/'report.json').write_text(original_dumps(case,indent=2,sort_keys=True)+'\n')
    def wait(self,timeout):self.returncode=0;return 0
    def poll(self):return self.returncode
   stdout=io.StringIO()
   with patch.object(BATCH.time,'monotonic',lambda:clock.now),patch.object(BATCH.subprocess,'Popen',OfflineController),patch.object(BATCH.json,'dumps',dumps),patch.object(Path,'write_text',write),patch.object(Path,'read_text',read),patch('sys.stdout',stdout):
    if late_phase is None:result=BATCH.run_batch(args,controller,plan,0.0,120.0,output,[]);self.assertEqual(result['result'],'passed')
    else:
     with self.assertRaises(AssertionError):BATCH.run_batch(args,controller,plan,0.0,120.0,output,[])
   persisted=json.loads(output.read_text())
   self.assertEqual(persisted['result'],'passed' if late_phase is None else 'failed')
   if late_phase is not None:self.assertGreater(persisted['elapsed_seconds'],120);self.assertEqual(stdout.getvalue(),'')
   if late_phase in ('case_oracle','batch_replay','report_serialization'):self.assertNotIn('passed',writes,'provisional or late success must never be persisted')
   if late_phase!='case_oracle':self.assertEqual(seen,['running'],'persisted report must remain running during complete replay')
   return persisted
 def test_completion_inside_deadline_succeeds(self):self.exercise()
 def test_final_case_oracle_crossing_deadline_fails(self):self.exercise('case_oracle')
 def test_full_batch_replay_crossing_deadline_fails(self):self.exercise('batch_replay')
 def test_final_report_serialization_crossing_deadline_fails(self):self.exercise('report_serialization')
 def test_final_report_persistence_crossing_deadline_is_rewritten_failed(self):self.exercise('report_persistence')
 def test_persisted_readback_crossing_deadline_is_rewritten_failed(self):self.exercise('persisted_readback')
 def test_final_return_serialization_crossing_deadline_fails(self):self.exercise('return_serialization')
def main():
 global CONTEXT
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inputs',required=True,type=Path);parser.add_argument('--freeze',required=True,type=Path);args,remaining=parser.parse_known_args()
 inputs=json.loads(args.inputs.read_text());assert set(inputs)==Q.P.INPUT_KEYS
 additional={key:dict(path=str(path),sha256=Q.P.sha(path)) for key,path in (('batch',HERE/'batch.py'),('plan',HERE/'plan.py'),('freeze',args.freeze))}
 reused={name:dict(path=str(Q.REUSE/name),sha256=Q.P.sha(Q.REUSE/name),mode=stat.S_IMODE((Q.REUSE/name).stat().st_mode)) for name in Q.REUSE_FILES}
 manifest=json.loads(Path(inputs['candidate_manifest']['path']).read_text());broadcast=Path(inputs['transport_actor']['path']).parent/'broadcast_delivery_actor.py'
 CONTEXT=dict(inputs_before=inputs,inputs_after=copy.deepcopy(inputs),extra_inputs_before=additional,extra_inputs_after=copy.deepcopy(additional),input_modes_before={key:stat.S_IMODE(Path(row['path']).stat().st_mode) for key,row in {**inputs,**{key:row for key,row in additional.items() if key!='freeze'}}.items()},reuse_inputs_before=reused,reuse_inputs_after=copy.deepcopy(reused),freeze=json.loads(args.freeze.read_text()),manifest=manifest,candidate_before=manifest['files'],candidate_after=copy.deepcopy(manifest['files']),broadcast_actor=dict(path=str(broadcast),sha256=Q.P.sha(broadcast)))
 CONTEXT['input_modes_after']=copy.deepcopy(CONTEXT['input_modes_before']);Q.verify_preflight(CONTEXT)
 unittest.main(argv=[__file__,*remaining],verbosity=2)
if __name__=='__main__':main()
