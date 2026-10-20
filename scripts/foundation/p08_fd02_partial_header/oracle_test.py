"""Synthetic offline controls only; reports are not selected runtime evidence."""
import ast,copy,hashlib,importlib.util,inspect,json,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
Q=load(HERE/'qualify.py','fd02_new_oracle');O=load(HERE.parent/'p08_fd01_singleton_resources/oracle_test.py','fd02_readonly_oracle_controls')
def hold_health(ex):
 target=ex['connections'][1];name=target['name'];bus=Q.P.BUS
 sent=O.message('target','sent',1,112,[(1,'o','/org/freedesktop/DBus'),(2,'s',bus),(3,'s','GetNameOwner'),(6,'s',bus),(8,'g','s')],Q.P.string(name))
 received=O.message('target','received',2,31,[(5,'u',112),(6,'s',name),(7,'s',bus),(8,'g','s')],Q.P.string(name))
 return dict(role='target',serial=112,reply_serial=112,owner=name,rights=0,latency_ms=1,sent=sent,received=received)
def mode(c,name):
 m={k:copy.deepcopy(c[k]) for k in ('open','exercise','close','connected','checked','closed','connected_attempts','checked_attempts','closed_attempts','cleanup_elapsed_ms')};m['mode']=name;m['phase_order']=['open','connected','prefix','retained-observed','retained','held_checked-observed','finish','checked','close','closed']
 ex=m['exercise'];ex['mode']=name;t=ex['transfer'];packet=bytes.fromhex(t['sent']['wire_hex']);prefix=packet[:15]
 state=copy.deepcopy(m['open']['fd_state']);state['fds'].append(t['source_fd']);state['fds'].sort(key=lambda f:f['fd']);state['count']+=1
 pieces=[(prefix,1)] if name==Q.MODES[0] else [(prefix[:14],0),(prefix[14:],1)]
 p=dict(op='prefix',pid=ex['pid'],uid=ex['uid'],gid=ex['gid'],mode=name,offset=15,prefix_hex=prefix.hex(),prefix_sha256=hashlib.sha256(prefix).hexdigest(),packet_hex=packet.hex(),packet_sha256=hashlib.sha256(packet).hexdigest(),suffix_bytes=len(packet)-15,suffix_sent=False,held=True,connections=ex['connections'],source_fd=t['source_fd'],writer_close=t['writer_close'],written_bytes=4,fd_state=state,
  sends=[dict(bytes=len(raw),wire_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest(),rights=right) for raw,right in pieces]);m['prefix']=p
 sample=copy.deepcopy(m['connected']);sample['actor']['fds']=copy.deepcopy(state['fds']);sample['actor']['count']=state['count']
 sample['broker']['fds'].append(dict(t['source_fd'],fd=99,pid=c['broker']['pid'],uid=0,gid=0));sample['broker']['count']+=1
 if c['backend']=='gao':
  peer=next(p for p in sample['telemetry']['peers'] if p['name']==ex['connections'][0]['name']);peer['buffer_bytes']=15
  for owner in (sample['telemetry']['usage']['global'],sample['telemetry']['usage']['uids']['1100'],sample['telemetry']['usage']['peers'][peer['peer']]):owner.update(frame_bytes=15,frame_fds=1)
 for phase in ('retained','held_checked'):m[phase]=copy.deepcopy(sample);m[phase+'_attempts']=[dict(sample=m[phase],success=True,elapsed_ms=1)]
 health=hold_health(ex);m['held']=dict(op='retained',pid=ex['pid'],uid=ex['uid'],gid=ex['gid'],mode=name,suffix_sent=False,target_unreadable=True,health=health,active_events=dict(source=[],target=[health['received']]),fd_state=copy.deepcopy(state))
 suffix=packet[15:];ex['suffix']=dict(bytes=len(suffix),wire_hex=suffix.hex(),sha256=hashlib.sha256(suffix).hexdigest(),rights=0)
 target_events=m['close']['events']['target'];target_events.insert(len(m['open']['target']['setup']),health['received'])
 m['retained_before_health']=m['held_checked_before_finish']=True
 m['operations']=[dict(command=command,response=dict(ok=True,result=m[key]),elapsed_ms=1) for command,key in (({'op':'open'},'open'),({'op':'prefix','mode':name},'prefix'),({'op':'retained'},'held'),({'op':'finish'},'exercise'),({'op':'close'},'close'))]
 return m
def valid_report():
 r=O.valid_report();r.update(requirement='FD-02',subcase='partial-header',result=Q.PASS,selection=Q.SELECTION,workload=Q.WORKLOAD,mode_observations=4,lifecycle_source_sha256=Q.BASE_SHA,active_node_sha256=Q.ACTIVE_NODE_SHA)
 r['reuse_inputs_before']={name:dict(path=str(Q.REUSE/name),sha256=Q.P.sha(Q.REUSE/name)) for name in Q.REUSE_FILES};r['reuse_inputs_after']=copy.deepcopy(r['reuse_inputs_before'])
 for c in r['combinations']:
  c['modes']=[mode(c,name) for name in Q.MODES];c['operations']=[c['operations'][0]]+[op for m in c['modes'] for op in m['operations']]
 return r
def open_control(backend,arrival_mode,fault):
 r=valid_report();c=r['combinations'][backend];m=c['modes'][arrival_mode];opened=m['open']
 field=fault.removeprefix('wrong_').removeprefix('missing_')
 if fault.startswith('missing_'):del opened[field]
 else:opened[field]='finish' if field=='op' else opened['connections'][1 if field=='source' else 0]
 assert m['operations'][0]['command']=={'op':'open'}
 assert m['operations'][0]['response']['result'] is opened
 assert c['operations'][1+5*arrival_mode]['response']['result'] is opened
 return r
OPEN_FAULTS=('wrong_op','wrong_source','wrong_target','missing_op','missing_source','missing_target')
CHANGES={
 'phase_order':lambda m:m['phase_order'].reverse(),
 'observer_owner':lambda m:m['retained']['broker'].update(pid=999),
 'absent_retention':lambda m:m['retained']['broker']['fds'].pop(),
 'swapped_right':lambda m:m['retained']['broker']['fds'][-1].update(ino=12345,target='pipe:[12345]'),
 'wrong_kind':lambda m:m['retained']['broker']['fds'][-1].update(mode=0o100600),
 'wrong_offset':lambda m:m['prefix'].update(offset=14),
 'wrong_mode':lambda m:m['prefix'].update(mode='wrong'),
 'wrong_prefix':lambda m:m['prefix'].update(prefix_hex='00'*15,prefix_sha256=hashlib.sha256(bytes(15)).hexdigest()),
 'wrong_send_position':lambda m:m['prefix']['sends'][0].update(rights=0),
 'premature_finish':lambda m:m.update(held_checked_before_finish=False),
 'premature_delivery':lambda m:m['held']['active_events']['target'].append(m['exercise']['transfer']['received']),
 'source_health_while_partial':lambda m:m['held']['active_events']['source'].append(m['exercise']['health'][0]['received']),
 'target_not_healthy':lambda m:m['held']['health'].update(reply_serial=999),
 'prefix_suffix_sent':lambda m:m['prefix'].update(suffix_sent=True),
 'held_buffer':lambda m:m['retained']['telemetry']['peers'][0].update(buffer_bytes=14),
 'held_credit':lambda m:m['retained']['telemetry']['usage']['global'].update(frame_fds=0),
 'held_authority':lambda m:m['retained']['telemetry']['authorities'].update({'GaoBus.Ids':'#PID<9.9.9>'}),
 'suffix_right':lambda m:m['exercise']['suffix'].update(rights=1),
 'transfer_wrong_content':lambda m:m['exercise']['transfer'].update(content='FAKE',content_hex=b'FAKE'.hex(),content_sha256=hashlib.sha256(b'FAKE').hexdigest()),
 'transfer_wrong_index':lambda m:m['exercise']['transfer'].update(index=1),
 'transfer_wrong_right_count':lambda m:m['exercise']['transfer'].update(rights=2),
 'transfer_wrong_sender':lambda m:m['exercise']['transfer'].update(sender=':1.999'),
 'writer_unclosed':lambda m:m['prefix']['writer_close'].update(closed=False),
 'reader_unclosed':lambda m:m['close']['closure'][0].update(closed=False),
 'numeric_recovery':lambda m:m['closed']['broker']['fds'][0].update(fd=999),
 'broker_leak_after_finish':lambda m:m['checked']['broker']['fds'].append(m['exercise']['transfer']['source_fd']),
 'forged_equality':lambda m:m.update(expected={'retained':True},actual={'retained':True},retained_before_health=False),
}
class PartialOracle(unittest.TestCase):
 def test_incomplete_prefix_requires_external_broker_retention(self):Q.assert_report(valid_report())
 def test_reference_is_kernel_observed_without_scalar_fabrication(self):
  r=valid_report();m=r['combinations'][1]['modes'][0];m['retained']['telemetry']={}
  with self.assertRaisesRegex(AssertionError,'invented reference'):Q.assert_report(r)
 def test_lifecycle_replaces_only_frozen_active_nodes(self):
  runner=Q.lifecycle();self.assertTrue(callable(runner))
  self.assertNotEqual(runner.__code__,Q.P.run_backend.__code__)
  code=runner.__code__;self.assertIn('run_modes',code.co_names)
 def test_selected_modes_are_not_four_backend_combinations(self):
  r=valid_report();self.assertEqual(r['counts']['selected'],2);self.assertEqual(r['mode_observations'],4)
  r['mode_observations']=2
  with self.assertRaises(AssertionError):Q.assert_report(r)
 def test_actual_mode_loop_exposes_complete_order_and_recovers_between_modes(self):
  r=valid_report()
  for c in r['combinations']:
   fixtures=copy.deepcopy(c['modes']);c['operations']=c['operations'][:1]
   class OfflineActorTranscript:
    def begin(self,**command):self.command=command
    def read(self,timeout=10):
     name=c['modes'][-1]['mode'];fixture=fixtures[Q.MODES.index(name)]
     key={'open':'open','prefix':'prefix','retained':'held','finish':'exercise','close':'close'}[self.command['op']]
     if self.command['op']=='prefix':assert self.command['mode']==name
     return dict(ok=True,result=copy.deepcopy(fixture[key]))
   def sample(empty=False):
    current=c['modes'][-1];fixture=fixtures[Q.MODES.index(current['mode'])]
    phase=current['phase_order'][-1].removesuffix('-observed')
    return copy.deepcopy(fixture[phase])
   Q.run_modes(None,r,c,OfflineActorTranscript(),object() if c['backend']=='gao' else None,sample,lambda:None)
  Q.assert_report(r)
  self.assertEqual(sum(len(c['modes']) for c in r['combinations']),4)
  self.assertTrue(all(c['modes'][0]['closed']==c['modes'][1]['closed'] for c in r['combinations']))
 def test_all_adverse_controls(self):
  Q.assert_report(valid_report())
  for name,change in CHANGES.items():
   with self.subTest(name=name):
    r=valid_report();change(r['combinations'][0]['modes'][0])
    with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError)):Q.assert_report(r)
def open_control_test(backend,arrival_mode,fault):
 def test(self):
  Q.assert_report(valid_report())
  with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError)):
   Q.assert_report(open_control(backend,arrival_mode,fault))
 return test
for backend,name in enumerate(('gao','reference')):
 for arrival_mode,mode_name in enumerate(Q.MODES):
  for fault in OPEN_FAULTS:
   setattr(PartialOracle,'test_open_response_'+name+'_'+mode_name.replace('-','_')+'_'+fault,open_control_test(backend,arrival_mode,fault))
if __name__=='__main__':unittest.main(verbosity=2)
