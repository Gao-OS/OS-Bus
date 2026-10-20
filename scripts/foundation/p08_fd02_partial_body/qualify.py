"""Bounded FD02/core final-body-byte controller; runtime requires an isolated guest.

Accepted lifecycle source is hash/AST-shape frozen; only the active workload node
range is replaced with run_modes. All imported startup/warmup/teardown is intact.
"""
import struct,argparse,ast,copy,hashlib,importlib.util,inspect,json,os,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
REUSE=Path(os.environ.get('FD02_PIPE_FIXTURES',str(HERE.parent/'p08_fd01_singleton_resources')))
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
P=load(REUSE/'qualify.py','fd02_readonly_pipe_controller')
WORKLOAD=json.loads((HERE/'workload.json').read_text());MODES=tuple(WORKLOAD['arrival_modes'])
PASS='passed_independent_fd02_partial_body_core';SELECTION=['FD-02/core/partial-body/'+b for b in ('gao','reference')]
BASE_SHA='1e17175dd92c795702de4d5dd69f85e9f632340fb769672e17122d4227e736f6'
REUSE_FILES=('actor.py','actor_test.py','qualify.py','oracle_test.py','workload.json','test.nix','README.md')
def body_offset(packet):
 # The complete strict decoder checks every header field and all padding first.
 P.parse_frame(packet)
 body,serial,header=struct.unpack_from('<III',packet,4)
 start=16+header+(-header%8)
 assert body==4 and serial==100 and len(packet)==start+4,'not a four-byte h body'
 offset=len(packet)-1
 assert offset==start+3,'partial-body must hold exactly final body byte'
 return offset

def assert_prefix(row):
 packet=bytes.fromhex(row['packet_hex']);offset=body_offset(packet)
 assert row['op']=='prefix' and row['mode'] in MODES and row['offset']==offset and row['suffix_sent'] is False and row['held'] is True
 P.assert_connections(row);packet=bytes.fromhex(row['packet_hex']);parsed=P.parse_frame(packet)
 names={r['role']:r['name'] for r in row['connections']}
 assert parsed==dict(type=4,serial=100,flags=0,fields={'1':'/foundation','2':'org.foundation.Transport','3':'Resource','6':names['target'],'8':'h','9':1},body_hex='00000000')
 prefix=packet[:offset];assert row['prefix_hex']==prefix.hex() and row['prefix_sha256']==hashlib.sha256(prefix).hexdigest()
 assert row['packet_sha256']==hashlib.sha256(packet).hexdigest() and row['suffix_bytes']==len(packet)-offset
 pieces=[(prefix,1)] if row['mode']==MODES[0] else [(prefix[:-1],0),(prefix[-1:],1)]
 assert row['sends']==[dict(bytes=len(raw),wire_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest(),rights=rights) for raw,rights in pieces],'wrong prefix send positions'
 source,writer=row['source_fd'],row['writer_close'];P.assert_fd(source,row);P.assert_fd(writer,row)
 assert P.stat.S_ISFIFO(source['mode']) and source['target']==f"pipe:[{source['ino']}]"
 assert writer['role']=='writer' and writer['closed'] is True and row['written_bytes']==4 and writer['fd']!=source['fd']
 assert all(writer[k]==source[k] for k in ('dev','ino','mode','target'))
 assert row['fd_state']['count']==len(row['fd_state']['fds']) and source in row['fd_state']['fds']
def assert_hold_health(row,prefix):
 assert row['op']=='retained' and row['mode']==prefix['mode'] and row['suffix_sent'] is False and row['target_unreadable'] is True
 assert all(row[k]==prefix[k] for k in ('pid','uid','gid')) and row['fd_state']==prefix['fd_state']
 h=row['health'];target=prefix['connections'][1];P.latency(h['latency_ms'],1000)
 assert (h['role'],h['serial'],h['reply_serial'],h['owner'],h['rights'])==('target',112,112,target['name'],0)
 sent=P.assert_wire(h['sent']);received=P.assert_wire(h['received'])
 assert sent==dict(type=1,serial=112,flags=0,fields={'1':'/org/freedesktop/DBus','2':P.BUS,'3':'GetNameOwner','6':P.BUS,'8':'s'},body_hex=P.string(target['name']).hex())
 f=received['fields'];assert received['type']==2 and f.get('5')==112 and f.get('6')==target['name'] and f.get('7')==P.BUS and f.get('8')=='s' and f.get('9',0)==0
 assert set(f)<=set(('5','6','7','8','9')) and received['body_hex']==P.string(target['name']).hex()
 for direction in ('sent','received'):
  assert h[direction]['rights']==0 and h[direction]['role']=='target' and h[direction]['phase']=='active' and h[direction]['direction']==direction
 assert h['received']['fd_targets']==[],'held health installed unexpected rights'
 assert row['active_events']==dict(source=[],target=[h['received']]),'premature delivery/source health'
def assert_retained(sample,prefix,baseline,backend):
 assert_prefix(prefix);P.assert_actor_inventory(prefix,sample['actor']);P.assert_inventory(sample['broker'])
 resource=prefix['source_fd'];matches=[f for f in sample['broker']['fds'] if all(f[k]==resource[k] for k in ('dev','ino','mode','target'))]
 assert len(matches)==1 and P.stat.S_ISFIFO(matches[0]['mode']),'actual broker FIFO retention absent/swapped'
 assert sample['broker']['count']==baseline['broker']['count']+1
 assert [f for f in sample['broker']['fds'] if f not in matches]==baseline['broker']['fds'],'other broker inventory changed'
 if backend=='gao':
  state=copy.deepcopy(sample['telemetry']);names={c['role']:c['name'] for c in prefix['connections']}
  peer,=[p for p in state['peers'] if p['name']==names['source']]
  assert peer['buffer_bytes']==body_offset(bytes.fromhex(prefix['packet_hex'])) and peer['queue']==0 and peer['output'] is None,'source partial buffer mismatch'
  peer['buffer_bytes']=0
  owners=(state['usage']['global'],state['usage']['uids']['1100'],state['usage']['peers'][peer['peer']])
  assert all(owner['frame_bytes']==body_offset(bytes.fromhex(prefix['packet_hex'])) and owner['frame_fds']==1 for owner in owners),'partial frame credits mismatch'
  for owner in owners:owner['frame_bytes']=owner['frame_fds']=0
  P.assert_native(state,baseline['telemetry'],prefix['connections'])
 else:assert 'telemetry' not in sample,'invented reference scalar state'
def assert_mode(mode,warmed,backend):
 assert mode['mode'] in MODES
 opened,prefix,held,exercise,closed=[mode[k] for k in ('open','prefix','held','exercise','close')]
 P.assert_connections(opened);assert_prefix(prefix);assert_hold_health(held,prefix)
 assert opened['op']=='open' and opened['source']==opened['connections'][0] and opened['target']==opened['connections'][1]
 assert opened['connections']==prefix['connections']==exercise['connections'] and mode['mode']==prefix['mode']==exercise['mode']
 P.assert_actor_inventory(opened,mode['connected']['actor'])
 for phase in ('connected','retained','held_checked','checked','closed'):P.assert_attempts(mode[phase+'_attempts'],mode[phase])
 for phase in ('retained','held_checked'):assert_retained(mode[phase],prefix,mode['connected'],backend)
 P.assert_exercise(exercise)
 packet=bytes.fromhex(prefix['packet_hex']);suffix=packet[body_offset(packet):]
 assert exercise['suffix']==dict(bytes=len(suffix),wire_hex=suffix.hex(),sha256=hashlib.sha256(suffix).hexdigest(),rights=0)
 assert exercise['transfer']['sent']['wire_hex']==prefix['packet_hex'] and exercise['transfer']['source_fd']==prefix['source_fd'] and exercise['transfer']['writer_close']==prefix['writer_close']
 P.assert_actor_inventory(exercise,mode['checked']['actor']);resources=[exercise['transfer'][k] for k in ('source_fd','received_fd')]
 assert mode['checked']['actor']['fds']==sorted(mode['connected']['actor']['fds']+resources,key=lambda f:f['fd'])
 for resource in resources:assert not any((f['dev'],f['ino'])==(resource['dev'],resource['ino']) for f in mode['checked']['broker']['fds']),'broker retained after forwarding'
 # Exact extra held-health response is checked separately; accepted close oracle
 # validates every remaining setup/Resource/health frame without skipping any.
 actual=copy.deepcopy(closed);events=actual['events']['target'];setup=opened['target']['setup'];assert events[len(setup)]==held['health']['received'];del events[len(setup)]
 P.assert_closed(actual,exercise,warmed['actor_state']);P.assert_actor_inventory(closed,mode['closed']['actor'])
 for owner in ('actor','broker'):P.assert_recovered(warmed[owner],mode['closed'][owner])
 if backend=='gao':
  for phase in ('connected','checked'):P.assert_native(mode[phase]['telemetry'],warmed['telemetry'],opened['connections'])
  P.assert_native(mode['closed']['telemetry'],warmed['telemetry'])
 P.latency(mode['cleanup_elapsed_ms'],1000)
 expected=[{'op':'open'},{'op':'prefix','mode':mode['mode']},{'op':'retained'},{'op':'finish'},{'op':'close'}]
 assert [r['command'] for r in mode['operations']]==expected,'partial operation order'
 for op,key in zip(mode['operations'],('open','prefix','held','exercise','close')):
  assert op['response']==dict(ok=True,result=mode[key]);P.latency(op['elapsed_ms'],1000 if key=='close' else 10000)
 assert mode['retained_before_health'] is True and mode['held_checked_before_finish'] is True

def run_modes(args,report,c,actor,daemon,sample,save):
 c['modes']=[]
 for name in MODES:
  m=dict(mode=name,operations=[],phase_order=[]);c['modes'].append(m);save()
  def request(command,timeout=10):
   m['phase_order'].append(command['op'])
   row=dict(command=command,started_monotonic=time.monotonic());m['operations'].append(row);c['operations'].append(row);save()
   try:actor.begin(**command);response=actor.read(timeout=timeout);row['response']=response;assert response['ok'] is True,response;return response['result']
   finally:row['elapsed_ms']=(time.monotonic()-row['started_monotonic'])*1000;save()
  def observe(phase,accept,empty=False,limit=1000):
   m['phase_order'].append(phase+'-observed' if phase in ('retained','held_checked') else phase)
   m[phase+'_attempts']=[];m[phase]=P.bounded_poll(lambda:sample(empty),accept,limit,m[phase+'_attempts']);save()
  def valid(fn):
   def accept(row):
    try:fn(row);return True
    except AssertionError:return False
   return accept
  m['open']=request(dict(op='open'));P.assert_connections(m['open']);save()
  def connected(row):
   P.assert_actor_inventory(m['open'],row['actor'])
   if daemon:P.assert_native(row['telemetry'],c['warmed']['telemetry'],m['open']['connections'])
  observe('connected',valid(connected))
  m['prefix']=request(dict(op='prefix',mode=name));assert_prefix(m['prefix']);save()
  check=lambda row:assert_retained(row,m['prefix'],m['connected'],c['backend'])
  observe('retained',valid(check));m['retained_before_health']=True
  m['held']=request(dict(op='retained'));assert_hold_health(m['held'],m['prefix']);save()
  observe('held_checked',valid(check));m['held_checked_before_finish']=True
  m['exercise']=request(dict(op='finish'));P.assert_exercise(m['exercise']);save()
  def checked(row):
   P.assert_actor_inventory(m['exercise'],row['actor'])
   for k in ('source_fd','received_fd'):
    f=m['exercise']['transfer'][k];assert f in row['actor']['fds'];assert not any((d['dev'],d['ino'])==(f['dev'],f['ino']) for d in row['broker']['fds'])
   if daemon:P.assert_native(row['telemetry'],c['warmed']['telemetry'],m['open']['connections'])
  observe('checked',valid(checked))
  tick=time.monotonic();m['close']=request(dict(op='close'),1)
  def recovered(row):
   P.assert_actor_inventory(m['close'],row['actor'])
   for owner in ('actor','broker'):P.assert_recovered(c['warmed'][owner],row[owner])
   if daemon:P.assert_native(row['telemetry'],c['warmed']['telemetry'])
  remaining=1000-(time.monotonic()-tick)*1000;assert remaining>0
  observe('closed',valid(recovered),True,remaining);m['cleanup_elapsed_ms']=(time.monotonic()-tick)*1000
  assert_mode(m,{**c['warmed'],'actor_state':c['warmup']['fd_state']},c['backend']);save()

def lifecycle(source=REUSE/'qualify.py'):
 assert P.sha(source)==BASE_SHA,'accepted lifecycle source drift'
 tree=ast.parse(inspect.getsource(P.run_backend));function=tree.body[0];body=function.body
 guarded=next(node for node in body if isinstance(node,ast.Try));nodes=guarded.body
 start=next(i for i,n in enumerate(nodes) if ast.unparse(n).startswith("c['open'] = request"))
 end=next(i for i,n in enumerate(nodes[start:],start) if ast.unparse(n)=="c['status'] = 'passed'")
 assert end-start==20,'accepted active node range drift'
 original=ast.dump(ast.Module(body=nodes[start:end],type_ignores=[]),include_attributes=False)
 expected_hash=hashlib.sha256(original.encode()).hexdigest()
 assert expected_hash==ACTIVE_NODE_SHA,'accepted active node shape drift'
 nodes[start:end]=ast.parse('run_modes(args, report, c, actor, daemon, sample, save)').body
 namespace={**P.__dict__,'run_modes':run_modes};ast.fix_missing_locations(tree)
 exec(compile(tree,str(HERE/'qualify.py')+'::accepted-lifecycle-adapter','exec'),namespace)
 return namespace['run_backend']
ACTIVE_NODE_SHA='868f491b144cb58e1c78c38f394b086ac6782a98a348d1cd4a26c87947e3b44b'

def assert_report(report):
 assert (report['schema'],report['requirement'],report['subcase'],report['profile'],report['result'])==(1,'FD-02','partial-body','core',PASS)
 assert report['selection']==SELECTION and report['workload']==WORKLOAD and report['mode_observations']==4
 assert report['lifecycle_source_sha256']==BASE_SHA and report['active_node_sha256']==ACTIVE_NODE_SHA
 assert report['inputs_before']==report['inputs_after'] and set(report['reuse_inputs_before'])==set(REUSE_FILES) and report['reuse_inputs_before']==report['reuse_inputs_after']
 for name,row in report['reuse_inputs_before'].items():assert row==dict(path=str(REUSE/name),sha256=P.sha(REUSE/name)),'reused source provenance mismatch'
 for key,name in (('actor','actor.py'),('actor_test','actor_test.py'),('qualify','qualify.py'),('oracle_test','oracle_test.py'),('workload','workload.json'),('test_nix','test.nix'),('readme','README.md')):
  assert report['inputs_before'][key]==dict(path=str(HERE/name),sha256=P.sha(HERE/name)),'new fixture provenance mismatch'
 for key,digest in WORKLOAD['static_shared_sha256'].items():assert report['inputs_before'][key]['sha256']==digest,'shared input provenance mismatch'
 assert report['inputs_before']['scope']['sha256']==WORKLOAD['scope_sha256'],'scope provenance mismatch'
 broadcast=report['broadcast_actor'];path=Path(report['inputs_before']['transport_actor']['path']).parent/'broadcast_delivery_actor.py'
 assert broadcast==dict(path=str(path),sha256=WORKLOAD['broadcast_actor_sha256']) and P.sha(path)==broadcast['sha256'],'broadcast source provenance mismatch'
 facade=copy.deepcopy(report);facade.update(requirement='FD-01',subcase='pipe',result=P.PASS,selection=P.SELECTION,workload=P.WORKLOAD)
 for c in report['combinations']:
  assert [m['mode'] for m in c['modes']]==list(MODES)
  for m in c['modes']:
   assert_mode(m,{**c['warmed'],'actor_state':c['warmup']['fd_state']},c['backend'])
   for phase in ('connected','retained','held_checked','checked','closed'):
    for owner in ('actor','broker'):
     inv=m[phase][owner];P.assert_inventory(inv)
     assert inv['pid']==c[owner]['pid'] and inv['uids']==c[owner]['kernel_ids']['uids'] and inv['gids']==c[owner]['kernel_ids']['gids'],'mode observer owner identity'
   assert m['phase_order']==['open','connected','prefix','retained-observed','retained','held_checked-observed','finish','checked','close','closed']
  assert c['operations']==[c['operations'][0]]+[op for m in c['modes'] for op in m['operations']]
  assert c['operations'][0]['command']=={'op':'warmup'} and c['operations'][0]['response']==dict(ok=True,result=c['warmup'])
  f=next(f for f in facade['combinations'] if f['backend']==c['backend']);m=copy.deepcopy(c['modes'][-1])
  for key in ('open','exercise','close','connected','checked','closed','connected_attempts','checked_attempts','closed_attempts','cleanup_elapsed_ms'):f[key]=m[key]
  events=f['close']['events']['target'];del events[len(f['open']['target']['setup'])]
  f['operations']=[copy.deepcopy(c['operations'][0])]+[dict(command={'op':op},response=dict(ok=True,result=f[key]),elapsed_ms=entry['elapsed_ms']) for op,key,entry in (('open','open',m['operations'][0]),('exercise','exercise',m['operations'][3]),('close','close',m['operations'][4]))]
 # This private validation facade invokes every unchanged process/config/wire/
 # warmup/recovery/teardown invariant. It is never written as runtime evidence;
 # actual source commands/modes/transcripts above remain exact and independently checked.
 P.assert_report(facade)

def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope','reuse-fixtures'):parser.add_argument('--'+name,required=True,type=Path)
 args=parser.parse_args(argv)
 assert args.reuse_fixtures.resolve()==REUSE.resolve() and args.fixtures.resolve()==HERE
 assert os.geteuid()==0 and Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n'
 assert str(args.evidence)=='/run/osbus-fd-quotas' and args.reference_executable.is_absolute() and str(args.reference_executable).startswith('/nix/store/')
 assert not (args.evidence/'bus').exists() and not (args.evidence/'report.json').exists()
 stripped=sorted(k for k in os.environ if k.startswith('DBUS_'))
 for key in stripped:del os.environ[key]
 os.environ.update(PYTHONDONTWRITEBYTECODE='1',FD02_PIPE_FIXTURES=str(REUSE))
 assert P.sha(args.candidate/'candidate.json')==WORKLOAD['candidate_manifest_sha256']
 manifest=json.loads((args.candidate/'candidate.json').read_text());assert manifest['not_a_release'] and len(manifest['files'])==80 and len(manifest['sources'])==71
 inputs=P.capture_inputs(args,manifest);candidate=P.candidate_inventory(args.candidate,manifest)
 def reuse_inputs():return {name:dict(path=str(REUSE/name),sha256=P.sha(REUSE/name)) for name in REUSE_FILES}
 channels=load(args.helpers/'channel.py','fd02_readonly_channel');runner=lifecycle();args.evidence.mkdir(exist_ok=True)
 report=dict(broadcast_actor=dict(path=str(args.wire_dir/'broadcast_delivery_actor.py'),sha256=P.sha(args.wire_dir/'broadcast_delivery_actor.py')),schema=1,requirement='FD-02',subcase='partial-body',profile='core',result='running',not_a_release=True,workload=WORKLOAD,selection=SELECTION,
  manifest=manifest,inputs_before=inputs,reuse_inputs_before=reuse_inputs(),candidate_before=candidate,cwd=os.getcwd(),command=[sys.executable,'-B',str(HERE/'qualify.py'),*(argv or sys.argv[1:])],observer=P.process_identity(os.getpid()),stripped_dbus_keys=stripped,combinations=[],started_monotonic=time.monotonic(),lifecycle_source_sha256=BASE_SHA,active_node_sha256=ACTIVE_NODE_SHA,mode_observations=0)
 def save():
  report['counts']=P.counts(report['combinations']);report['mode_observations']=sum(len(c.get('modes',[])) for c in report['combinations'])
  (args.evidence/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 save()
 try:
  for backend in ('gao','reference'):
   if not runner(args,report,backend,channels,save):
    report['combinations'] += [dict(backend=b,status='blocked',reason='prior backend failure') for b in ('gao','reference')[len(report['combinations']):]]
    raise AssertionError('FD02 slice stopped on backend failure')
  report['result']=PASS
 except Exception as e:report.update(result='failed',error=repr(e))
 finally:
  try:report.update(inputs_after=P.capture_inputs(args,manifest),reuse_inputs_after=reuse_inputs(),candidate_after=P.candidate_inventory(args.candidate,manifest))
  except Exception as e:report.update(result='failed',hash_error=repr(e))
  report['elapsed_seconds']=time.monotonic()-report['started_monotonic'];save()
  try:assert_report(report)
  except Exception as e:report.update(result='failed',completion_error=repr(e))
  save()
 assert report['result']==PASS,report
 print(json.dumps(dict(result=PASS,counts=report['counts'],mode_observations=4,not_a_release=True)))
if __name__=='__main__':main()
