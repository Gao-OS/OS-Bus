"""One fresh FD02 boundary invocation; only a reserved disposable guest may run."""
import argparse,ast,copy,hashlib,importlib.util,inspect,json,os,stat,struct,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
REUSE=Path(os.environ.get('FD02_PIPE_FIXTURES',str(HERE.parent/'p08_fd01_singleton_resources')))
RUN_ROOT=Path('/run/osbus-fd02-all-boundaries')
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
P=load(REUSE/'qualify.py','fd02_all_readonly_pipe_controller');WORKLOAD=json.loads((HERE/'workload.json').read_text());MODES=tuple(WORKLOAD['arrival_modes'])
PASS='passed_independent_fd02_boundary_core';SELECTION=['FD-02/core/each-relevant-boundary/'+backend for backend in ('gao','reference')]
BASE_SHA='1e17175dd92c795702de4d5dd69f85e9f632340fb769672e17122d4227e736f6';ACTIVE_NODE_SHA='868f491b144cb58e1c78c38f394b086ac6782a98a348d1cd4a26c87947e3b44b'
REUSE_FILES=('actor.py','actor_test.py','qualify.py','oracle_test.py','workload.json','test.nix','README.md')
OWN_FILES=(('actor','actor.py'),('actor_test','actor_test.py'),('qualify','qualify.py'),('oracle_test','oracle_test.py'),('workload','workload.json'),('test_nix','test.nix'),('readme','README.md'))
def socket_path(boundary):
 assert type(boundary) is int and boundary>=1,'positive integer boundary required'
 return RUN_ROOT/('case-'+str(boundary))/'bus'
def geometry(packet):
 parsed=P.parse_frame(packet);body,serial,header=struct.unpack_from('<III',packet,4);end=16+header;start=end+(-header%8)
 assert packet[:4]==b'l\x04\x00\x01' and parsed['type']==4 and serial==100 and body==4 and parsed['body_hex']=='00000000' and len(packet)==start+body
 return dict(fixed_header_bytes=16,header_fields_bytes=header,header_end=end,alignment_bytes=start-end,body_start=start,body_bytes=body,frame_bytes=len(packet),boundaries=len(packet)-1)
def assert_prefix(row):
 packet=bytes.fromhex(row['packet_hex']);layout=geometry(packet);offset=row['offset'];assert type(offset) is int and 1<=offset<len(packet)
 assert row['op']=='prefix' and row['mode'] in MODES and row['geometry']==layout and row['suffix_sent'] is False and row['held'] is True
 P.assert_connections(row);names={connection['role']:connection['name'] for connection in row['connections']}
 assert P.parse_frame(packet)==dict(type=4,serial=100,flags=0,fields={'1':'/foundation','2':'org.foundation.Transport','3':'Resource','6':names['target'],'8':'h','9':1},body_hex='00000000')
 prefix=packet[:offset];assert row['prefix_hex']==prefix.hex() and row['prefix_sha256']==hashlib.sha256(prefix).hexdigest() and row['packet_sha256']==hashlib.sha256(packet).hexdigest() and row['suffix_bytes']==len(packet)-offset
 pieces=[(prefix,1)] if row['mode']==MODES[0] or offset==1 else [(prefix[:-1],0),(prefix[-1:],1)]
 assert row['sends']==[dict(bytes=len(raw),wire_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest(),rights=rights) for raw,rights in pieces],'exact nonempty ancillary positions required'
 source,writer=row['source_fd'],row['writer_close'];P.assert_fd(source,row);P.assert_fd(writer,row)
 assert P.stat.S_ISFIFO(source['mode']) and source['target']==f"pipe:[{source['ino']}]" and writer['role']=='writer' and writer['closed'] is True and row['written_bytes']==4 and writer['fd']!=source['fd']
 assert all(writer[key]==source[key] for key in ('dev','ino','mode','target')) and row['fd_state']['count']==len(row['fd_state']['fds']) and source in row['fd_state']['fds']
def assert_hold_health(row,prefix):
 assert row['op']=='retained' and row['mode']==prefix['mode'] and row['offset']==prefix['offset'] and row['suffix_sent'] is False
 assert all(row[key] is True for key in ('target_unreadable','source_unreadable','target_unreadable_before_probe','source_unreadable_before_probe'))
 assert all(row[key]==prefix[key] for key in ('pid','uid','gid')) and row['fd_state']==prefix['fd_state']
 health=row['health'];target=prefix['connections'][1];P.latency(health['latency_ms'],1000)
 assert (health['role'],health['serial'],health['reply_serial'],health['owner'],health['rights'])==('target',112,112,target['name'],0)
 sent=P.assert_wire(health['sent']);received=P.assert_wire(health['received'])
 assert sent==dict(type=1,serial=112,flags=0,fields={'1':'/org/freedesktop/DBus','2':P.BUS,'3':'GetNameOwner','6':P.BUS,'8':'s'},body_hex=P.string(target['name']).hex())
 fields=received['fields'];assert received['type']==2 and fields.get('5')==112 and fields.get('6')==target['name'] and fields.get('7')==P.BUS and fields.get('8')=='s' and fields.get('9',0)==0
 assert set(fields)<=set(('5','6','7','8','9')) and received['body_hex']==P.string(target['name']).hex()
 for direction in ('sent','received'):assert health[direction]['rights']==0 and health[direction]['role']=='target' and health[direction]['phase']=='active' and health[direction]['direction']==direction
 assert health['received']['fd_targets']==[] and row['active_events']==dict(source=[],target=[health['received']]),'premature delivery or source traffic'
def assert_retained(sample,prefix,baseline,backend):
 assert_prefix(prefix);P.assert_actor_inventory(prefix,sample['actor']);P.assert_inventory(sample['broker']);resource=prefix['source_fd']
 matches=[fd for fd in sample['broker']['fds'] if all(fd[key]==resource[key] for key in ('dev','ino','mode','target'))]
 assert len(matches)==1 and P.stat.S_ISFIFO(matches[0]['mode']),'actual matching broker FIFO absent or duplicated'
 assert sample['broker']['count']==baseline['broker']['count']+1 and [fd for fd in sample['broker']['fds'] if fd not in matches]==baseline['broker']['fds']
 if backend=='gao':
  state=copy.deepcopy(sample['telemetry']);source=prefix['connections'][0]['name'];peer,=[entry for entry in state['peers'] if entry['name']==source]
  assert peer['buffer_bytes']==prefix['offset'] and peer['queue']==0 and peer['output'] is None;peer['buffer_bytes']=0
  owners=(state['usage']['global'],state['usage']['uids']['1100'],state['usage']['peers'][peer['peer']])
  assert all(owner['frame_bytes']==prefix['offset'] and owner['frame_fds']==1 for owner in owners),'held frame credits mismatch'
  for owner in owners:owner['frame_bytes']=owner['frame_fds']=0
  P.assert_native(state,baseline['telemetry'],prefix['connections'])
 else:assert 'telemetry' not in sample,'invented reference scalar state'
def assert_mode(mode,warmed,backend,boundary):
 assert mode['mode'] in MODES and mode['boundary']==boundary
 opened,prefix,held,exercise,closed=[mode[key] for key in ('open','prefix','held','exercise','close')]
 P.assert_connections(opened);assert_prefix(prefix);assert_hold_health(held,prefix)
 assert opened['op']=='open' and opened['source']==opened['connections'][0] and opened['target']==opened['connections'][1]
 assert opened['connections']==prefix['connections']==exercise['connections'] and mode['mode']==prefix['mode']==exercise['mode'] and prefix['offset']==exercise['offset']==boundary
 P.assert_actor_inventory(opened,mode['connected']['actor'])
 for phase in ('connected','retained','held_checked','checked','closed'):P.assert_attempts(mode[phase+'_attempts'],mode[phase])
 for phase in ('retained','held_checked'):assert_retained(mode[phase],prefix,mode['connected'],backend)
 P.assert_exercise(exercise);packet=bytes.fromhex(prefix['packet_hex']);suffix=packet[boundary:]
 assert exercise['suffix']==dict(bytes=len(suffix),wire_hex=suffix.hex(),sha256=hashlib.sha256(suffix).hexdigest(),rights=0)
 assert exercise['transfer']['sent']['wire_hex']==prefix['packet_hex'] and exercise['transfer']['source_fd']==prefix['source_fd'] and exercise['transfer']['writer_close']==prefix['writer_close']
 P.assert_actor_inventory(exercise,mode['checked']['actor']);resources=[exercise['transfer'][key] for key in ('source_fd','received_fd')]
 assert mode['checked']['actor']['fds']==sorted(mode['connected']['actor']['fds']+resources,key=lambda fd:fd['fd'])
 for resource in resources:assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in mode['checked']['broker']['fds'])
 actual=copy.deepcopy(closed);events=actual['events']['target'];setup=opened['target']['setup'];assert events[len(setup)]==held['health']['received'];del events[len(setup)]
 P.assert_closed(actual,exercise,warmed['actor_state']);P.assert_actor_inventory(closed,mode['closed']['actor'])
 for owner in ('actor','broker'):P.assert_recovered(warmed[owner],mode['closed'][owner])
 if backend=='gao':
  for phase in ('connected','checked'):P.assert_native(mode[phase]['telemetry'],warmed['telemetry'],opened['connections'])
  P.assert_native(mode['closed']['telemetry'],warmed['telemetry'])
 P.latency(mode['cleanup_elapsed_ms'],1000)
 expected=[{'op':'open'},{'op':'prefix','mode':mode['mode'],'offset':boundary},{'op':'retained'},{'op':'finish'},{'op':'close'}]
 assert [operation['command'] for operation in mode['operations']]==expected
 for operation,key in zip(mode['operations'],('open','prefix','held','exercise','close')):assert operation['response']==dict(ok=True,result=mode[key]);P.latency(operation['elapsed_ms'],1000 if key=='close' else 10000)
 assert mode['retained_before_health'] is True and mode['held_checked_before_finish'] is True
def run_modes(args,report,combination,actor,daemon,sample,save):
 combination['modes']=[]
 for name in MODES:
  mode=dict(mode=name,boundary=args.boundary,operations=[],phase_order=[]);combination['modes'].append(mode);save()
  def request(command,timeout=10):
   mode['phase_order'].append(command['op']);operation=dict(command=command,started_monotonic=time.monotonic());mode['operations'].append(operation);combination['operations'].append(operation);save()
   try:actor.begin(**command);response=actor.read(timeout=timeout);operation['response']=response;assert response['ok'] is True,response;return response['result']
   finally:operation['elapsed_ms']=(time.monotonic()-operation['started_monotonic'])*1000;save()
  def observe(phase,accept,empty=False,limit=1000):
   mode['phase_order'].append(phase+'-observed' if phase in ('retained','held_checked') else phase);mode[phase+'_attempts']=[];mode[phase]=P.bounded_poll(lambda:sample(empty),accept,limit,mode[phase+'_attempts']);save()
  def valid(check):
   def accept(row):
    try:check(row);return True
    except AssertionError:return False
   return accept
  mode['open']=request(dict(op='open'));P.assert_connections(mode['open'])
  def connected(row):
   P.assert_actor_inventory(mode['open'],row['actor'])
   if daemon:P.assert_native(row['telemetry'],combination['warmed']['telemetry'],mode['open']['connections'])
  observe('connected',valid(connected));mode['prefix']=request(dict(op='prefix',mode=name,offset=args.boundary));assert_prefix(mode['prefix']);save()
  retained=lambda row:assert_retained(row,mode['prefix'],mode['connected'],combination['backend'])
  observe('retained',valid(retained));mode['retained_before_health']=True;mode['held']=request(dict(op='retained'));assert_hold_health(mode['held'],mode['prefix']);save()
  observe('held_checked',valid(retained));mode['held_checked_before_finish']=True;mode['exercise']=request(dict(op='finish'));P.assert_exercise(mode['exercise']);save()
  def checked(row):
   P.assert_actor_inventory(mode['exercise'],row['actor'])
   for key in ('source_fd','received_fd'):
    resource=mode['exercise']['transfer'][key];assert resource in row['actor']['fds'];assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in row['broker']['fds'])
   if daemon:P.assert_native(row['telemetry'],combination['warmed']['telemetry'],mode['open']['connections'])
  observe('checked',valid(checked));tick=time.monotonic();mode['close']=request(dict(op='close'),1)
  def recovered(row):
   P.assert_actor_inventory(mode['close'],row['actor'])
   for owner in ('actor','broker'):P.assert_recovered(combination['warmed'][owner],row[owner])
   if daemon:P.assert_native(row['telemetry'],combination['warmed']['telemetry'])
  remaining=1000-(time.monotonic()-tick)*1000;assert remaining>0;observe('closed',valid(recovered),True,remaining);mode['cleanup_elapsed_ms']=(time.monotonic()-tick)*1000
  assert_mode(mode,{**combination['warmed'],'actor_state':combination['warmup']['fd_state']},combination['backend'],args.boundary);save()
def private_workload(boundary):return {**P.WORKLOAD,'socket':str(socket_path(boundary))}
def private_namespace(boundary):
 namespace={**P.__dict__,'run_modes':run_modes,'WORKLOAD':private_workload(boundary)}
 namespace['native_config']=types.FunctionType(P.native_config.__code__,namespace)
 def reference_config(path):
  assert path==str(socket_path(boundary)),'wrong private case socket'
  # Keep the accepted XML generator and every policy/limit byte unchanged;
  # replace only its one literal private listen address after its own guard.
  original=P.reference_config(P.WORKLOAD['socket']);needle='unix:path='+P.WORKLOAD['socket']
  assert original.count(needle)==1
  return original.replace(needle,'unix:path='+path)
 namespace['reference_config']=reference_config
 return namespace
def lifecycle(boundary,source=REUSE/'qualify.py'):
 assert P.sha(source)==BASE_SHA,'accepted lifecycle source drift'
 tree=ast.parse(inspect.getsource(P.run_backend));guarded=next(node for node in tree.body[0].body if isinstance(node,ast.Try));nodes=guarded.body
 start=next(index for index,node in enumerate(nodes) if ast.unparse(node).startswith("c['open'] = request"));end=next(index for index,node in enumerate(nodes[start:],start) if ast.unparse(node)=="c['status'] = 'passed'")
 assert end-start==20 and hashlib.sha256(ast.dump(ast.Module(body=nodes[start:end],type_ignores=[]),include_attributes=False).encode()).hexdigest()==ACTIVE_NODE_SHA
 nodes[start:end]=ast.parse('run_modes(args, report, c, actor, daemon, sample, save)').body
 namespace=private_namespace(boundary);ast.fix_missing_locations(tree);exec(compile(tree,str(HERE/'qualify.py')+'::unchanged-private-lifecycle','exec'),namespace)
 return namespace['run_backend']
def verify_preflight(report):
 frozen=report['freeze'];assert frozen['schema']==1 and frozen['scope']=='FD02/all-boundaries/core' and frozen['candidate_manifest_sha256']==WORKLOAD['candidate_manifest_sha256']
 actual={**report['inputs_before'],**{key:value for key,value in report['extra_inputs_before'].items() if key!='freeze'}}
 assert set(report['inputs_before'])==P.INPUT_KEYS and set(report['extra_inputs_before'])=={'batch','plan','freeze'}
 assert set(frozen['guest_inputs'])==set(actual) and set(report['input_modes_before'])==set(actual)
 for key,row in actual.items():
  expected=frozen['guest_inputs'][key];assert set(expected)=={'sha256','mode'} and type(expected['mode']) is int and expected==dict(sha256=row['sha256'],mode=report['input_modes_before'][key])
  assert P.sha(row['path'])==row['sha256'] and stat.S_IMODE(Path(row['path']).stat().st_mode)==expected['mode']
 assert set(report['reuse_inputs_before'])==set(REUSE_FILES) and set(frozen['reused_inputs'])==set(REUSE_FILES)
 for name,row in report['reuse_inputs_before'].items():assert row==dict(path=str(REUSE/name),sha256=P.sha(REUSE/name),mode=stat.S_IMODE((REUSE/name).stat().st_mode)) and frozen['reused_inputs'][name]=={key:row[key] for key in ('sha256','mode')}
 assert frozen['broadcast_actor_sha256']==report['broadcast_actor']['sha256']==P.sha(report['broadcast_actor']['path'])
 for key,name in OWN_FILES:assert report['inputs_before'][key]['path']==str(HERE/name)
 for key in ('batch','plan'):assert report['extra_inputs_before'][key]['path']==str(HERE/(key+'.py'))
 assert P.sha(report['extra_inputs_before']['freeze']['path'])==report['extra_inputs_before']['freeze']['sha256'] and json.loads(Path(report['extra_inputs_before']['freeze']['path']).read_text())==frozen
 for key,digest in WORKLOAD['static_shared_sha256'].items():assert report['inputs_before'][key]['sha256']==digest
 assert report['broadcast_actor']['sha256']==WORKLOAD['broadcast_actor_sha256']
 assert report['inputs_before']['candidate_manifest']['sha256']==WORKLOAD['candidate_manifest_sha256']
 assert report['candidate_before']==report['manifest']['files'],'candidate inventory differs before launch'
def verify_freeze(report):
 assert report['inputs_before']==report['inputs_after'] and report['extra_inputs_before']==report['extra_inputs_after'] and report['input_modes_before']==report['input_modes_after']
 assert report['reuse_inputs_before']==report['reuse_inputs_after']
 verify_preflight(report)
def assert_report(report):
 assert (report['schema'],report['requirement'],report['subcase'],report['profile'],report['result'])==(1,'FD-02','each-relevant-boundary','core',PASS)
 boundary=report['boundary'];socket=socket_path(boundary);assert report['selection']==SELECTION and report['workload']==WORKLOAD and report['mode_observations']==4 and report['socket']==str(socket)
 assert report['preflight_verified'] is True,'freeze must pass before backend launch'
 assert report['lifecycle_source_sha256']==BASE_SHA and report['active_node_sha256']==ACTIVE_NODE_SHA;verify_freeze(report)
 layouts=[];facade=copy.deepcopy(report);workload=private_workload(boundary);facade.update(requirement='FD-01',subcase='pipe',result=P.PASS,selection=P.SELECTION,workload=workload)
 for combination in report['combinations']:
  assert [mode['mode'] for mode in combination['modes']]==list(MODES)
  for mode in combination['modes']:
   assert_mode(mode,{**combination['warmed'],'actor_state':combination['warmup']['fd_state']},combination['backend'],boundary);layouts.append(mode['prefix']['geometry'])
   for phase in ('connected','retained','held_checked','checked','closed'):
    for owner in ('actor','broker'):
     inventory=mode[phase][owner];P.assert_inventory(inventory);assert inventory['pid']==combination[owner]['pid'] and inventory['uids']==combination[owner]['kernel_ids']['uids'] and inventory['gids']==combination[owner]['kernel_ids']['gids']
   assert mode['phase_order']==['open','connected','prefix','retained-observed','retained','held_checked-observed','finish','checked','close','closed']
  assert combination['operations']==[combination['operations'][0]]+[operation for mode in combination['modes'] for operation in mode['operations']]
  assert combination['operations'][0]['command']=={'op':'warmup'} and combination['operations'][0]['response']==dict(ok=True,result=combination['warmup'])
  selected=next(value for value in facade['combinations'] if value['backend']==combination['backend']);mode=copy.deepcopy(combination['modes'][-1])
  for key in ('open','exercise','close','connected','checked','closed','connected_attempts','checked_attempts','closed_attempts','cleanup_elapsed_ms'):selected[key]=mode[key]
  del selected['close']['events']['target'][len(selected['open']['target']['setup'])]
  selected['operations']=[copy.deepcopy(combination['operations'][0])]+[dict(command={'op':op},response=dict(ok=True,result=selected[key]),elapsed_ms=entry['elapsed_ms']) for op,key,entry in (('open','open',mode['operations'][0]),('exercise','exercise',mode['operations'][3]),('close','close',mode['operations'][4]))]
 assert len(layouts)==4 and all(layout==layouts[0] for layout in layouts) and report['geometry']==layouts[0] and 1<=boundary<=layouts[0]['boundaries']
 # Exact unchanged full oracle code; only the trusted private socket expectation
 # differs. Policies, profile, actors, wire, recovery and teardown remain intact.
 oracle=types.FunctionType(P.assert_report.__code__,private_namespace(boundary),P.assert_report.__name__,P.assert_report.__defaults__,P.assert_report.__closure__)
 oracle(facade)
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope','reuse-fixtures','freeze'):parser.add_argument('--'+name,required=True,type=Path)
 parser.add_argument('--boundary',required=True,type=int);args=parser.parse_args(argv)
 assert args.reuse_fixtures.resolve()==REUSE.resolve() and args.fixtures.resolve()==HERE and args.evidence==socket_path(args.boundary).parent
 assert os.geteuid()==0 and Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n' and str(args.reference_executable).startswith('/nix/store/')
 assert not (args.evidence/'bus').exists() and not (args.evidence/'report.json').exists()
 stripped=sorted(key for key in os.environ if key.startswith('DBUS_'))
 for key in stripped:del os.environ[key]
 os.environ.update(PYTHONDONTWRITEBYTECODE='1',FD02_PIPE_FIXTURES=str(REUSE));assert P.sha(args.candidate/'candidate.json')==WORKLOAD['candidate_manifest_sha256']
 manifest=json.loads((args.candidate/'candidate.json').read_text());assert manifest['not_a_release'] and len(manifest['files'])==80 and len(manifest['sources'])==71
 def extras():return {key:dict(path=str(path),sha256=P.sha(path)) for key,path in (('batch',HERE/'batch.py'),('plan',HERE/'plan.py'),('freeze',args.freeze))}
 def reused():return {name:dict(path=str(REUSE/name),sha256=P.sha(REUSE/name),mode=stat.S_IMODE((REUSE/name).stat().st_mode)) for name in REUSE_FILES}
 def modes(inputs,additional):return {key:stat.S_IMODE(Path(row['path']).stat().st_mode) for key,row in {**inputs,**{key:value for key,value in additional.items() if key!='freeze'}}.items()}
 inputs=P.capture_inputs(args,manifest);additional=extras();channels=load(args.helpers/'channel.py','fd02_all_readonly_channel');runner=lifecycle(args.boundary);args.evidence.mkdir(exist_ok=True)
 report=dict(schema=1,requirement='FD-02',subcase='each-relevant-boundary',profile='core',result='running',not_a_release=True,workload=WORKLOAD,selection=SELECTION,boundary=args.boundary,socket=str(socket_path(args.boundary)),geometry=None,broadcast_actor=dict(path=str(args.wire_dir/'broadcast_delivery_actor.py'),sha256=P.sha(args.wire_dir/'broadcast_delivery_actor.py')),freeze=json.loads(args.freeze.read_text()),manifest=manifest,inputs_before=inputs,extra_inputs_before=additional,input_modes_before=modes(inputs,additional),reuse_inputs_before=reused(),candidate_before=P.candidate_inventory(args.candidate,manifest),cwd=os.getcwd(),command=[sys.executable,'-B',str(HERE/'qualify.py'),*(argv or sys.argv[1:])],observer=P.process_identity(os.getpid()),stripped_dbus_keys=stripped,combinations=[],started_monotonic=time.monotonic(),lifecycle_source_sha256=BASE_SHA,active_node_sha256=ACTIVE_NODE_SHA,mode_observations=0)
 def save():
  report['counts']=P.counts(report['combinations']);report['mode_observations']=sum(len(combination.get('modes',[])) for combination in report['combinations'])
  layouts=[mode['prefix']['geometry'] for combination in report['combinations'] for mode in combination.get('modes',[]) if 'prefix' in mode]
  report['geometry']=layouts[0] if layouts else None;(args.evidence/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 save()
 try:
  verify_preflight(report);report['preflight_verified']=True;save()
  for backend in ('gao','reference'):
   if not runner(args,report,backend,channels,save):
    report['combinations'] += [dict(backend=value,status='blocked',reason='prior backend failure') for value in ('gao','reference')[len(report['combinations']):]];raise AssertionError('boundary invocation stopped on backend failure')
  report['result']=PASS
 except Exception as error:report.update(result='failed',error=repr(error))
 finally:
  try:
   after=P.capture_inputs(args,manifest);extra_after=extras();report.update(inputs_after=after,extra_inputs_after=extra_after,input_modes_after=modes(after,extra_after),reuse_inputs_after=reused(),candidate_after=P.candidate_inventory(args.candidate,manifest))
  except Exception as error:report.update(result='failed',hash_error=repr(error))
  report['elapsed_seconds']=time.monotonic()-report['started_monotonic'];save()
  try:assert_report(report)
  except Exception as error:report.update(result='failed',completion_error=repr(error))
  save()
 assert report['result']==PASS,report;print(json.dumps(dict(result=PASS,boundary=args.boundary,counts=report['counts'],mode_observations=4,geometry=report['geometry'],not_a_release=True)))
if __name__=='__main__':main()
