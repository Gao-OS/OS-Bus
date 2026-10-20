"""Independent FD07 missing-destination controller; runtime isolated guest only."""
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def argument(name,default): return Path(sys.argv[sys.argv.index(name)+1]) if name in sys.argv else default
FD05=argument('--fd05',HERE.parent/'p08_fd_nonnegotiation')
SHARED=argument('--shared',HERE.parent/'p08_fd01_singleton_resources')
MIXED=argument('--mixed',HERE.parent/'p08_fd03_mixed_bundles')
BUNDLES=argument('--bundles',HERE.parent/'p08_fd03_different_bundles')
WIRE=argument('--wire-dir',ROOT/'apps/gao_bus/test/fixtures')
PINS={FD05/'qualify.py':'29b8f48876135dbe60af163cb1a1bd0b7ca560c1b1a9ae11e204b7d1debc7ca3',
    FD05/'actor.py':'69d001f20e17637d98d0f9bd90b454486c12158dad57faab21067958195e6ab1',
    SHARED/'qualify.py':'1e17175dd92c795702de4d5dd69f85e9f632340fb769672e17122d4227e736f6',
    MIXED/'qualify.py':'6d7da41dfa770256a4cb23ea6fb600bf2debb893f68c3a6c3db5832df04e1fa1',
    BUNDLES/'qualify.py':'6c9c572e731dd44c66543c473b5c994fd48e11338dc0d5501304e06cfb86288a',
    WIRE/'transport_actor.py':'c799bc12a074addb40b2bbad8a4c6a7da1f2ad8dd54e126d480318e0c249d726',
    WIRE/'broadcast_delivery_actor.py':'1cf84c6634fbd3fef1fd0306829fdbd6b8e548c2e9b018d135cbaefbfef1d982'}
for path,digest in PINS.items(): assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,('predecessor drift',str(path))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
N=load('fd07_memfd_lifecycle',FD05/'qualify.py');S=load('fd07_numeric_lifecycle',SHARED/'qualify.py')
M=load('fd07_precontainment_authority',MIXED/'qualify.py')
WORKLOAD=json.loads((HERE/'workload.json').read_text());BUS=S.BUS;ERROR=WORKLOAD['missing']['error'];CONTENTS=WORKLOAD['missing']['contents'].encode()
PASS='passed_independent_fd07_missing_destination_core';SELECTION=['FD-07/core/missing-destination/gao','FD-07/core/missing-destination/reference']
expected=copy.deepcopy(N.WORKLOAD);expected.pop('unicast')
expected.update(requirement='FD-07',subcase='missing-destination',cases=['missing-destination'],authority_seconds=60,
    candidate_manifest_sha256='a27888106012b209b8941a4c7e5b9611764c7ceaa3ff2e27ebe9c753783a6c77',missing=dict(serial=100,flags=2,destination='org.foundation.Absent',path='/broadcast',interface='org.foundation.Broadcast',member='Resource',signature='h',index=0,rights=1,
    contents='OS-BUS-BROADCAST-MEMFD',resource_name_prefix='foundation-broadcast-',error='org.freedesktop.DBus.Error.ServiceUnknown',error_header9='absent',returned_rights=0,delivered_rights=0,healthy_serials=[110,111,112,210,211,212]))
assert WORKLOAD==expected,'FD07 workload/cap/deadline drift'
FILES={'actor':'actor.py','actor_test':'actor_test.py','qualify':'qualify.py','oracle_test':'oracle_test.py','workload':'workload.json','test_nix':'test.nix','readme':'README.md'}
PINNED_FILES={prefix+'_'+role:root/file for prefix,root in [('fd05',FD05),('shared',SHARED),('mixed',MIXED),('bundles',BUNDLES)] for role,file in FILES.items()}
SHAPES={};TREE=ast.parse((FD05/'qualify.py').read_text())
NS=dict(vars(N));NS.update(HERE=HERE,WORKLOAD=WORKLOAD)
def function(name,tree=TREE):
    found=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name];assert len(found)==1;return copy.deepcopy(found[0])
def replace(fn,old,new):
    return M.Q.replace_statement(fn,old,new)
def compile_function(name,fn,namespace=NS,tree=TREE):
    SHAPES[name]=dict(original_ast_sha256=hashlib.sha256(ast.dump(function(name,tree),include_attributes=False).encode()).hexdigest(),
        executed_ast_sha256=hashlib.sha256(ast.dump(fn,include_attributes=False).encode()).hexdigest())
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),str(HERE/'qualify.py'),'exec'),namespace);return namespace[fn.name]

# Strict raw parser: retain all singleton extent/padding/header checks, allowing
# only the additionally required NO_AUTO_START flag and existing third role.
f=function('parse_frame',ast.parse((SHARED/'qualify.py').read_text()))
f=replace(f,"assert raw[1] in (1,2,3,4) and raw[2] in (0,1), 'unexpected frame type/flags'","assert raw[1] in (1,2,3,4) and raw[2] in (0,1,2), 'unexpected frame type/flags'")
wire_ns=dict(vars(S));parse_frame=compile_function('parse_frame',f,wire_ns,ast.parse((SHARED/'qualify.py').read_text()))
def assert_wire(row):
    parsed=N.assert_wire(row);strict=parse_frame(bytes.fromhex(row['wire_hex']))
    assert all(parsed[key]==strict[key] for key in ('type','serial','fields','body_hex'))
    assert row.get('phase','active') in ('setup','active')
    assert row['direction'] in ('sent','received')
    return {**parsed,'flags':strict['flags']}

def assert_missing_sent(row):
    frame=assert_wire(row)
    assert frame==dict(type=1,serial=100,fields={'1':'/broadcast','2':'org.foundation.Broadcast','3':'Resource','6':'org.foundation.Absent','8':'h','9':1},body_hex='00000000',role='source',rights=1,flags=2)
    S.integer(row['sendmsg_bytes'],1);assert row['sendmsg_bytes']<=row['wire_bytes'] and row['completed_bytes']==row['wire_bytes']
    S.assert_fd(row['right_fd'])
    return frame

def assert_resource(row,owner,role):
    S.assert_fd(row,{k:owner[k] for k in ('pid','uid','gid')})
    pid=owner['pid']
    assert S.stat.S_ISREG(row['mode']) and row['target']==f'/memfd:foundation-broadcast-{pid} (deleted)'
    assert row['role']==role and row['size']==len(CONTENTS) and row['closed'] is row['ebadf'] is row['eof'] is True
    assert row['contents_hex']==CONTENTS.hex() and row['contents_sha256']==hashlib.sha256(CONTENTS).hexdigest()
    assert row['read_chunks_hex']==[CONTENTS.hex(),'']

def assert_exercise(row):
    assert row['case']=='missing-destination';names=N.assert_connections(row)
    assert len(row['sent'])==len(row['received'])==7 and row['barriers']==[]
    assert all(event['direction']==direction for direction in ('sent','received') for event in row[direction])
    sent=[assert_wire(event) for event in row['sent']];received=[assert_wire(event) for event in row['received']]
    assert_missing_sent(row['sent'][0]);assert row['error_name']==ERROR and row['error_reply_serial']==100
    error=received[0];fields=error['fields']
    assert error['role']=='source' and error['type']==3 and error['rights']==0 and error['flags'] in (0,1)
    assert fields=={'4':ERROR,'5':100,'6':names['source'],'7':BUS,'8':'s'}
    assert row['received'][0]['fd_targets']==[]
    roles=['source','target','ordinary']
    pairs=[(role,base+i) for base in (110,210) for i,role in enumerate(roles)]
    assert [(h['role'],h['serial']) for h in row['health']]==pairs
    for index,(role,serial) in enumerate(pairs,1):
        N.latency(row['health'][index-1]['latency_ms'],1000)
        call=sent[index];reply=received[index]
        assert call==dict(type=1,serial=serial,fields={'1':'/org/freedesktop/DBus','2':BUS,'3':'GetNameOwner','6':BUS,'8':'s'},body_hex=S.string(names[role]).hex(),role=role,rights=0,flags=0)
        N.assert_reply(reply,role,names[role],serial,S.string(names[role]))
        assert set(reply['fields'])<=set(('5','6','7','8','9')) and reply['flags'] in (0,1)
        assert row['received'][index]['fd_targets']==[]
    assert row['assertions']==dict(strict_first_message=True,actor_fd_growth=0,resource_deliveries=0,rights0_deliveries=0,healthy_replies=6,returned_rights=0,delivered_rights=0)
    assert len(row['resources'])==1
    resource=row['resources'][0];assert_resource(resource,row,'source')
    assert row['sent'][0]['right_fd']=={k:resource[k] for k in S.FD_KEYS}
    assert row['closure']==[{**{k:resource[k] for k in S.FD_KEYS},'role':'source','closed':True}]

def assert_warmup(row):
    N.assert_warmup(row)
    assert all(event['direction']==direction for direction in ('sent','received') for event in row[direction])
    for role,r in zip(('source','target'),row['resources']): assert_resource(r,row,role)
    for event in row['sent']+row['received']: assert assert_wire(event)['flags'] in ((0,) if event in row['sent'] else (0,1))
    original=[r for r in row['sent'] if r.get('phase')!='setup'][0]
    S.integer(original['sendmsg_bytes'],1)
    assert original['sendmsg_bytes']<=original['wire_bytes'] and original['completed_bytes']==original['wire_bytes']
    assert original['right_fd']=={k:row['resources'][0][k] for k in S.FD_KEYS}
    owned=[({k:r[k] for k in S.FD_KEYS},r['role']) for r in row['resources']]
    owned += [(c['socket'],c['role']) for c in row['warmup_connections']]
    assert row['closure']==[{**fd,'role':role,'closed':True} for fd,role in owned]
    active=[r for r in row['received'] if r.get('phase')!='setup'];assert len(active)==3
    assert len(active[0]['fd_targets'])==1
    assert all(active[0]['fd_targets'][0][k]==row['resources'][1][k] for k in ('fd','target','dev','ino','mode','size'))

def external(pid):
    numeric=S.external(pid)
    targets=sorted(fd['target'] for fd in numeric['fds'])
    return dict(pid=numeric['pid'],uids=numeric['uids'],gids=numeric['gids'],fds=numeric['count'],targets=targets,memfds=sorted(t for t in targets if '/memfd:' in t),numeric=numeric)

def assert_inventory(row):
    N.assert_inventory(row);S.assert_inventory(row['numeric'])
    assert row['numeric']['pid']==row['pid'] and row['numeric']['uids']==row['uids'] and row['numeric']['gids']==row['gids']
    assert row['fds']==row['numeric']['count'] and row['targets']==sorted(r['target'] for r in row['numeric']['fds'])
def assert_recovered(before,after):
    N.assert_recovered(before,after);assert_inventory(before);assert_inventory(after);S.assert_recovered(before['numeric'],after['numeric'])
def assert_actor_inventory(receipt,observed):
    N.assert_actor_inventory(receipt,observed)
    S.assert_actor_inventory(receipt,observed['numeric'])

native_tree=ast.parse((SHARED/'qualify.py').read_text());native_ns=dict(vars(S))
f=function('assert_native',native_tree)
f=replace(f,"assert p['credentials']=={k:c[k] for k in ('pid','uid','gid')} and p['negotiated'] is True","assert p['credentials']=={k:c[k] for k in ('pid','uid','gid')} and p['negotiated'] is c['negotiated']")
strong_native=compile_function('assert_native',f,native_ns,native_tree)
def assert_native(state,baseline,connections=(),matches=0):
    N.assert_native(state,baseline,connections,matches);assert matches==0;strong_native(state,baseline,connections)

def capture_inputs(args,manifest):
    result=N.capture_inputs(args,manifest)
    for key,path in PINNED_FILES.items(): result[key]=dict(path=str(path),sha256=S.sha(path))
    for path,digest in PINS.items(): assert S.sha(path)==digest
    return result

NS.update(assert_exercise=assert_exercise,assert_warmup=assert_warmup,external=external,assert_inventory=assert_inventory,
    assert_actor_inventory=assert_actor_inventory,assert_recovered=assert_recovered,assert_native=assert_native,capture_inputs=capture_inputs)
f=function('assert_report')
f=replace(f,"assert report['schema']==1 and report['requirement']=='FD-05' and report['profile']=='core'","assert report['schema']==1 and report['requirement']=='FD-07' and report['profile']=='core' and report['subcase']=='missing-destination'")
f=replace(f,"assert report['workload']==WORKLOAD and report['selection']==['FD-05/core/gao','FD-05/core/reference']","assert report['workload']==WORKLOAD and report['selection']==SELECTION")
f=replace(f,"assert report['result']=='passed_independent_fd05_core'","assert report['result']==PASS")
NS.update(SELECTION=SELECTION,PASS=PASS)
base_report=compile_function('assert_report',f)
def assert_report(report):
    base_report(report);M.assert_authority(report)
    assert report['adapter_provenance']==ADAPTER_PROVENANCE
    required={'actor','actor_test','qualify','oracle_test','workload','test_nix','readme','scope','channel','transport_actor','broadcast_actor','quota_daemon','collector','candidate_manifest','python','elixir','erl','beam','reference_executable','runuser'}|set(PINNED_FILES)
    assert set(report['inputs_before'])==required
    for key,path in PINNED_FILES.items(): assert report['inputs_before'][key]['sha256']==S.sha(path)
    for c in report['combinations']:
        assert_no_probe_errors(c)
        for owner in ('actor','broker','launcher'): S.assert_process(c[owner])
        assert c['launcher']['uid']==c['broker']['uid']==0
        for phase in ('before','warmed'):
            for owner in ('actor','broker'): assert_inventory(c[phase][owner])
        assert_recovered(c['before']['actor'],c['warmed']['actor'])
        assert_actor_inventory(c['warmup'],c['warmed']['actor'])
        for case in c['cases']:
            for receipt,phase in [('open','connected'),('exercise','checked'),('close','closed')]: assert_actor_inventory(case[receipt],case[phase]['actor'])
            for phase in ('connected','checked','closed'):
                for owner in ('actor','broker'): assert_inventory(case[phase][owner])
            assert_recovered(case['connected']['actor'],case['checked']['actor'])
            resource=case['exercise']['resources'][0]
            for phase in ('connected','checked','closed'):
                for owner in ('actor','broker'):
                    assert not any(fd['target']==resource['target'] for fd in case[phase][owner]['numeric']['fds'])
            sockets=[(c['socket'],c['role']) for c in case['open']['connections']]
            assert case['close']['closure']==[{**fd,'role':role,'closed':True} for fd,role in sockets]
        stop=c['teardown'];N.latency(stop['elapsed_ms'],1000)
        assert_clean_containment(stop)
        for owner in ('actor','backend'):
            if owner=='actor' or c['backend']=='gao':
                assert stop[owner]['fallback_actions']==[] and stop[owner]['cleanup_errors']==[] and stop[owner]['drain_complete'] is True
        M.assert_retired(stop['actor']['before_containment'],c['launcher']['pid'],c['actor']['pid'])
        M.assert_retired(stop['backend']['before_containment'],c['broker']['pid'],c['broker']['pid'],(0,) if c['backend']=='gao' else (0,-15))
        assert stop['broker_absent'] is stop['launcher_absent'] is True
        assert stop['actor_eof']['ok'] is True and stop['actor_eof']['result']['baseline_equal'] is True and stop['actor_eof']['result']['fd_growth']==0
        if c['backend']=='reference':
            assert c['reference_config']==c['reference_config_exported']==N.reference_config(WORKLOAD['socket'])
            assert c['reference_config_sha256']==hashlib.sha256(c['reference_config_exported'].encode()).hexdigest()
NS['assert_report']=assert_report

def assert_clean_containment(stop):
    assert stop.get('fallback_group_signals',[])==[]
    assert stop['containment_attempts']
    for attempt in stop['containment_attempts']:
        assert attempt['success'] is True and 'error' not in attempt
        assert not any(attempt['sample'].values()),'fallback group containment cannot qualify graceful teardown'

def assert_no_probe_errors(combination):
    attempts=list(combination['startup_attempts'])
    for case in combination['cases']:
        for phase in ('connected_attempts','checked_attempts','cleanup_attempts'): attempts+=case[phase]
    assert all('error' not in attempt for attempt in attempts),'observer probe error cannot qualify recovery'

def reference_stop(process,log,deadline):
    errors=[];timed_out=False;waited=False
    try:
        process.send_signal(signal.SIGTERM)
        remaining=deadline-time.monotonic();assert remaining>0
        process.wait(timeout=remaining);waited=True
    except subprocess.TimeoutExpired: timed_out=True
    except Exception as error: errors.append(repr(error))
    before=M.probe_retired(process.pid,process.pid,waited,process.returncode,timed_out,errors)
    log.close()
    return dict(pid=process.pid,method='sigterm',returncode=process.returncode,before_containment=before)
def assert_owned_group(group,members,identities):
    proofs=[]
    for expected in identities:
        if expected and expected['pid'] in members:
            observed=N.process_identity(expected['pid'])
            keys=('pid','uid','gid','starttime_ticks','pgid')
            assert {k:observed[k] for k in keys}=={k:expected[k] for k in keys},'owned process identity drift'
            assert observed['pgid']==group
            proofs.append({k:observed[k] for k in keys})
    assert proofs,'cannot contain a group without a live original process identity'
    return proofs

def stop_channel(channel,actual_pid,deadline,identities):
    # The frozen channel's fallback has two3s waits. Keep its EOF, group
    # containment and log preservation contract under this one1000ms deadline.
    waited=False;timed_out=False;errors=[];fallback=[];drain_complete=False
    try:
        channel.process.stdin.close()
        remaining=deadline-time.monotonic();assert remaining>0,'pre-containment teardown deadline'
        try: channel.process.wait(timeout=remaining);waited=True
        except subprocess.TimeoutExpired: timed_out=True
    except Exception as error: errors.append(repr(error))
    before=M.probe_retired(channel.process.pid,actual_pid,waited,channel.process.returncode,timed_out,errors)
    try:
        members=S.group_members(channel.process.pid)
        if members:
            proofs=assert_owned_group(channel.process.pid,members,identities)
            fallback.append(dict(signal='SIGKILL',group=channel.process.pid,members=members,identity_proofs=proofs))
            try: os.killpg(channel.process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        if not waited:
            channel.process.wait(timeout=max(0,deadline-time.monotonic()))
    except Exception as error: errors.append(repr(error))
    tail=channel.buffer
    try:
        os.set_blocking(channel.process.stdout.fileno(),False)
        while True:
            assert time.monotonic()<=deadline,'log drain teardown deadline'
            try: piece=os.read(channel.process.stdout.fileno(),65536)
            except BlockingIOError: break
            if not piece: drain_complete=True;break
            tail+=piece
            assert len(tail)<=4_194_304,'fixture teardown output too large'
    except Exception as error: errors.append(repr(error))
    finally:
        try:
            if tail:
                with channel.log.open('ab') as output: output.write(tail)
        except Exception as error: errors.append(repr(error))
        try: channel.process.stdout.close()
        except Exception as error: errors.append(repr(error))
    return dict(command=channel.command,pid=channel.process.pid,returncode=channel.process.returncode,
        method='eof' if waited and not fallback else 'kill',before_containment=before,
        fallback_actions=fallback,cleanup_errors=errors,drain_complete=drain_complete,drained_bytes=len(tail))
def contain_owned(group,members,combination):
    identities=[combination.get(owner) for owner in ('actor','launcher','broker')]
    proofs=assert_owned_group(group,members,identities)
    combination['teardown'].setdefault('fallback_group_signals',[]).append(dict(group=group,members=members,identity_proofs=proofs,signal='SIGKILL'))
    try: os.killpg(group,signal.SIGKILL)
    except ProcessLookupError: pass
NS.update(reference_stop=reference_stop,stop_channel=stop_channel,contain_owned=contain_owned)
BACKEND_STOP_BEFORE="if daemon: teardown['backend']=daemon.stop(grace=5)\nelif reference: teardown['backend']=reference_stop(reference,reference_log)"
BACKEND_STOP_AFTER="if daemon: teardown['backend']=stop_channel(daemon,broker_pid,teardown_started+1,[c.get('broker')])\nelif reference: teardown['backend']=reference_stop(reference,reference_log,teardown_started+1)"
f=function('run_backend')
f=replace(f,"daemon=channel_module.Channel(command,directory/'broker.log','FIXTURE ')","daemon=channel_module.Channel(command,directory/'broker.log','FIXTURE ')\nbroker_pid=daemon.process.pid\nc['broker']=process_identity(broker_pid)")
f=replace(f,"broker_pid=reference.pid","broker_pid=reference.pid\nc['broker']=process_identity(broker_pid)")
f=replace(f,"actor=channel_module.Actor(actor_command,directory/'actor.log')","actor=channel_module.Actor(actor_command,directory/'actor.log')\nc['launcher']=process_identity(actor.process.pid)")
f=replace(f,"actor_command=[report['inputs_before']['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir)]",
    "actor_command=[report['inputs_before']['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir),str(args.fd05),str(args.shared)]")
f=replace(f,"teardown=c['teardown']","teardown=c['teardown']\nteardown_started=time.monotonic()")
f=replace(f,"if actor: teardown['actor']=actor.stop(grace=5)","if actor: teardown['actor']=stop_channel(actor,actor_pid,teardown_started+1,[c.get('launcher'),c.get('actor')])")
f=replace(f,BACKEND_STOP_BEFORE,BACKEND_STOP_AFTER)
f=replace(f,"bounded_poll(contain,lambda r:not any(r.values()),1000,teardown['containment_attempts'])","bounded_poll(contain,lambda r:not any(r.values()),max(.001,1000-(time.monotonic()-teardown_started)*1000),teardown['containment_attempts'])")
f=replace(f,"if rows:\n try: os.killpg(int(group),signal.SIGKILL)\n except ProcessLookupError: pass","if rows: contain_owned(int(group),rows,c)")
f=replace(f,"teardown['socket_absent']=not socket_path.exists()","teardown['socket_absent']=not socket_path.exists()\nteardown['elapsed_ms']=(time.monotonic()-teardown_started)*1000")
base_run_backend=compile_function('run_backend',f)
def run_backend(args,report,backend,channel_module,save):
    prior=len(report['combinations'])
    try:
        with M.authority_budget(report): result=base_run_backend(args,report,backend,channel_module,save)
        S.latency(report['authority']['elapsed_seconds'],60)
        c=report['combinations'][-1];stop=c['teardown']
        assert_no_probe_errors(c)
        S.latency(stop['elapsed_ms'],1000)
        assert_clean_containment(stop)
        stop['broker_absent']=not Path('/proc',str(c['broker']['pid'])).exists()
        stop['launcher_absent']=not Path('/proc',str(c['launcher']['pid'])).exists()
        stop['actor_eof']=json.loads((args.evidence/backend/'actor.log').read_text().splitlines()[-1])
        M.assert_retired(stop['actor']['before_containment'],c['launcher']['pid'],c['actor']['pid'])
        M.assert_retired(stop['backend']['before_containment'],c['broker']['pid'],c['broker']['pid'],(0,) if backend=='gao' else (0,-15))
        for owner in ('actor','backend'):
            if owner=='actor' or backend=='gao':
                assert stop[owner]['fallback_actions']==[] and stop[owner]['cleanup_errors']==[] and stop[owner]['drain_complete'] is True
        if backend=='reference':
            c['reference_config_path']=str(args.evidence/backend/'reference.conf')
            c['reference_config_exported']=Path(c['reference_config_path']).read_text()
        save();return result
    except Exception as error:
        if len(report['combinations'])==prior: report['combinations'].append(dict(backend=backend,status='blocked',reason=repr(error)))
        else: report['combinations'][-1].update(status='failed',error=repr(error))
        save();return False
NS.update(run_backend=run_backend,record_authority=M.record_authority)
f=function('main')
f=replace(f,"for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope'):\n parser.add_argument('--'+name,required=True,type=Path)",
    "for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope','fd05','shared','mixed','bundles'):\n parser.add_argument('--'+name,required=True,type=Path)")
f=replace(f,"report['elapsed_seconds']=time.monotonic()-report['started_monotonic']","record_authority(report)\nreport['elapsed_seconds']=time.monotonic()-report['started_monotonic']")
class Labels(ast.NodeTransformer):
    def __init__(self): self.counts={'FD-05':0,'passed_independent_fd05_core':0}
    def visit_Constant(self,node):
        if node.value=='FD-05': self.counts[node.value]+=1;return ast.Constant(value='FD-07')
        if node.value=='passed_independent_fd05_core': self.counts[node.value]+=1;return ast.Name(id='PASS',ctx=ast.Load())
        return node
labels=Labels();f=labels.visit(f);assert labels.counts=={'FD-05':1,'passed_independent_fd05_core':2}
assignments=[n for n in f.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='report' for t in n.targets)];assert len(assignments)==1
selection_matches=0
for keyword in assignments[0].value.keywords:
    if keyword.arg=='selection':
        assert ast.literal_eval(keyword.value)==['FD-05/core/gao','FD-05/core/reference']
        selection_matches+=1;keyword.value=ast.Name(id='SELECTION',ctx=ast.Load())
assert selection_matches==1
assignments[0].value.keywords += [ast.keyword(arg='subcase',value=ast.Constant(value='missing-destination')),ast.keyword(arg='adapter_provenance',value=ast.Name(id='ADAPTER_PROVENANCE',ctx=ast.Load()))]
NS.update(PASS=PASS,SELECTION=SELECTION)
main=compile_function('main',f)
ADAPTER_PROVENANCE=dict(original_sha256=PINS[FD05/'qualify.py'],executed_sha256=S.sha(HERE/'qualify.py'),exact_adaptations=SHAPES)
NS['ADAPTER_PROVENANCE']=ADAPTER_PROVENANCE
for name in ('counts','CAPS','NORMALIZED_CAPS','METRICS','AUTHORITIES','assert_connections','assert_process','reference_config','native_config'):
    if name not in globals(): globals()[name]=getattr(N,name) if hasattr(N,name) else getattr(S,name)
if __name__=='__main__': main()
