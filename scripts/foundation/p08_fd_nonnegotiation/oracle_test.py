"""Pure FD-05 receipt controls; never launch a broker, actor, VM or build."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fd05_controller', HERE / 'qualify.py')
Q = importlib.util.module_from_spec(SPEC) if SPEC else None
if Q and Path(SPEC.origin).exists():
    SPEC.loader.exec_module(Q)


def frame(kind, serial, fields, body=b''):
    header = b''
    for code, sig, val in fields:
        header += bytes(-len(header) % 8) + bytes([code, 1]) + sig.encode() + b'\0'
        if sig in ('s', 'o'):
            raw = val.encode()
            header += struct.pack('<I', len(raw)) + raw + b'\0'
        elif sig == 'g':
            header += bytes([len(val)]) + val.encode() + b'\0'
        else:
            header += struct.pack('<I', val)
    return b'l' + bytes([kind, 0, 1]) + struct.pack('<III', len(body), serial, len(header)) + header + bytes(-len(header) % 8) + body


def string(value):
    raw = value.encode()
    return struct.pack('<I', len(raw)) + raw + b'\0'


def message(role, kind, serial, fields, body=b'', rights=0):
    raw = frame(kind, serial, fields, body)
    return dict(role=role, type=kind, serial=serial, fields={str(c): v for c, _, v in fields},
                body_hex=body.hex(), rights=rights, wire_hex=raw.hex(), wire_sha256=hashlib.sha256(raw).hexdigest())


def process(pid, uid, exe):
    return dict(pid=pid, uid=uid, gid=uid, executable=exe, argv=[exe], starttime_ticks=100,
                kernel_ids=dict(uids=[uid]*4, gids=[uid]*4), pgid=pid, executable_sha256='a'*64)


def census(pid, uid, n):
    return dict(pid=pid, uids=[uid]*4, gids=[uid]*4, fds=n, memfds=[], targets=['socket:[1]']*n)


def actor(case):
    pid, uid = 200, 1100
    roles = ['source', 'target', 'ordinary']
    connections = [dict(role=role, name=f':1.{i+1}', unique_name=f':1.{i+1}', negotiated=role != 'ordinary', pid=pid, uid=uid, gid=uid,
                        negotiation=dict(requested=role != 'ordinary', auth_reply='OK ' + 'a'*32, fd_reply='AGREE_UNIX_FD' if role != 'ordinary' else None)) for i, role in enumerate(roles)]
    actor_process=process(pid,uid,'/python'); actor_process['kernel_ids']={'Uid':[uid]*4,'Gid':[uid]*4,'NSpid':[pid],'NStgid':[pid]}
    base = dict(pid=pid, uid=uid, gid=uid, process=actor_process, fds=dict(count=3+len(roles), targets=[]), case=case, connections=connections)
    source, ordinary = connections[0]['name'], connections[-1]['name']
    sent, received, health, barriers, resources = [], [], [], [], []
    def send(role, kind, serial, fields, body=b'', rights=0):
        row = message(role, kind, serial, fields, body, rights)
        row['wire_bytes'] = len(bytes.fromhex(row['wire_hex']))
        sent.append(row)
    def healthy(role, name, serial):
        send(role, 1, serial, [(1,'o','/org/freedesktop/DBus'),(2,'s','org.freedesktop.DBus'),(3,'s','GetNameOwner'),(6,'s','org.freedesktop.DBus'),(8,'g','s')], string(name))
        received.append(message(role, 2, 800+serial, [(5,'u',serial),(6,'s',name),(7,'s','org.freedesktop.DBus'),(8,'g','s')], string(name)))
        health.append(dict(role=role, serial=serial, latency_ms=1))
    if case == 'unicast':
        send('source',1,3,[(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','Resource'),(6,'s',ordinary),(8,'g','h'),(9,'u',1)],bytes(4),1)
        received.append(message('source',3,500,[(4,'s','org.freedesktop.DBus.Error.NotSupported'),(5,'u',3),(6,'s',source),(7,'s','org.freedesktop.DBus'),(8,'g','s')],string('not negotiated')))
        healthy('ordinary',ordinary,4)
        healthy('source',source,5)
        contents=b'DO-NOT-DELIVER'
        resources=[dict(role='source',fd=9,target='pipe:[2]',dev=1,ino=2,mode=4480,size=0,contents_hex=contents.hex(),contents_sha256=hashlib.sha256(contents).hexdigest(),closed=True)]
        base.update(error_name='org.freedesktop.DBus.Error.NotSupported',error_reply_serial=3)
    else:
        def broadcast(serial, member, sig, body, rights):
            fields=[(1,'o','/broadcast'),(2,'s','org.foundation.Broadcast'),(3,'s',member),(8,'g',sig)]
            if rights: fields.append((9,'u',1))
            send('source',4,serial,fields,body,rights)
            return fields+[(7,'s',source)]
        fields=broadcast(100,'Resource','h',bytes(4),1)
        def barrier(serial):
            send('source',1,serial,[(1,'o','/org/freedesktop/DBus'),(2,'s','org.freedesktop.DBus'),(3,'s','ListNames'),(6,'s','org.freedesktop.DBus'),(8,'g','')])
            received.append(message('source',2,900+serial,[(5,'u',serial),(6,'s',source),(7,'s','org.freedesktop.DBus'),(8,'g','as')],bytes(4)))
            barriers.append(dict(serial=serial,latency_ms=1))
        barrier(101)
        received.append(message('target',4,100,fields,bytes(4),1))
        contents=b'OS-BUS-BROADCAST-MEMFD'
        resources=[dict(role='target',fd=9,target='/memfd:foundation-broadcast-200 (deleted)',dev=1,ino=2,mode=33279,size=len(contents),contents_hex=contents.hex(),contents_sha256=hashlib.sha256(contents).hexdigest(),closed=True)]
        resources.insert(0,{**resources[0],'role':'source','fd':8})
        for i,c in enumerate(connections): healthy(c['role'],c['name'],110+i)
        fields=broadcast(200,'Plain','s',string('RIGHTS0-BROADCAST'),0)
        barrier(201)
        for c in connections[1:]: received.append(message(c['role'],4,200,fields,string('RIGHTS0-BROADCAST')))
        for i,c in enumerate(connections): healthy(c['role'],c['name'],210+i)
    return {**base, 'sent':sent,'received':received,'health':health,'barriers':barriers,'resources':resources,
            'assertions':dict(strict_first_message=True,actor_fd_growth=0,resource_deliveries=int(case=='mixed'),rights0_deliveries=2 if case=='mixed' else 0,healthy_replies=len(health))}


def valid_report():
    authorities={name:f'#PID<0.{i+1}.0>' for i,name in enumerate(Q.AUTHORITIES)}
    def telemetry(connections=(), matches=0):
        empty=dict.fromkeys(Q.METRICS,0); counts={**empty,'connections':len(connections)}
        peers=[dict(name=c['name'],peer=f'#PID<0.{i+20}.0>',credentials={k:c[k] for k in ('pid','uid','gid')},
                    negotiated=c['negotiated'],queue=0,buffer_bytes=0,output=None) for i,c in enumerate(connections)]
        return dict(pending=0,capabilities=0,matches=matches,authorities=copy.deepcopy(authorities),peers=peers,
                    usage=dict(global_counts=None,**{'global':counts},peers={p['peer']:{**empty,'connections':1} for p in peers},
                               uids={'1100':counts} if peers else {},reservations=0,limits=copy.deepcopy(Q.CAPS),xml=dict(limits=None,queues=None)))
    def sample(n, native, connections=(), matches=0):
        result=dict(broker=census(100,0,12+(2*n if native else n)),actor=census(200,1100,3+n))
        if native: result['telemetry']=telemetry(connections,matches)
        return result
    combos=[]
    for backend in ('gao','reference'):
        native=backend=='gao'
        p=process(200,1100,'/python');p['pgid']=300
        empty=sample(0,native)
        warm=actor('mixed'); warm_connections=copy.deepcopy(warm['connections'][:2])
        warm.update(connections=[],warmup_connections=warm_connections,usable_transfer=True,closed=True,actor_fd_growth=0,fds=dict(count=3,targets=[]),barriers=[],health=warm['health'][:2])
        fields=[(1,'o','/broadcast'),(2,'s','org.foundation.Broadcast'),(3,'s','Resource'),(8,'g','h'),(9,'u',1),(6,'s',':1.2')]
        warm['sent']=[message('source',4,100,fields,bytes(4),1),warm['sent'][2],warm['sent'][3]]
        warm['received']=[message('target',4,100,fields+[(7,'s',':1.1')],bytes(4),1),warm['received'][2],warm['received'][3]]
        c=dict(backend=backend,status='passed',broker=process(100,0,'/beam' if native else '/dbus'),actor=p,
               launcher=process(300,0,'/runuser'),versions={k:dict(returncode=0,stdout='version',command=['/synthetic/'+('python' if k=='actor' else 'elixir' if native else 'reference_executable'),'--version']) for k in ('actor','broker')},
               before=copy.deepcopy(empty),warmed=copy.deepcopy(empty),warmup=warm,cases=[],
               effective_config=Q.native_config(),ready=dict(config_file=None,profile='system' if native else 'core',send_timeout_ms=5000,resource_limits=copy.deepcopy(Q.CAPS)),
               reference_config=Q.reference_config(Q.WORKLOAD['socket']))
        for name in ('unicast','mixed'):
            exercise=actor(name); opened=copy.deepcopy(exercise);connections=opened['connections']
            connected=sample(3,native,connections,2 if name=='mixed' else 0)
            closed=copy.deepcopy(empty)
            c['cases'].append(dict(name=name,status='passed',open=opened,exercise=exercise,connected=connected,checked=copy.deepcopy(connected),closed=closed,
                                  close=dict(connections=[],closed=True,fds=dict(count=3,targets=[])),
                                  cleanup_attempts=[dict(elapsed_ms=1,sample=closed,success=True)],cleanup_elapsed_ms=2,
                                  connected_attempts=[dict(elapsed_ms=1,sample=connected,success=True)],checked_attempts=[dict(elapsed_ms=1,sample=connected,success=True)]))
        c['teardown']=dict(actor=dict(method='eof',returncode=0,pid=300),backend=dict(method='eof' if native else 'sigterm',returncode=0 if native else -15,pid=100),
                           groups_absent=True,socket_absent=True,actual_actor_absent=True,observer_unlink=None)
        combos.append(c)
    required=('actor','actor_test','qualify','oracle_test','workload','test_nix','readme','scope','channel','transport_actor','broadcast_actor','quota_daemon','collector','candidate_manifest','python','elixir','erl','beam','reference_executable','runuser')
    inputs={key:dict(path='/synthetic/'+key,sha256='a'*64) for key in required}
    inputs['candidate_manifest']['sha256']=Q.WORKLOAD['candidate_manifest_sha256']
    files={f'file{i}':'a'*64 for i in range(80)}
    return dict(schema=1,not_a_release=True,elapsed_seconds=30,stripped_dbus_keys=['DBUS_SESSION_BUS_ADDRESS'],requirement='FD-05',profile='core',workload=copy.deepcopy(Q.WORKLOAD),selection=['FD-05/core/gao','FD-05/core/reference'],
                inputs_before=inputs,inputs_after=copy.deepcopy(inputs),manifest=dict(not_a_release=True,files=files,sources={f'source{i}':'b'*64 for i in range(71)}),
                candidate_before=files,candidate_after=copy.deepcopy(files),command=['/python','-B','qualify.py'],observer=process(400,0,'/python'),combinations=combos,
                counts=dict(selected=2,executed=2,passed=2,failed=0,blocked=0,skipped=0),result='passed_independent_fd05_core')


def setup_prefixed_warmup():
    row=valid_report()['combinations'][0]['warmup']
    setup=[]
    for index,c in enumerate(row['warmup_connections']):
        role,name=c['role'],c['name']
        setup.extend([
            message(role,2,1+4*index,[(5,'u',1),(6,'s',name),(7,'s',Q.BUS),(8,'g','s')],string(name)),
            message(role,4,2+4*index,[(1,'o','/org/freedesktop/DBus'),(2,'s',Q.BUS),(3,'s','NameAcquired'),(6,'s',name),(7,'s',Q.BUS),(8,'g','s')],string(name)),
            message(role,2,4+4*index,[(5,'u',2),(6,'s',name),(7,'s',Q.BUS),(8,'g','as')],bytes(4))])
    for receipt in setup: receipt.update(phase='setup',fd_targets=[])
    for receipt in row['received']: receipt.update(phase='active',fd_targets=[])
    row['received'][0]['fd_targets']=[{k:row['resources'][1][k] for k in ('fd','target','dev','ino','mode','size')}]
    row['received']=setup+row['received']
    return row


class OracleTests(unittest.TestCase):
    def require(self, name):
        self.assertTrue(Q is not None and hasattr(Q, name), f'FD-05 controller missing {name}')
        return getattr(Q, name)

    def reject(self, fn, value):
        with self.assertRaises((AssertionError,ValueError,KeyError,TypeError,struct.error)):
            fn(value)

    def assert_reference_admission(self, text):
        root=ET.fromstring(text)
        policies=root.findall('policy')
        for policy in policies:
            if 'user' in policy.attrib or 'group' in policy.attrib:
                self.assertFalse(any('user' in rule.attrib or 'group' in rule.attrib for rule in policy),
                                 'connection admission has bus-global semantics')
        defaults=[policy for policy in policies if policy.attrib=={'context':'default'}]
        self.assertEqual(len(defaults),1)
        rules=[(rule.tag,rule.attrib) for rule in defaults[0] if 'user' in rule.attrib or 'group' in rule.attrib]
        self.assertEqual(rules,[('deny',{'user':'*'}),('allow',{'user':'1100'})])
        for uid in (0,1099,1100,1101,65534):
            admitted=None
            for tag,attrs in rules:
                if attrs['user'] in ('*',str(uid)): admitted=tag=='allow'
            self.assertEqual(admitted,uid==1100)

    def test_reference_admission_default_order(self):
        self.assert_reference_admission(self.require('reference_config')(Q.WORKLOAD['socket']))

    def test_reference_admission_negative_controls(self):
        valid='<busconfig><policy context="default"><deny user="*"/><allow user="1100"/></policy><policy user="1100"/></busconfig>'
        self.assert_reference_admission(valid)
        invalid=[
            valid.replace('<allow user="1100"/>','').replace('<policy user="1100"/>','<policy user="1100"><allow user="1100"/></policy>'),
            valid.replace('<deny user="*"/><allow user="1100"/>','<allow user="1100"/><deny user="*"/>'),
            valid.replace('<allow user="1100"/>','<allow user="*"/>'),
            valid.replace('<allow user="1100"/>','<allow user="1101"/>'),
            valid.replace('<deny user="*"/>',''),
            valid.replace('<policy user="1100"/>','<policy group="1100"><allow group="1100"/></policy>')]
        for text in invalid:
            with self.subTest(config=text),self.assertRaises(AssertionError): self.assert_reference_admission(text)

    def test_reference_policy_inventory_and_limits(self):
        root=ET.fromstring(self.require('reference_config')(Q.WORKLOAD['socket']))
        self.assertEqual((root.tag,root.attrib),('busconfig',{}))
        self.assertEqual([child.tag for child in root],['type','listen','auth','policy','policy']+['limit']*6)
        for child,tag,text in zip(list(root)[:3],('type','listen','auth'),('system','unix:path=/run/osbus-fd-quotas/bus','EXTERNAL')):
            self.assertEqual((child.tag,child.attrib,child.text,len(child)),(tag,{},text,0))
        default,uid=root.findall('policy')
        self.assertEqual(default.attrib,{'context':'default'})
        self.assertEqual([(rule.tag,rule.attrib) for rule in default],[('deny',{'user':'*'}),('allow',{'user':'1100'}),
                         ('deny',{'own':'*'}),('deny',{'send_destination':'*'}),('deny',{'receive_sender':'*'})])
        self.assertEqual(uid.attrib,{'user':'1100'})
        self.assertEqual([(rule.tag,rule.attrib) for rule in uid],[('allow',{'send_destination':'*'}),('allow',{'receive_sender':'*'})])
        self.assertTrue(all(len(rule)==0 and not (rule.text or '').strip() for policy in (default,uid) for rule in policy))
        self.assertEqual([(limit.attrib,limit.text,len(limit)) for limit in root.findall('limit')],
                         [({'name':name},value,0) for name,value in [('auth_timeout','10000'),('max_incoming_unix_fds','64'),
                          ('max_outgoing_unix_fds','64'),('max_message_unix_fds','16'),('max_connections_per_user','8'),('max_completed_connections','8')]])

    def test_valid_unicast(self): self.require('assert_exercise')(actor('unicast'))
    def test_valid_mixed(self): self.require('assert_exercise')(actor('mixed'))
    def test_missing_error(self):
        r=actor('unicast'); r['received'].pop(0); self.reject(self.require('assert_exercise'),r)
    def test_wrong_error(self):
        r=actor('unicast'); r['received'][0]['fields']['4']='wrong'; self.reject(self.require('assert_exercise'),r)
    def test_fabricated_wire(self):
        r=actor('mixed'); r['received'][1]['body_hex']='01'; self.reject(self.require('assert_exercise'),r)
    def test_bad_wire_digest(self):
        r=actor('mixed'); r['received'][1]['wire_sha256']='b'*64; self.reject(self.require('assert_exercise'),r)
    def test_missing_plain(self):
        r=actor('mixed'); r['received'].pop(6); self.reject(self.require('assert_exercise'),r)
    def test_duplicate_health(self):
        r=actor('mixed'); r['health'][1]=r['health'][0]; self.reject(self.require('assert_exercise'),r)
    def test_health_deadline(self):
        r=actor('mixed'); r['health'][0]['latency_ms']=1001; self.reject(self.require('assert_exercise'),r)
    def test_negative_latency(self):
        r=actor('unicast'); r['health'][0]['latency_ms']=-1; self.reject(self.require('assert_exercise'),r)
    def test_wrong_negotiation(self):
        r=actor('mixed'); r['connections'][-1]['negotiated']=True; self.reject(self.require('assert_exercise'),r)
    def test_wrong_actor_pid(self):
        r=actor('mixed'); r['connections'][1]['pid']=201; self.reject(self.require('assert_exercise'),r)
    def test_no_resource_close(self):
        r=actor('mixed'); r['resources'][0]['closed']=False; self.reject(self.require('assert_exercise'),r)
    def test_wrong_resource_contents(self):
        r=actor('mixed'); r['resources'][0]['contents_hex']='00'; self.reject(self.require('assert_exercise'),r)
    def test_ordinary_unexpected_frame(self):
        r=actor('mixed'); r['received'].insert(4,copy.deepcopy(r['received'][1])); r['received'][4]['role']='ordinary'; self.reject(self.require('assert_exercise'),r)
    def test_resource_growth(self):
        r=actor('mixed'); r['assertions']['actor_fd_growth']=1; self.reject(self.require('assert_exercise'),r)
    def test_bad_sent_destination(self):
        r=actor('unicast'); r['sent'][0]=message('source',1,3,[(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','Resource'),(6,'s',':1.99'),(8,'g','h'),(9,'u',1)],bytes(4),1); self.reject(self.require('assert_exercise'),r)
    def test_duplicate_header(self):
        raw=frame(2,4,[(5,'u',4),(5,'u',4)]); self.reject(self.require('parse_frame'),raw)
    def test_truncated_frame(self): self.reject(self.require('parse_frame'),frame(2,4,[(5,'u',4)])[:-1])
    def test_trailing_frame(self): self.reject(self.require('parse_frame'),frame(2,4,[(5,'u',4)])+b'X')
    def test_numeric_recovery(self):
        fn=self.require('assert_recovered'); fn(census(100,0,12),census(100,0,12))
        with self.assertRaises(AssertionError): fn(census(100,0,12),census(100,0,13))
    def test_memfd_recovery(self):
        fn=self.require('assert_recovered'); r=census(100,0,12); r['memfds']=['/memfd:leak'];
        with self.assertRaises(AssertionError): fn(census(100,0,12),r)
    def test_missing_inventory(self): self.reject(self.require('assert_inventory'),{'pid':100})
    def test_wrong_kernel_uid(self):
        fn=self.require('assert_process'); r=process(200,1100,'/python'); r['kernel_ids']['uids'][1]=0; self.reject(fn,r)
    def test_missing_teardown(self): self.reject(self.require('assert_report'),{'result':'passed','counts':{'passed':2}})
    def test_labels_cannot_count_passes(self):
        self.assertEqual(self.require('counts')([{'backend':'gao','status':'running'},{'backend':'reference','status':'skipped'}]),dict(selected=2,executed=1,passed=0,failed=0,blocked=0,skipped=1))

    def test_complete_report(self): self.require('assert_report')(valid_report())
    def mutation(self, change):
        r=valid_report();change(r);self.reject(self.require('assert_report'),r)
    def test_incomplete_case(self): self.mutation(lambda r:r['combinations'][0]['cases'].pop())
    def test_duplicate_case(self): self.mutation(lambda r:r['combinations'][0]['cases'].__setitem__(1,r['combinations'][0]['cases'][0]))
    def test_missing_selected_backend(self): self.mutation(lambda r:r['combinations'].pop())
    def test_fabricated_pass_counts(self): self.mutation(lambda r:r['counts'].update(executed=0))
    def test_actor_not_eof(self): self.mutation(lambda r:r['combinations'][0]['teardown']['actor'].update(method='kill'))
    def test_no_backend_teardown(self): self.mutation(lambda r:r['combinations'][0]['teardown'].pop('backend'))
    def test_backend_wrong_exit(self): self.mutation(lambda r:r['combinations'][0]['teardown']['backend'].update(returncode=1))
    def test_reference_wrong_exit(self): self.mutation(lambda r:r['combinations'][1]['teardown']['backend'].update(returncode=-9))
    def test_reference_fake_eof(self): self.mutation(lambda r:r['combinations'][1]['teardown']['backend'].update(method='eof'))
    def test_reference_fabricated_internal_counters(self): self.mutation(lambda r:r['combinations'][1]['warmed'].update(telemetry={}))
    def test_process_group_survives(self): self.mutation(lambda r:r['combinations'][0]['teardown'].update(groups_absent=False))
    def test_socket_survives(self): self.mutation(lambda r:r['combinations'][0]['teardown'].update(socket_absent=False))
    def test_wrong_actual_actor(self): self.mutation(lambda r:r['combinations'][0]['actor'].update(pid=300))
    def test_wrong_kernel_credentials(self): self.mutation(lambda r:r['combinations'][0]['cases'][0]['checked']['telemetry']['peers'][0]['credentials'].update(uid=0))
    def test_authority_restart(self): self.mutation(lambda r:r['combinations'][0]['cases'][0]['closed']['telemetry']['authorities'].update({'GaoBus.Router':'#PID<0.999.0>'}))
    def test_pending_leak(self): self.mutation(lambda r:r['combinations'][0]['cases'][0]['closed']['telemetry'].update(pending=1))
    def test_transient_credit(self): self.mutation(lambda r:r['combinations'][0]['cases'][0]['checked']['telemetry']['usage']['global'].update(egress_fds=1))
    def test_numeric_broker_leak(self):
        def change(r):
            row=r['combinations'][0]['cases'][0]['closed']['broker'];row['fds']+=1;row['targets'].append('pipe:[99]')
        self.mutation(change)
    def test_cleanup_deadline(self): self.mutation(lambda r:r['combinations'][0]['cases'][0]['cleanup_attempts'][0].update(elapsed_ms=1001))
    def test_changed_input(self): self.mutation(lambda r:r['inputs_after']['actor'].update(sha256='c'*64))
    def test_missing_hash(self):
        def change(r):
            r['inputs_before'].pop('actor');r['inputs_after'].pop('actor')
        self.mutation(change)
    def test_reference_policy_drift(self): self.mutation(lambda r:r['combinations'][1].update(reference_config='<busconfig/>'))
    def test_unowned_reference_unlink(self): self.mutation(lambda r:r['combinations'][1]['teardown'].update(observer_unlink=dict(matched_inode=False,after_backend_exit=True)))

    def test_missing_warmup_wire(self): self.mutation(lambda r:r['combinations'][0]['warmup']['received'].clear())
    def test_warmup_label_only(self): self.mutation(lambda r:r['combinations'][0]['warmup']['resources'].clear())
    def test_wrong_warmup_inode(self): self.mutation(lambda r:r['combinations'][0]['warmup']['resources'][1].update(ino=999))
    def test_actual_authority_pid_format(self):
        state=valid_report()['combinations'][0]['before']['telemetry']
        state['authorities']={name:f'#PID<{i}.114.0>' for i,name in enumerate(Q.AUTHORITIES)}
        self.require('assert_native')(state,copy.deepcopy(state))
    def test_malformed_authority_pid_format(self):
        for value in ('<0.114.0>','#PID<0.114.0','#PID<0.114.0>extra','#PID<0.114>','#PID<0.114.0.1>',
                      '#PID<-1.114.0>','#PID<0.+114.0>','#PID<0.x.0>','#PID<0.114.0>\n','#PID<０.114.0>',None,114):
            with self.subTest(value=value):
                state=valid_report()['combinations'][0]['before']['telemetry']
                state['authorities']={name:'#PID<0.114.0>' for name in Q.AUTHORITIES}
                state['authorities'][Q.AUTHORITIES[0]]=value
                with self.assertRaises(AssertionError): self.require('assert_native')(state,copy.deepcopy(state))
    def test_setup_prefixed_warmup(self): self.require('assert_warmup')(setup_prefixed_warmup())
    def test_setup_prefixed_warmup_missing_resource(self):
        r=setup_prefixed_warmup(); r['received'].pop(6); self.reject(self.require('assert_warmup'),r)
    def test_setup_prefixed_warmup_missing_fd(self):
        r=setup_prefixed_warmup(); r['received'][6]['fd_targets'].clear(); self.reject(self.require('assert_warmup'),r)
    def test_setup_prefixed_warmup_mismatched_fd(self):
        for key in ('fd','target','dev','ino','mode','size'):
            with self.subTest(key=key):
                r=setup_prefixed_warmup(); fd=r['received'][6]['fd_targets'][0]
                fd[key]=fd[key]+1 if type(fd[key]) is int else '/memfd:wrong (deleted)'
                self.reject(self.require('assert_warmup'),r)
    def test_setup_prefixed_warmup_wrong_resource(self):
        r=setup_prefixed_warmup(); original=r['received'][6]
        fields=[(1,'o','/broadcast'),(2,'s','org.foundation.Broadcast'),(3,'s','Wrong'),(6,'s',':1.2'),(7,'s',':1.1'),(8,'g','h'),(9,'u',1)]
        r['received'][6]={**message('target',4,100,fields,bytes(4),1),'phase':'active','fd_targets':original['fd_targets']}
        self.reject(self.require('assert_warmup'),r)
    def test_setup_prefixed_warmup_resource_not_first(self):
        r=setup_prefixed_warmup(); r['received'][6:8]=r['received'][7:8]+r['received'][6:7]
        self.reject(self.require('assert_warmup'),r)
    def test_actor_close_total_deadline(self): self.mutation(lambda r:r['combinations'][0]['cases'][0].update(cleanup_elapsed_ms=1001))

    def test_runtime_deadline(self): self.mutation(lambda r:r.update(elapsed_seconds=121))
    def test_unsettled_phase_observation(self): self.mutation(lambda r:r['combinations'][0]['cases'][0]['connected_attempts'][0].update(success=False))
    def test_missing_settling_attempts(self): self.mutation(lambda r:r['combinations'][0]['cases'][0].pop('checked_attempts'))
    def test_wrong_native_policy(self): self.mutation(lambda r:r['combinations'][0]['effective_config'].update(policy_rules=[]))
    def test_wrong_observed_executable(self): self.mutation(lambda r:r['combinations'][0]['actor'].update(executable_sha256='f'*64))
    def test_wrong_version_executable(self): self.mutation(lambda r:r['combinations'][1]['versions']['broker'].update(command=['/unbound','--version']))
    def test_actual_proc_identity_and_inventory(self):
        import os
        identity=self.require('process_identity')(os.getpid());self.require('assert_process')(identity)
        inventory=self.require('external')(os.getpid());self.require('assert_inventory')(inventory)
        self.assertEqual(identity['pid'],inventory['pid'])
    def test_wrong_raw_health_body(self):
        r=actor('unicast');r['received'][1]=message('ordinary',2,804,[(5,'u',4),(6,'s',':1.3'),(7,'s','org.freedesktop.DBus'),(8,'g','s')],string('wrong'))
        self.reject(self.require('assert_exercise'),r)
    def test_wrong_raw_health_destination(self):
        r=actor('unicast');r['received'][1]=message('ordinary',2,804,[(5,'u',4),(6,'s',':1.99'),(7,'s','org.freedesktop.DBus'),(8,'g','s')],string(':1.3'))
        self.reject(self.require('assert_exercise'),r)
    def test_malformed_header_signature(self):
        self.reject(self.require('parse_frame'),frame(2,4,[(5,'s','4')]))

    def test_actual_nix_candidate_mode(self):
        candidate=Path('/nix/store/0i77zw541q6m6kmyb37p22nnkc463nx0-osbus-fd05-core-candidate16')
        self.assertTrue(candidate.is_dir(), 'current realized immutable candidate is required')
        manifest=json.loads((candidate/'candidate.json').read_text())
        self.assertEqual(self.require('candidate_inventory')(candidate,manifest),manifest['files'])
    def test_mode_validation_local(self):
        fn=self.require('assert_candidate_mode')
        fn(Path('/local/candidate/lib/a'),0o644,0o644)
        fn(Path('/local/candidate/lib/a'),0o755,0o755)
        with self.assertRaises(AssertionError): fn(Path('/local/candidate/lib/a'),0o644,0o444)
    def test_mode_validation_store(self):
        fn=self.require('assert_candidate_mode')
        fn(Path('/nix/store/frozen/lib/a'),0o644,0o444)
        fn(Path('/nix/store/frozen/lib/a'),0o755,0o555)
        for wrong in (0o644,0o400,0o440,0o555):
            with self.assertRaises(AssertionError): fn(Path('/nix/store/frozen/lib/a'),0o644,wrong)
        with self.assertRaises(AssertionError): fn(Path('/nix/store/frozen/lib/a'),0o755,0o444)
    def test_candidate_hash_rejection(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix='fd05-oracle-') as directory:
            candidate=Path(directory);(candidate/'a').write_bytes(b'changed')
            (candidate/'a').chmod(0o644)
            with self.assertRaises(AssertionError): self.require('candidate_inventory')(candidate,{'files':{'a':hashlib.sha256(b'original').hexdigest()},'file_modes':{'a':0o644}})


if __name__ == '__main__': unittest.main(verbosity=2)
