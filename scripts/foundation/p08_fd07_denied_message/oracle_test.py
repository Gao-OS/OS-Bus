"""Inert full-report FD07 controls and explicit unchanged wire predecessor RED."""
import copy
import ast
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
PREDECESSOR = '--predecessor' in sys.argv
if PREDECESSOR: sys.argv.remove('--predecessor')
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
Q=load('fd07_denied_oracle_controls',HERE/'qualify.py')
O=load('fd07_denied_original_synthetic',Q.FD05/'oracle_test.py')
T=load('fd07_denied_singleton_synthetic',Q.SHARED/'oracle_test.py')

def event(role,direction,kind,serial,fields,body=b'',rights=0,flags=0,targets=None):
    row=T.message(role,direction,kind,serial,fields,body,rights,targets=targets)
    raw=bytearray.fromhex(row['wire_hex']);raw[2]=flags
    row.update(wire_hex=raw.hex(),wire_sha256=hashlib.sha256(raw).hexdigest())
    return row

def resource(fd=8,role='source'):
    contents=Q.CONTENTS
    return dict(**T.fd(fd,2,pid=200,uid=1100,target='/memfd:foundation-broadcast-200 (deleted)',mode=0o100600),
        role=role,size=len(contents),contents_hex=contents.hex(),contents_sha256=hashlib.sha256(contents).hexdigest(),
        eof=True,read_chunks_hex=[contents.hex(),''],closed=True,ebadf=True)

def active():
    row=O.actor('unicast');row.update(case='denied-message',barriers=[],health=[],sent=[],received=[])
    for i,client in enumerate(row['connections'],3): client.update(socket_fd=i,socket=T.fd(i))
    row['fd_state']=T.fd_state([T.fd(i) for i in range(6)])
    row['fds']=dict(count=6,targets=[{**{k:fd[k] for k in ('fd','target','dev','ino','mode')},'size':0} for fd in row['fd_state']['fds']])
    row['resources']=[resource()]
    source=row['connections'][0]['name']
    fields=[(1,'o','/broadcast'),(2,'s','org.foundation.Broadcast'),(3,'s','Resource'),
        (6,'s',row['connections'][1]['name']),(8,'g','h'),(9,'u',1)]
    sent=event('source','sent',1,100,fields,bytes(4),1,2)
    sent.update(right_fd={k:row['resources'][0][k] for k in Q.S.FD_KEYS},sendmsg_bytes=sent['wire_bytes'],completed_bytes=sent['wire_bytes'])
    row['sent'].append(sent)
    row['received'].append(event('source','received',3,900,[(4,'s',Q.ERROR),(5,'u',100),(6,'s',source),(7,'s',Q.BUS),(8,'g','s')],Q.S.string('absent')))
    for serial in (110,111,112,210,211,212):
        client=row['connections'][serial-(110 if serial<200 else 210)]
        role,name=client['role'],client['name']
        row['health'].append(dict(role=role,serial=serial,latency_ms=1))
        row['sent'].append(event(role,'sent',1,serial,[(1,'o','/org/freedesktop/DBus'),(2,'s',Q.BUS),(3,'s','GetNameOwner'),(6,'s',Q.BUS),(8,'g','s')],Q.S.string(name)))
        row['received'].append(event(role,'received',2,serial+1000,[(5,'u',serial),(6,'s',name),(7,'s',Q.BUS),(8,'g','s')],Q.S.string(name)))
    row.update(error_name=Q.ERROR,error_reply_serial=100,closure=[{**{k:resource()[k] for k in Q.S.FD_KEYS},'role':'source','closed':True}])
    row['assertions']=dict(strict_first_message=True,actor_fd_growth=0,resource_deliveries=0,rights0_deliveries=0,healthy_replies=6,returned_rights=0,delivered_rights=0)
    return row

def census(pid,uid,n):
    fds=[T.fd(i,pid=pid,uid=uid) for i in range(n)]
    return dict(pid=pid,uids=[uid]*4,gids=[uid]*4,fds=n,targets=sorted(r['target'] for r in fds),memfds=[],numeric=T.inventory(fds,pid,uid))

def actual_actor_gid(value,gid):
    if isinstance(value,dict):
        if value.get('uid')==1100 and 'gid' in value: value['gid']=gid
        if value.get('uids')==[1100]*4: value['gids']=[gid]*4
        if value.get('Uid')==[1100]*4: value['Gid']=[gid]*4
        for child in value.values(): actual_actor_gid(child,gid)
    elif isinstance(value,list):
        for child in value: actual_actor_gid(child,gid)
    return value

def valid_report():
    report=O.valid_report(); report.update(requirement='FD-07',subcase='denied-message',workload=copy.deepcopy(Q.WORKLOAD),
        selection=Q.SELECTION,result=Q.PASS,adapter_provenance=copy.deepcopy(Q.ADAPTER_PROVENANCE),started_monotonic=100,
        authority=dict(limit_seconds=60,started_monotonic=100,finished_monotonic=101,elapsed_seconds=1))
    report['inputs_before']['candidate_manifest']['sha256']=Q.WORKLOAD['candidate_manifest_sha256']
    for key,path in Q.PINNED_FILES.items(): report['inputs_before'][key]=dict(path=str(path),sha256=Q.S.sha(path))
    report['inputs_before']['policy_adapter']=dict(path=str(Q.HERE/'policy_adapter.exs'),sha256=Q.S.sha(Q.HERE/'policy_adapter.exs'))
    report['inputs_before']['quota_daemon']['sha256']=Q.DAEMON_SHA256
    report['inputs_after']=copy.deepcopy(report['inputs_before'])
    for c in report['combinations']:
        c['startup_attempts']=[]
        c['warmup']=O.setup_prefixed_warmup()
        if c['backend']=='gao':
            c['effective_config']=Q.native_config()
            c['ready'].update(policy_rules=Q.policy_rules(),policy_generation=1,policy_adapter=copy.deepcopy(Q.POLICY_PROVENANCE))
        for direction in ('sent','received'):
            for event in c['warmup'][direction]:
                if event.get('phase')!='setup' and event['fields'].get('2')=='org.foundation.Broadcast':
                    event['fields'].update({'2':Q.WARMUP_INTERFACE,'3':Q.WARMUP_MEMBER})
                    types={'1':'o','2':'s','3':'s','6':'s','7':'s','8':'g','9':'u'}
                    raw=bytearray(O.frame(event['type'],event['serial'],[(int(k),types[k],v) for k,v in event['fields'].items()],bytes.fromhex(event['body_hex'])))
                    raw[2]=bytes.fromhex(event['wire_hex'])[2]
                    event.update(wire_hex=raw.hex(),wire_sha256=hashlib.sha256(raw).hexdigest())
                raw=bytes.fromhex(event['wire_hex'])
                assert event['wire_sha256']==hashlib.sha256(raw).hexdigest()
                event.update(direction=direction,phase=event.get('phase','active'),wire_bytes=len(raw))
        c['warmup']['resources']=[resource(8),resource(9,'target')]
        for i,client in enumerate(c['warmup']['warmup_connections'],3): client.update(socket_fd=i,socket=T.fd(i))
        c['warmup']['fd_state']=T.fd_state([T.fd(i) for i in range(3)])
        c['warmup']['fds']=dict(count=3,targets=[{**{k:fd[k] for k in ('fd','target','dev','ino','mode')},'size':0} for fd in c['warmup']['fd_state']['fds']])
        c['warmup']['closure']=[{**{k:r[k] for k in Q.S.FD_KEYS},'role':r['role'],'closed':True} for r in c['warmup']['resources']]
        for client in c['warmup']['warmup_connections']:
            c['warmup']['closure'].append(dict(**T.fd(client['socket_fd']),role=client['role'],closed=True))
        warmfd={k:resource(9,'target')[k] for k in ('fd','target','dev','ino','mode','size')}
        c['warmup']['received'][6]['fd_targets']=[warmfd]
        original=[r for r in c['warmup']['sent'] if r.get('phase')!='setup'][0]
        original.update(right_fd={k:resource()[k] for k in Q.S.FD_KEYS},sendmsg_bytes=original['wire_bytes'],completed_bytes=original['wire_bytes'])
        case=c['cases'][0];c['cases']=[case];case.update(name='denied-message',open=active(),exercise=active())
        case['close'].update(closure=[dict(**T.fd(client['socket_fd']),role=client['role'],closed=True) for client in case['open']['connections']])
        case['close'].update(pid=200,uid=1100,gid=1100,fd_state=T.fd_state([T.fd(i) for i in range(3)]),
            fds=dict(count=3,targets=[{**{k:T.fd(i)[k] for k in ('fd','target','dev','ino','mode')},'size':0} for i in range(3)]))
        for phase in ('before','warmed'):
            for subject,pid,uid in [('actor',200,1100),('broker',100,0)]: c[phase][subject]=census(pid,uid,3 if subject=='actor' else 12)
        for phase in ('connected','checked','closed'):
            for subject,pid,uid in [('actor',200,1100),('broker',100,0)]:
                n=(3 if subject=='actor' else 12)+(3 if phase!='closed' else 0)
                case[phase][subject]=census(pid,uid,n)
            attempts=case['cleanup_attempts' if phase=='closed' else phase+'_attempts']
            attempts[-1]['sample']=copy.deepcopy(case[phase])
        for phase in ('before','warmed'):
            if c['backend']=='gao':
                state=c[phase]['telemetry'];state['usage']['limits']=copy.deepcopy(Q.S.NORMALIZED_CAPS)
                state['usage']['xml']=dict(limits=None,queues=None,**{'global':dict(incomplete=0,completed=0)},uids={})
                state['names']=[Q.BUS]
        for phase in ('connected','checked','closed'):
            if c['backend']=='gao':
                state=case[phase]['telemetry'];state['usage']['limits']=copy.deepcopy(Q.S.NORMALIZED_CAPS)
                state['usage']['xml']=dict(limits=None,queues=None,**{'global':dict(incomplete=0,completed=0)},uids={})
                state['names']=[Q.BUS]+([] if phase=='closed' else [client['name'] for client in case['open']['connections']])
        for phase in ('connected','checked','closed'):
            attempts=case['cleanup_attempts' if phase=='closed' else phase+'_attempts'];attempts[-1]['sample']=copy.deepcopy(case[phase])
        stop=c['teardown'];stop.update(elapsed_ms=1,broker_absent=True,launcher_absent=True,actor_eof=dict(ok=True,result=dict(fd_growth=0,baseline_equal=True)))
        stop['containment_attempts']=[dict(elapsed_ms=1,success=True,sample={'300':[],'100':[]})]
        for owner,wrapper,pid in [('actor',300,200),('backend',100,100)]:
            stop[owner].update(fallback_actions=[],cleanup_errors=[],drain_complete=True,drained_bytes=0)
            stop[owner]['before_containment']=dict(wrapper_pid=wrapper,actual_pid=pid,wrapper_waited=True,
                wrapper_returncode=stop[owner]['returncode'],timed_out=False,errors=[],pid_absent=True,actor_pid_absent=True,group_absent=True,group_members=[])
        c.update(reference_config_path='/synthetic/reference.conf',reference_config=Q.reference_config(Q.WORKLOAD['socket']),reference_config_exported=Q.reference_config(Q.WORKLOAD['socket']),
            reference_config_sha256=hashlib.sha256(Q.reference_config(Q.WORKLOAD['socket']).encode()).hexdigest())
    return report

class CompleteReport(unittest.TestCase):
    def test_actual_gid100_resource_is_bound_to_actor_credentials(self):
        Q.assert_exercise(active())
        row=actual_actor_gid(active(),100)
        self.assertEqual(row['gid'],100)
        self.assertEqual(row['resources'][0]['gid'],100)
        Q.assert_exercise(row)
    def test_actual_gid100_complete_report_joins_external_inventory(self):
        report=actual_actor_gid(valid_report(),100)
        Q.assert_report(report)
        report['combinations'][0]['cases'][0]['checked']['actor']['gids']=[1100]*4
        with self.assertRaises(AssertionError): Q.assert_report(report)
    def test_resource_wrong_owner_remains_rejected_with_actual_gid100(self):
        for key,value in (('gid',1100),('uid',0),('pid',201)):
            row=actual_actor_gid(active(),100);Q.assert_exercise(row)
            row['resources'][0][key]=value
            with self.assertRaisesRegex(AssertionError,'FD owner mismatch'): Q.assert_exercise(row)
    def test_denied_call_cannot_allow_activation(self):
        sent=active()['sent'][0]
        check=Q.N.assert_wire if PREDECESSOR else lambda event:Q.assert_denied_sent(event,':1.2')
        check(sent)
        raw=bytearray.fromhex(sent['wire_hex']);raw[2]=0
        sent.update(wire_hex=raw.hex(),wire_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(AssertionError): check(sent)
    def test_zero_fd_header_on_denial_cannot_be_hidden(self):
        row=active();source=row['connections'][0]['name']
        check=Q.N.assert_wire if PREDECESSOR else lambda event:Q.assert_denied_error(event,source)
        reply=row['received'][0];check(reply)
        fields=[(4,'s',Q.ERROR),(5,'u',100),(6,'s',source),(7,'s',Q.BUS),(8,'g','s'),(9,'u',0)]
        changed=event('source','received',3,900,fields,Q.S.string('denied'))
        with self.assertRaises(AssertionError):check(changed)
    def test_native_policy_is_exactly_one_narrow_added_send_deny(self):
        expected=copy.deepcopy(Q.N.native_config()['policy_rules'])
        expected.append(dict(action='send',effect='deny',match=dict(uid=1100,type='method_call',interface='org.foundation.Broadcast')))
        self.assertEqual(Q.policy_rules(),expected)
        self.assertEqual(Q.native_config()['policy_rules'],expected)
        Q.assert_policy_configuration(valid_report()['combinations'][0])
    def test_effective_policy_snapshot_cannot_be_omitted_or_broadened(self):
        for mutate in (lambda c:c['ready']['policy_rules'].pop(),lambda c:c['ready']['policy_rules'][-1]['match'].update(uid=0),
                       lambda c:c['ready']['policy_rules'][-1]['match'].update(type='signal'),
                       lambda c:c['ready']['policy_rules'][-1]['match'].update(interface='*'),
                       lambda c:c['ready'].update(policy_generation=0),lambda c:c['ready']['policy_adapter'].update(executed_sha256='0'*64),
                       lambda c:c['effective_config']['policy_rules'].pop(),lambda c:c['ready'].pop('policy_rules')):
            report=valid_report();Q.assert_report(report);mutate(report['combinations'][0])
            with self.assertRaises((AssertionError,KeyError)):Q.assert_report(report)
    def test_reference_policy_has_only_the_matching_user_send_deny(self):
        import xml.etree.ElementTree as ET
        config=Q.reference_config(Q.WORKLOAD['socket']);tree=ET.fromstring(config)
        denied=[(p.attrib,child.attrib) for p in tree.findall('policy') for child in p.findall('deny') if 'send_interface' in child.attrib]
        self.assertEqual(denied,[({'user':'1100'},{'send_type':'method_call','send_interface':'org.foundation.Broadcast'})])
        for replacement in ('send_type="signal"','send_interface="org.foundation.Warmup"'):
            altered=config.replace('send_type="method_call"',replacement) if 'send_type' in replacement else config.replace('send_interface="org.foundation.Broadcast"',replacement)
            report=valid_report();Q.assert_report(report)
            report['combinations'][1].update(reference_config=altered,reference_config_exported=altered,
                reference_config_sha256=hashlib.sha256(altered.encode()).hexdigest())
            with self.assertRaises(AssertionError):Q.assert_report(report)
    def test_distinct_allowed_warmup_remains_resource_usable_and_closed(self):
        warm=valid_report()['combinations'][0]['warmup'];Q.assert_warmup(warm)
        for row in warm['sent']+warm['received']:
            if row.get('phase')!='setup' and row['rights']:
                self.assertEqual(row['fields']['2'],Q.WARMUP_INTERFACE)
                self.assertEqual(row['fields']['3'],Q.WARMUP_MEMBER)
        for key,value in (('eof',False),('ebadf',False),('ino',999),('gid',0)):
            changed=copy.deepcopy(warm);changed['resources'][1][key]=value
            with self.assertRaises(AssertionError):Q.assert_warmup(changed)
    def test_denied_call_must_target_existing_negotiated_peer(self):
        row=active();Q.assert_exercise(row)
        fields=[(1,'o','/broadcast'),(2,'s','org.foundation.Broadcast'),(3,'s','Resource'),
                (6,'s','org.foundation.Absent'),(8,'g','h'),(9,'u',1)]
        bad=event('source','sent',1,100,fields,bytes(4),1,2)
        row['sent'][0].update(bad)
        with self.assertRaises(AssertionError):Q.assert_exercise(row)
    def test_complete_synthetic_report(self): Q.assert_report(valid_report())
    def test_denied_message_semantic_mutations(self):
        mutations=[lambda r:r['received'][0]['fields'].update({'4':'wrong'}),lambda r:r['received'][0].update(rights=1),
            lambda r:r['received'][0]['fields'].update({'9':0}),lambda r:r['received'][0]['fields'].update({'5':101}),
            lambda r:r['health'].pop(),lambda r:r['received'].append(copy.deepcopy(r['received'][0])),
            lambda r:r['resources'][0].update(ebadf=False),lambda r:r['resources'][0].update(eof=False),
            lambda r:r['assertions'].update(delivered_rights=1)]
        for mutate in mutations:
            row=active();Q.assert_exercise(row);mutate(row)
            with self.assertRaises(AssertionError): Q.assert_exercise(row)
    def test_authority61_rejected_while_guest120_passes(self):
        report=valid_report();report.update(elapsed_seconds=61);report['authority'].update(finished_monotonic=161,elapsed_seconds=61)
        Q.base_report(report)
        with self.assertRaises(AssertionError): Q.assert_report(report)
    def test_added_lifecycle_and_inventory_facts_cannot_be_fabricated(self):
        mutations=[
            lambda r:r['combinations'][0]['teardown']['actor']['before_containment'].update(pid_absent=False),
            lambda r:r['combinations'][0]['teardown']['backend']['before_containment'].update(errors=['probe failed']),
            lambda r:r['combinations'][0]['teardown']['actor'].update(fallback_actions=[{'signal':'SIGKILL'}]),
            lambda r:r['combinations'][0]['teardown']['backend'].update(cleanup_errors=['drain failed']),
            lambda r:r['combinations'][0]['teardown']['actor'].update(drain_complete=False),
            lambda r:r['combinations'][0]['teardown']['containment_attempts'][0].update(success=False,sample={'300':[200]}),
            lambda r:r['combinations'][0]['teardown'].update(fallback_group_signals=[{'signal':'SIGKILL'}]),
            lambda r:r['combinations'][0]['cases'][0]['checked_attempts'][0].update(error='probe failed'),
            lambda r:r['combinations'][0]['teardown']['actor_eof']['result'].update(baseline_equal=False),
            lambda r:r['combinations'][0]['cases'][0]['exercise']['sent'][0]['right_fd'].update(ino=999),
            lambda r:r['combinations'][0]['cases'][0]['connected']['actor']['numeric']['fds'][0].update(ino=999),
            lambda r:r['combinations'][0]['cases'][0]['checked']['telemetry']['names'].append(':1.fabricated'),
            lambda r:r['combinations'][0]['warmup']['resources'][0].update(ebadf=False),
            lambda r:r['combinations'][0]['warmup']['resources'][1].update(read_chunks_hex=['00','']),
            lambda r:r['combinations'][0]['warmup']['sent'][0].update(completed_bytes=0),
            lambda r:r['combinations'][0]['teardown'].update(elapsed_ms=1001),
            lambda r:r['combinations'][1].update(reference_config_exported='<busconfig/>')]
        for mutate in mutations:
            report=valid_report();Q.assert_report(report);mutate(report)
            with self.assertRaises(AssertionError): Q.assert_report(report)

class StopControls(unittest.TestCase):
    def test_complete_backend_stop_node_preserves_both_branches(self):
        original=Q.function('run_backend')
        composed=Q.replace(original,Q.BACKEND_STOP_BEFORE,Q.BACKEND_STOP_AFTER)
        expected=ast.dump(ast.parse(Q.BACKEND_STOP_AFTER).body[0],include_attributes=False)
        self.assertEqual(sum(ast.dump(node,include_attributes=False)==expected for node in ast.walk(composed)),1)
        altered=Q.replace(Q.function('run_backend'),Q.BACKEND_STOP_BEFORE,
            "if daemon: teardown['backend']=daemon.stop(grace=5)\nelif reference: teardown['backend']=reference_stop(reference,reference_log,99)")
        with self.assertRaises(AssertionError): Q.replace(altered,Q.BACKEND_STOP_BEFORE,Q.BACKEND_STOP_AFTER)
    def channel(self):
        channel=Mock();channel.command=['inert'];channel.buffer=b''
        channel.process.pid=300;channel.process.returncode=0
        channel.process.stdout.fileno.return_value=9
        return channel
    def stop(self,channel,groups=(),reads=(b'',),times=None):
        identity=dict(pid=300,uid=0,gid=0,starttime_ticks=100,pgid=300)
        with patch.object(Q.time,'monotonic',return_value=100,side_effect=times),patch.object(Q.M,'probe_retired',return_value={'observed':True}),\
                patch.object(Q.N,'process_identity',return_value=identity),\
                patch.object(Q.S,'group_members',return_value=list(groups)),patch.object(Q.os,'killpg') as kill,\
                patch.object(Q.os,'set_blocking'),patch.object(Q.os,'read',side_effect=reads):
            result=Q.stop_channel(channel,200,101,[identity])
        return result,kill
    def test_graceful_stop_uses_remaining_deadline_and_observed_eof(self):
        channel=self.channel();result,kill=self.stop(channel)
        channel.process.wait.assert_called_once_with(timeout=1)
        channel.stop.assert_not_called();kill.assert_not_called()
        self.assertEqual(result['fallback_actions'],[]);self.assertEqual(result['cleanup_errors'],[])
        self.assertTrue(result['drain_complete']);self.assertEqual(result['method'],'eof')
    def test_timeout_containment_does_not_get_a_fresh_wait_budget(self):
        channel=self.channel();channel.process.wait.side_effect=[Q.subprocess.TimeoutExpired('inert',1),0]
        result,kill=self.stop(channel,(300,200),times=[100,100.75,100.75])
        self.assertEqual([call.kwargs['timeout'] for call in channel.process.wait.call_args_list],[1,.25])
        kill.assert_called_once_with(300,Q.signal.SIGKILL)
        self.assertEqual(result['method'],'kill');self.assertTrue(result['fallback_actions'])
        channel.stop.assert_not_called()
    def test_non_eof_drain_remains_incomplete(self):
        channel=self.channel();result,_=self.stop(channel,reads=(BlockingIOError(),))
        self.assertFalse(result['drain_complete'])
    def test_fallback_requires_original_process_birth_identity(self):
        identity=dict(pid=300,uid=0,gid=0,starttime_ticks=100,pgid=300)
        with patch.object(Q.N,'process_identity',return_value={**identity,'starttime_ticks':101}):
            with self.assertRaises(AssertionError): Q.assert_owned_group(300,[300],[identity])
        with self.assertRaises(AssertionError): Q.assert_owned_group(300,[999],[identity])

class InheritedControls(unittest.TestCase):
    def require(self,name): return getattr(Q,name)
    def reject(self,fn,row):
        with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError,struct.error)): fn(row)
    def mutation(self,change):
        report=valid_report();Q.assert_report(report);change(report)
        self.reject(Q.assert_report,report)
    def test_duplicate_selected_case(self): self.mutation(lambda r:r['combinations'][0]['cases'].append(copy.deepcopy(r['combinations'][0]['cases'][0])))
for name,method in vars(O.OracleTests).items():
    if name.startswith('test_') and 'mutation' in method.__code__.co_names and name!='test_duplicate_case':
        setattr(InheritedControls,name,method)

if __name__=='__main__': unittest.main(verbosity=2)
