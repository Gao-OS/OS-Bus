"""Bounded FD-01/core Unix-socket controller. Runtime requires an isolated guest.

Import is offline: no subprocess, bus, socket or VM is started by the oracles.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
WORKLOAD = json.loads((HERE/'workload.json').read_text())
BUS = 'org.freedesktop.DBus'
PASS = 'passed_independent_fd01_unix_socket_core'
SELECTION = ['FD-01/core/unix-socket/gao', 'FD-01/core/unix-socket/reference']
METRICS = ('connections','authenticating','ingress_messages','ingress_bytes','ingress_fds',
           'egress_messages','egress_bytes','egress_fds','frame_bytes','frame_fds',
           'activation_messages','activation_bytes','activation_fds')
AUTHORITIES = ('GaoBus.Supervisor','GaoBus.Ids','GaoBus.NameRegistry','GaoBus.MatchRules',
               'GaoBus.Policy','GaoBus.Policy.Capability','GaoBus.Limits','GaoBus.Router','GaoBus.Listener')
CAPS = {'global':{'connections':8,'ingress_messages':128,'ingress_bytes':1048576,'ingress_fds':64,
                  'egress_messages':128,'egress_bytes':1048576,'egress_fds':3},
        'uid':{'connections':8,'egress_messages':128,'egress_bytes':1048576,'egress_fds':2},
        'peer':{'ingress_messages':16,'ingress_bytes':262144,'ingress_fds':16,
                'egress_messages':16,'egress_bytes':262144,'egress_fds':16}}
# The unchanged Limits fixture normalizes overrides with candidate16 defaults.
# These are observed expectations, never supplied as new daemon settings.
NORMALIZED_CAPS = {
    'global':{**CAPS['global'],'authenticating':64,'frame_bytes':16777216,'frame_fds':1024,
              'activation_messages':512,'activation_bytes':4194304,'activation_fds':2048},
    'uid':{**CAPS['uid'],'authenticating':16,'ingress_messages':128,'ingress_bytes':1048576,'ingress_fds':512,
           'frame_bytes':4194304,'frame_fds':256,'activation_messages':128,'activation_bytes':1048576,'activation_fds':512},
    'peer':{**CAPS['peer'],'frame_bytes':1048576,'frame_fds':64,
            'activation_messages':32,'activation_bytes':1048576,'activation_fds':128}}
INPUT_KEYS = {'actor','actor_test','qualify','oracle_test','workload','test_nix','readme','scope',
              'channel','transport_actor','quota_daemon','collector','candidate_manifest',
              'python','elixir','erl','beam','reference_executable','runuser'}
FD_KEYS = ('fd','target','dev','ino','mode','pid','uid','gid')


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def integer(value, minimum=0):
    assert type(value) is int and value >= minimum, ('integer',value)


def latency(value, limit):
    assert type(value) in (int,float) and math.isfinite(value) and 0 <= value <= limit, ('deadline',value,limit)


def string(value):
    raw=value.encode()
    return struct.pack('<I',len(raw))+raw+b'\0'


def list_names(body):
    """Decode only this singleton's finite little-endian ListNames `as` body."""
    assert type(body) is bytes and 4<=len(body)<2**21, 'ListNames array body bounds'
    size,=struct.unpack_from('<I',body)
    assert size==len(body)-4, 'ListNames array byte length/trailing data'
    names,offset=[],4
    while offset<len(body):
        aligned=offset+(-offset%4)
        assert not any(body[offset:aligned]) and aligned+4<=len(body), 'ListNames string alignment/bounds'
        size,=struct.unpack_from('<I',body,aligned)
        start=aligned+4;end=start+size
        assert size>0 and end<len(body) and body[end]==0, 'ListNames string length/terminator'
        name=body[start:end].decode('utf8')
        assert '\0' not in name and name not in names, 'ListNames embedded NUL/duplicate'
        names.append(name)
        assert len(names)<=3, 'ListNames singleton name count'
        offset=end+1
    assert offset==len(body), 'ListNames trailing string bytes'
    return names


def parse_frame(raw):
    """Independent strict decoder for the exact bounded singleton wire contract."""
    assert type(raw) is bytes and len(raw)>=16 and raw[0]==ord('l') and raw[3]==1
    assert raw[1] in (1,2,3,4) and raw[2] in (0,1), 'unexpected frame type/flags'
    body_size,serial,header_size=struct.unpack_from('<III',raw,4)
    integer(serial,1)
    assert body_size+header_size < 2**21
    end=16+header_size
    body_start=end+(-header_size%8)
    assert len(raw)==body_start+body_size, 'truncated or trailing wire bytes'
    assert not any(raw[end:body_start]), 'header padding'
    fields,offset={},16
    while offset<end:
        aligned=offset+(-offset%8)
        assert not any(raw[offset:aligned]) and aligned+4<=end
        code,length,sig,nul=raw[aligned:aligned+4]
        assert code in range(1,10) and str(code) not in fields and length==1 and nul==0
        assert chr(sig)=={1:'o',2:'s',3:'s',4:'s',5:'u',6:'s',7:'s',8:'g',9:'u'}[code]
        offset=aligned+4
        if chr(sig) in ('s','o'):
            assert offset+4<=end
            size,=struct.unpack_from('<I',raw,offset)
            assert offset+size+5<=end and raw[offset+4+size]==0
            value=raw[offset+4:offset+4+size].decode('utf8')
            assert '\0' not in value
            offset+=5+size
        elif chr(sig)=='g':
            assert offset<end
            size=raw[offset]
            assert offset+size+2<=end and raw[offset+1+size]==0
            value=raw[offset+1:offset+1+size].decode('ascii')
            assert '\0' not in value
            offset+=2+size
        else:
            assert offset+4<=end
            value,=struct.unpack_from('<I',raw,offset)
            offset+=4
        fields[str(code)]=value
    assert offset==end
    return dict(type=raw[1],serial=serial,fields=fields,body_hex=raw[body_start:].hex(),flags=raw[2])


def assert_fd(row, identity=None):
    assert set(row)>=set(FD_KEYS)
    for key in FD_KEYS:
        if key!='target': integer(row[key],1 if key=='pid' else 0)
    assert type(row['target']) is str and row['target']
    if identity:
        assert all(row[k]==identity[k] for k in ('pid','uid','gid')), 'FD owner mismatch'
    if stat.S_ISSOCK(row['mode']):
        assert row['target']==f"socket:[{row['ino']}]", 'invented socket inode'


def assert_wire(row):
    raw=bytes.fromhex(row['wire_hex'])
    assert hashlib.sha256(raw).hexdigest()==row['wire_sha256'], 'wire digest mismatch'
    assert row['wire_bytes']==len(raw)
    parsed=parse_frame(raw)
    for key,value in parsed.items():
        # Actor records full raw wire bytes; flags are decoded independently.
        # Any additional declared flags value must also agree with those bytes.
        if key!='flags' or key in row: assert row[key]==value, ('wire/receipt mismatch',key)
    integer(row['rights'])
    assert row['rights']==parsed['fields'].get('9',0)
    assert row['phase'] in ('setup','active') and row['direction'] in ('sent','received')
    assert row['role'] in ('source','target')
    if row['direction']=='received':
        assert len(row['fd_targets'])==row['rights']
        for fd in row['fd_targets']: assert_fd(fd)
    return parsed


def assert_process(row):
    for key in ('pid','uid','gid','starttime_ticks','pgid'): integer(row[key],1 if key in ('pid','starttime_ticks','pgid') else 0)
    assert row['kernel_ids']==dict(uids=[row['uid']]*4,gids=[row['gid']]*4)
    assert row['executable'].startswith('/') and row['argv'] and all(type(v) is str for v in row['argv'])
    assert re.fullmatch('[0-9a-f]{64}',row['executable_sha256'])


def assert_inventory(row):
    integer(row['pid'],1); integer(row['count'])
    assert len(row['uids'])==len(row['gids'])==4
    assert len(set(row['uids']))==len(set(row['gids']))==1
    assert len(row['fds'])==row['count']
    assert [fd['fd'] for fd in row['fds']]==sorted({fd['fd'] for fd in row['fds']})
    owner=dict(pid=row['pid'],uid=row['uids'][0],gid=row['gids'][0])
    for fd in row['fds']: assert_fd(fd,owner)


def assert_actor_inventory(receipt, observed):
    assert_inventory(observed)
    assert {k:receipt[k] for k in ('pid','uid','gid')}==dict(pid=observed['pid'],uid=observed['uids'][0],gid=observed['gids'][0])
    assert receipt['fd_state']=={k:observed[k] for k in ('fds','count')}, 'actor/proc inventory mismatch'


def assert_recovered(before, after):
    assert_inventory(before); assert_inventory(after)
    assert before==after, 'numeric FD identities not reclaimed'


def assert_connections(row):
    assert row['uid']==1100 and type(row['pid']) is int
    cs=row['connections']
    assert [c['role'] for c in cs]==['source','target']
    assert len({c['name'] for c in cs})==2 and len({c['socket_fd'] for c in cs})==2
    expected_names={BUS}
    for c in cs:
        assert all(c[k]==row[k] for k in ('pid','uid','gid'))
        assert re.fullmatch(r':[0-9]+\.[0-9]+',c['name'])
        assert c['negotiated'] is True and c['negotiation']['requested'] is True
        assert c['negotiation']['fd_reply']=='AGREE_UNIX_FD'
        assert re.fullmatch(r'OK [0-9a-fA-F]{32}',c['negotiation']['auth_reply'])
        assert_fd(c['socket'],row)
        assert c['socket']['fd']==c['socket_fd'] and stat.S_ISSOCK(c['socket']['mode'])
        expected_names.add(c['name'])
        sent=[]; hello=[]; barrier=[]
        for event in c['setup']:
            parsed=assert_wire(event)
            assert event['phase']=='setup' and event['role']==c['role'] and event['rights']==0
            fields=parsed['fields']
            if event['direction']=='sent':
                assert parsed['flags']==0, 'actor setup writer flags'
                serial=parsed['serial']; assert serial in (1,2) and parsed['type']==1
                member='Hello' if serial==1 else 'ListNames'
                assert fields=={'1':'/org/freedesktop/DBus','2':BUS,'3':member,'6':BUS,'8':''} and parsed['body_hex']==''
                sent.append(serial)
            elif fields.get('5')==1:
                expected={'5':1,'6':c['name'],'7':BUS,'8':'s'}
                assert parsed['type']==2 and (fields==expected or fields=={**expected,'9':0}), 'Hello setup reply identity/signature'
                assert parsed['body_hex']==string(c['name']).hex()
                hello.append(event)
            elif fields.get('5')==2:
                expected={'5':2,'6':c['name'],'7':BUS,'8':'as'}
                assert parsed['type']==2 and (fields==expected or fields=={**expected,'9':0}), 'ListNames setup reply identity/signature'
                names=list_names(bytes.fromhex(parsed['body_hex']))
                assert set(names)==expected_names, 'ListNames setup live names'
                barrier.append(event)
        assert sent==[1,2] and len(hello)==len(barrier)==1 and c['setup'][-1]==barrier[0]


def assert_exercise(row):
    assert row['op']=='exercise' and row['held'] is True
    assert_connections(row)
    source,target=row['connections']
    t=row['transfer']
    assert (t['serial'],t['sender'],t['target'],t['signature'],t['index'],t['header9'],t['rights'])==(
        100,source['name'],target['name'],'h',0,1,1)
    assert t['content']=='SOCKET' and t['content_hex']==b'SOCKET'.hex() and t['content_sha256']==hashlib.sha256(b'SOCKET').hexdigest()
    original,partner,received=[t[k] for k in ('source_fd','partner_fd','received_fd')]
    assert len({fd['fd'] for fd in (original,partner,received)})==3
    for fd in (original,partner,received):
        assert_fd(fd,row); assert stat.S_ISSOCK(fd['mode'])
    assert all(original[k]==received[k] for k in ('dev','ino','mode','target'))
    assert original['ino']!=partner['ino']
    fields={'1':'/foundation','2':'org.foundation.Transport','3':'Resource','6':target['name'],'8':'h','9':1}
    for direction,role in [('sent','source'),('received','target')]:
        event=t[direction]; parsed=assert_wire(event)
        assert event['direction']==direction and event['phase']=='active' and event['role']==role
        expected=fields if direction=='sent' else {**fields,'7':source['name']}
        assert parsed==dict(type=4,serial=100,fields=expected,body_hex='00000000',flags=0)
    assert t['received']['fd_targets']==[received]
    assert [h['role'] for h in row['health']]==['source','target']
    for c,serial,h in zip(row['connections'],(110,111),row['health']):
        assert h['serial']==h['reply_serial']==serial and h['owner']==c['name'] and h['rights']==0
        latency(h['latency_ms'],1000)
        sent=assert_wire(h['sent']); received_wire=assert_wire(h['received'])
        for direction in ('sent','received'):
            assert h[direction]['role']==c['role'] and h[direction]['phase']=='active' and h[direction]['direction']==direction
            assert h[direction]['rights']==0
        assert sent==dict(type=1,serial=serial,fields={'1':'/org/freedesktop/DBus','2':BUS,'3':'GetNameOwner','6':BUS,'8':'s'},body_hex=string(c['name']).hex(),flags=0)
        fields=received_wire['fields']
        assert received_wire['type']==2 and fields.get('5')==serial and fields.get('6')==c['name'] and fields.get('7')==BUS and fields.get('8')=='s'
        assert set(fields)<=set(('5','6','7','8','9')) and fields.get('9',0)==0
        assert received_wire['body_hex']==string(c['name']).hex()
    assert row['fd_state']['count']==len(row['fd_state']['fds'])
    expected=[c['socket'] for c in row['connections']]+[original,partner,received]
    for fd in expected: assert fd in row['fd_state']['fds']


def assert_closed(row, exercise, baseline, op='close'):
    assert row['op']==op and row['connections']==[] and row['held'] is False
    assert row['baseline_equal'] is True and row['fd_growth']==0
    latency(row['latency_ms'],1000)
    assert row['fd_state']==baseline
    assert all(row[k]==exercise[k] for k in ('pid','uid','gid'))
    t=exercise['transfer']
    owned=[('received',t['received_fd']),('original',t['source_fd']),('partner',t['partner_fd'])]
    owned += [(c['role'],c['socket']) for c in exercise['connections']]
    assert row['closure']==[{**fd,'role':role,'closed':True} for role,fd in owned]
    assert set(row['events'])=={'source','target'}
    active={'source':[exercise['health'][0]['received']], 'target':[t['received'],exercise['health'][1]['received']]}
    for c in exercise['connections']:
        assert row['events'][c['role']]==c['setup']+active[c['role']], 'unexpected/skipped active frame'


def assert_native(state, baseline, connections=()):
    assert state['pending']==state['matches']==state['capabilities']==0
    assert state['authorities']==baseline['authorities'] and set(state['authorities'])==set(AUTHORITIES)
    assert all(re.fullmatch(r'#PID<[0-9]+\.[0-9]+\.[0-9]+>',v) for v in state['authorities'].values())
    usage=state['usage']
    assert usage['limits']==NORMALIZED_CAPS and usage['limits']==baseline['usage']['limits']
    assert usage['xml']=={'limits':None,'queues':None,'global':{'incomplete':0,'completed':0},'uids':{}}
    assert usage['reservations']==0
    expected=dict.fromkeys(METRICS,0); expected['connections']=len(connections)
    assert usage['global']==expected
    assert len(state['peers'])==len(connections) and len({p['name'] for p in state['peers']})==len(connections)
    peer_counts={}
    for c in connections:
        p,=[p for p in state['peers'] if p['name']==c['name']]
        assert p['credentials']=={k:c[k] for k in ('pid','uid','gid')} and p['negotiated'] is True
        assert not p.get('departed') and p['queue']==p['buffer_bytes']==0 and p['output'] is None
        peer_counts[p['peer']]={**dict.fromkeys(METRICS,0),'connections':1}
    assert usage['peers']==peer_counts and usage['uids']==({'1100':expected} if connections else {})
    assert sorted(state['names'])==sorted([BUS]+[c['name'] for c in connections])


def native_config():
    return dict(profile='system',socket=WORKLOAD['socket'],config_file=None,cluster=False,capability_restrictions=False,
                send_timeout_ms=5000,resource_limits=CAPS,policy_rules=[dict(action=action,effect='allow',match={'uid':uid})
                for uid in (0,1100,1101) for action in ('connect','send','receive')])


def reference_config(path):
    """Own explicit system-core policy. No FD05 generator or default includes."""
    assert path=='/run/osbus-fd-quotas/bus'
    lines=['<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">',
           '<busconfig>','  <type>system</type>',f'  <listen>unix:path={path}</listen>','  <auth>EXTERNAL</auth>',
           '  <policy context="default">','    <deny user="*"/>','    <allow user="1100"/>',
           '    <deny own="*"/>','    <deny send_destination="*"/>','    <deny receive_sender="*"/>','  </policy>',
           '  <policy user="1100">','    <allow send_destination="*"/>','    <allow receive_sender="*"/>','  </policy>']
    for name,value in [('auth_timeout',10000),('max_incoming_unix_fds',64),('max_outgoing_unix_fds',64),
                       ('max_message_unix_fds',16),('max_connections_per_user',8),('max_completed_connections',8)]:
        lines.append(f'  <limit name="{name}">{value}</limit>')
    return '\n'.join(lines+['</busconfig>',''])


def counts(combinations):
    result=dict(selected=2,executed=0,passed=0,failed=0,blocked=0,skipped=0)
    for c in combinations:
        status=c['status']; assert status in ('running','passed','failed','blocked','skipped')
        if status not in ('blocked','skipped'): result['executed']+=1
        if status in result: result[status]+=1
    return result


def assert_attempts(attempts, sample, limit=1000):
    assert attempts and attempts[-1]['success'] is True and attempts[-1]['sample']==sample
    times=[a['elapsed_ms'] for a in attempts]
    assert times==sorted(times)
    for value in times: latency(value,limit)


def assert_report(report):
    assert (report['schema'],report['requirement'],report['subcase'],report['profile'])==(1,'FD-01','unix-socket','core')
    assert report['not_a_release'] is True and report['result']==PASS
    assert report['workload']==WORKLOAD and report['selection']==SELECTION
    latency(report['elapsed_seconds'],120)
    assert report['inputs_before']==report['inputs_after'] and set(report['inputs_before'])==INPUT_KEYS
    inputs=report['inputs_before']
    for row in inputs.values(): assert row['path'].startswith('/') and re.fullmatch('[0-9a-f]{64}',row['sha256'])
    assert inputs['candidate_manifest']['sha256']==WORKLOAD['candidate_manifest_sha256']
    manifest=report['manifest']
    assert manifest['not_a_release'] is True and len(manifest['files'])==80 and len(manifest['sources'])==71
    assert report['candidate_before']==report['candidate_after']==manifest['files']
    assert_process(report['observer']); assert report['observer']['uid']==0 and report['command'] and report['cwd'].startswith('/')
    assert report['observer']['executable_sha256']==inputs['python']['sha256']
    assert all(k.startswith('DBUS_') for k in report['stripped_dbus_keys'])
    cs=report['combinations']
    assert [c['backend'] for c in cs]==['gao','reference']
    assert report['counts']==counts(cs)==dict(selected=2,executed=2,passed=2,failed=0,blocked=0,skipped=0)
    for c in cs:
        assert c['status']=='passed'
        for key in ('broker','actor','launcher'): assert_process(c[key])
        assert len({c[k]['pid'] for k in ('broker','actor','launcher')}|{report['observer']['pid']})==4
        assert c['actor']['uid']==1100 and c['broker']['uid']==c['launcher']['uid']==0
        assert c['actor']['pgid']==c['launcher']['pid'] and c['broker']['pgid']==c['broker']['pid']
        for key,input_key in [('actor','python'),('broker','beam' if c['backend']=='gao' else 'reference_executable'),('launcher','runuser')]:
            assert c[key]['executable_sha256']==inputs[input_key]['sha256']
        for key,input_key in [('actor','python'),('broker','elixir' if c['backend']=='gao' else 'reference_executable')]:
            v=c['versions'][key]
            assert v['returncode']==0 and v['stdout'] and v['command'][0]==inputs[input_key]['path']
        initial=c['initial']; assert initial['ok'] is True and initial['result']['op']=='ready' and initial['result']['connections']==[]
        assert_actor_inventory(initial['result'],c['before']['actor'])
        for phase in ('before','warmed','connected','checked','closed'):
            for subject in ('actor','broker'):
                assert_inventory(c[phase][subject]); assert c[phase][subject]['pid']==c[subject]['pid']
                assert c[phase][subject]['uids']==c[subject]['kernel_ids']['uids'] and c[phase][subject]['gids']==c[subject]['kernel_ids']['gids']
            if phase!='before': assert_attempts(c[phase+'_attempts'],c[phase])
        assert_recovered(c['before']['actor'],c['warmed']['actor'])
        warm=c['warmup']
        assert warm['op']=='warmup' and warm['connections']==[] and warm['held'] is False and warm['fd_growth']==0
        assert_exercise(warm['exercise'])
        assert_closed(warm['close'],warm['exercise'],initial['result']['fd_state'],'warmup-close')
        assert_actor_inventory(warm,c['warmed']['actor'])
        assert all(warm[k]==c['actor'][k] for k in ('pid','uid','gid'))
        assert_connections(c['open']); assert_exercise(c['exercise'])
        assert c['open']['op']=='open' and c['open']['source']==c['open']['connections'][0] and c['open']['target']==c['open']['connections'][1]
        assert c['open']['connections']==c['exercise']['connections']
        assert_actor_inventory(c['open'],c['connected']['actor']); assert_actor_inventory(c['exercise'],c['checked']['actor'])
        resources=[c['exercise']['transfer'][key] for key in ('source_fd','partner_fd','received_fd')]
        assert len({r['ino'] for r in resources})==2
        assert c['checked']['actor']['fds']==sorted(c['connected']['actor']['fds']+resources,key=lambda r:r['fd'])
        for r in resources:
            assert r in c['checked']['actor']['fds']
            assert not any((fd['dev'],fd['ino'])==(r['dev'],r['ino']) for fd in c['checked']['broker']['fds']), 'broker retained endpoint'
        assert_closed(c['close'],c['exercise'],warm['fd_state'])
        assert_actor_inventory(c['close'],c['closed']['actor'])
        for subject in ('actor','broker'): assert_recovered(c['warmed'][subject],c['closed'][subject])
        for subject in ('actor','broker'):
            assert not any(fd['target'] in {r['target'] for r in resources} for fd in c['closed'][subject]['fds'])
        latency(c['cleanup_elapsed_ms'],1000)
        assert [r['command'] for r in c['operations']]==[{'op':op} for op in ('warmup','open','exercise','close')]
        for operation,key in zip(c['operations'],('warmup','open','exercise','close')):
            assert operation['response']=={'ok':True,'result':c[key]}
            latency(operation['elapsed_ms'],1000 if key=='close' else 10000)
        if c['backend']=='gao':
            assert c['ready']['event']=='ready' and int(c['ready']['pid'])==c['broker']['pid']
            assert c['ready']['profile']=='system' and c['ready']['config_file'] is None and c['ready']['send_timeout_ms']==5000 and c['ready']['resource_limits']==CAPS
            assert c['effective_config']==native_config()
            for phase in ('before','warmed','closed'): assert_native(c[phase]['telemetry'],c['warmed']['telemetry'])
            for phase in ('connected','checked'): assert_native(c[phase]['telemetry'],c['warmed']['telemetry'],c['open']['connections'])
        else:
            assert all('telemetry' not in c[p] for p in ('before','warmed','connected','checked','closed'))
            config=reference_config(WORKLOAD['socket'])
            assert c['reference_config']==c['reference_config_exported']==config
            assert c['reference_config_sha256']==hashlib.sha256(config.encode()).hexdigest()
            assert c['backend_command']==[inputs['reference_executable']['path'],'--nofork','--nopidfile','--config-file='+c['reference_config_path']]
            assert c['ready']==dict(profile='core',pid=c['broker']['pid'],startup_status='running',config_validated_by_startup=True)
            assert_attempts(c['startup_attempts'],c['socket_identity'],10000)
        st=c['teardown']
        assert st['actor']['pid']==c['launcher']['pid'] and st['actor']['method']=='eof' and st['actor']['returncode']==0
        assert st['backend']['pid']==c['broker']['pid']
        if c['backend']=='gao': assert st['backend']['method']=='eof' and st['backend']['returncode']==0 and st['observer_unlink'] is None
        else:
            assert st['backend']['method']=='sigterm' and st['backend']['returncode'] in (0,-15)
            if st['observer_unlink'] is not None:
                unlink=st['observer_unlink']
                assert unlink['matched_inode'] is True and unlink['after_backend_exit'] is True
                assert (unlink['dev'],unlink['ino'])==(c['socket_identity']['dev'],c['socket_identity']['ino'])
        assert all(st[key] is True for key in ('groups_absent','actual_actor_absent','broker_absent','launcher_absent','socket_absent'))
        eof=st['actor_eof']; assert eof['ok'] is True
        final=eof['result']
        assert final['op']=='eof' and final['connections']==final['closure']==[] and final['events']=={} and final['held'] is False
        assert final['baseline_equal'] is True and final['fd_growth']==0 and final['fd_state']==warm['fd_state']
        assert all(final[k]==c['actor'][k] for k in ('pid','uid','gid'))
        latency(final['latency_ms'],1000); latency(st['elapsed_ms'],1000)
        assert st['containment_attempts'] and st['containment_attempts'][-1]['success'] is True
        assert not any(st['containment_attempts'][-1]['sample'].values())


def external(pid):
    root=Path('/proc')/str(pid)
    status={k:v.split() for k,v in (line.split(':',1) for line in (root/'status').read_text().splitlines() if ':' in line)}
    uid,gid=int(status['Uid'][0]),int(status['Gid'][0])
    records=[]
    for entry in sorted((root/'fd').iterdir(),key=lambda p:int(p.name)):
        try:
            target=os.readlink(entry); info=entry.stat()
            records.append(dict(fd=int(entry.name),target=target,dev=info.st_dev,ino=info.st_ino,mode=info.st_mode,pid=pid,uid=uid,gid=gid))
        except FileNotFoundError: pass
    row=dict(pid=pid,uids=list(map(int,status['Uid'])),gids=list(map(int,status['Gid'])),fds=records,count=len(records))
    assert_inventory(row)
    return row


def process_identity(pid):
    root=Path('/proc')/str(pid); inv=external(pid)
    row=dict(pid=pid,uid=inv['uids'][0],gid=inv['gids'][0],executable=os.readlink(root/'exe'),executable_sha256=sha(root/'exe'),
             argv=(root/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
             starttime_ticks=int((root/'stat').read_text().rsplit(')',1)[1].split()[19]),
             kernel_ids=dict(uids=inv['uids'],gids=inv['gids']),pgid=os.getpgid(pid))
    assert_process(row)
    return row


def group_members(group):
    members=[]
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try:
            if os.getpgid(int(entry.name))==group: members.append(int(entry.name))
        except ProcessLookupError: pass
    return sorted(members)


def bounded_poll(probe, accept, limit_ms, attempts):
    started=time.monotonic(); deadline=started+limit_ms/1000
    while True:
        row={}
        try:
            row['sample']=probe(); row['success']=bool(accept(row['sample']))
        except Exception as error: row.update(error=repr(error),success=False)
        row['elapsed_ms']=(time.monotonic()-started)*1000
        attempts.append(row)
        if row['success']:
            assert time.monotonic()<=deadline, 'late bounded observation'
            return row['sample']
        remaining=deadline-time.monotonic(); assert remaining>0, ('bounded observation failed',attempts)
        select.select([],[],[],min(.005,remaining))


def request(actor, operations, op, timeout=10):
    row=dict(command={'op':op},started_monotonic=time.monotonic()); operations.append(row)
    actor.begin(op=op)
    try:
        response=actor.read(timeout=timeout); row['response']=response
        assert response['ok'] is True, response
        return response['result']
    finally: row['elapsed_ms']=(time.monotonic()-row['started_monotonic'])*1000


def version(path):
    command=[str(path),'--version']
    run=subprocess.run(command,capture_output=True,text=True,timeout=10)
    return dict(command=command,returncode=run.returncode,stdout=run.stdout,stderr=run.stderr)


def candidate_inventory(candidate, manifest):
    result={}
    for relative,expected in manifest['files'].items():
        path=candidate/relative
        assert path.is_file() and sha(path)==expected, ('candidate changed',relative)
        mode=manifest['file_modes'][relative]
        if path.is_relative_to('/nix/store'): mode &= ~0o222
        assert stat.S_IMODE(path.stat().st_mode)==mode
        result[relative]=expected
    return result


def capture_inputs(args, manifest):
    runtime=manifest['runtime']; elixir=Path(runtime['elixir_store'])/'bin/elixir'; otp=Path(runtime['otp_store'])
    beam,=list((otp/'lib/erlang').glob('erts-*/bin/beam.smp'))
    paths={name:args.fixtures/file for name,file in [('actor','actor.py'),('actor_test','actor_test.py'),('qualify','qualify.py'),
             ('oracle_test','oracle_test.py'),('workload','workload.json'),('test_nix','test.nix'),('readme','README.md')]}
    paths.update(scope=args.scope,channel=args.helpers/'channel.py',transport_actor=args.wire_dir/'transport_actor.py',
                 quota_daemon=args.quota_daemon,collector=args.collector,candidate_manifest=args.candidate/'candidate.json',
                 python=Path(sys.executable),elixir=elixir,erl=otp/'bin/erl',beam=beam,
                 reference_executable=args.reference_executable,runuser=Path(shutil.which('runuser') or '/missing-runuser'))
    result={}
    for name,path in paths.items():
        assert path.is_absolute() and path.is_file(), ('missing input',name,str(path))
        result[name]=dict(path=str(path),sha256=sha(path))
    return result


def run_backend(args, report, backend, channels, save):
    directory=args.evidence/backend; directory.mkdir()
    c=dict(backend=backend,status='running',operations=[],startup_attempts=[],teardown={},versions={})
    report['combinations'].append(c); save()
    daemon=actor=reference=None; reference_log=None; actor_pid=broker_pid=None
    socket_path=Path(WORKLOAD['socket'])
    try:
        assert not socket_path.exists(), 'occupied private socket'
        inputs=report['inputs_before']
        if backend=='gao':
            command=[inputs['elixir']['path'],'--erl','+S 2:2']
            for path in sorted((args.candidate/'lib').glob('*/ebin')): command+=['-pa',str(path)]
            command += [str(args.quota_daemon),str(socket_path),str(args.collector)]
            c['backend_command']=command; save()
            daemon=channels.Channel(command,directory/'broker.log','FIXTURE ')
            c['ready']=daemon.read(timeout=10)
            broker_pid=daemon.process.pid
            assert int(c['ready']['pid'])==broker_pid and c['ready']['event']=='ready'
            c['effective_config']=native_config()
        else:
            config=reference_config(str(socket_path)); config_path=directory/'reference.conf'; config_path.write_text(config)
            c.update(reference_config=config,reference_config_exported=config_path.read_text(),reference_config_sha256=sha(config_path),reference_config_path=str(config_path))
            command=[inputs['reference_executable']['path'],'--nofork','--nopidfile','--config-file='+str(config_path)]
            c['backend_command']=command; save()
            reference_log=(directory/'broker.log').open('wb')
            reference=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=reference_log,stderr=subprocess.STDOUT,start_new_session=True)
            broker_pid=reference.pid
            def socket_probe():
                assert reference.poll() is None, ('reference startup exit',reference.returncode)
                if not socket_path.exists(): return {}
                info=socket_path.stat(); assert stat.S_ISSOCK(info.st_mode)
                return dict(dev=info.st_dev,ino=info.st_ino,mode=info.st_mode)
            c['socket_identity']=bounded_poll(socket_probe,bool,10000,c['startup_attempts'])
            c['ready']=dict(profile='core',pid=broker_pid,startup_status='running',config_validated_by_startup=True)
        assert socket_path.is_socket()
        if 'socket_identity' not in c:
            info=socket_path.stat(); c['socket_identity']=dict(dev=info.st_dev,ino=info.st_ino,mode=info.st_mode)
        c['broker']=process_identity(broker_pid)
        c['versions']['broker']=version(inputs['elixir' if daemon else 'reference_executable']['path'])
        c['versions']['actor']=version(sys.executable)
        command=[inputs['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir)]
        c['actor_command']=command; save()
        actor=channels.Actor(command,directory/'actor.log')
        c['initial']=actor.read(timeout=10); assert c['initial']['ok'] is True
        actor_pid=c['initial']['result']['pid']
        c['actor']=process_identity(actor_pid); c['launcher']=process_identity(actor.process.pid)
        assert actor_pid!=actor.process.pid and c['actor']['uid']==1100
        def sample(empty=False):
            row={}
            if daemon:
                daemon.process.stdin.write(('metrics\n' if empty else 'inspect\n').encode()); daemon.process.stdin.flush()
                row['telemetry']=daemon.read(timeout=1)
            row.update(broker=external(broker_pid),actor=external(actor_pid))
            return row
        c['before']=sample(True); assert_actor_inventory(c['initial']['result'],c['before']['actor']); save()
        c['warmup']=request(actor,c['operations'],'warmup'); save()
        assert_exercise(c['warmup']['exercise'])
        assert_closed(c['warmup']['close'],c['warmup']['exercise'],c['initial']['result']['fd_state'],'warmup-close')
        def settle(phase, receipt, empty=False):
            attempts=c.setdefault(phase+'_attempts',[])
            def accept(row):
                try:
                    assert_actor_inventory(receipt,row['actor'])
                    if empty: assert_recovered(c['before']['actor'],row['actor'])
                    if daemon:
                        baseline=c.get('warmed',row)['telemetry']
                        assert_native(row['telemetry'],baseline,() if empty else receipt['connections'])
                    if phase=='checked':
                        for key in ('source_fd','partner_fd','received_fd'):
                            resource=receipt['transfer'][key]
                            assert resource in row['actor']['fds']
                            assert not any((fd['dev'],fd['ino'])==(resource['dev'],resource['ino']) for fd in row['broker']['fds'])
                    if phase=='closed':
                        for subject in ('actor','broker'): assert_recovered(c['warmed'][subject],row[subject])
                    return True
                except AssertionError: return False
            return bounded_poll(lambda:sample(empty),accept,1000,attempts)
        c['warmed']=settle('warmed',c['warmup'],True); save()
        c['open']=request(actor,c['operations'],'open'); assert_connections(c['open']); save()
        c['connected']=settle('connected',c['open']); save()
        c['exercise']=request(actor,c['operations'],'exercise'); assert_exercise(c['exercise']); save()
        c['checked']=settle('checked',c['exercise']); save()
        started=time.monotonic()
        c['close']=request(actor,c['operations'],'close',timeout=1); save()
        # Close and external reclamation share the same absolute 1000 ms budget.
        remaining=1000-(time.monotonic()-started)*1000; assert remaining>0
        c['closed_attempts']=[]
        def accept_closed(row):
            try:
                assert_actor_inventory(c['close'],row['actor'])
                for subject in ('actor','broker'): assert_recovered(c['warmed'][subject],row[subject])
                if daemon: assert_native(row['telemetry'],c['warmed']['telemetry'])
                return True
            except AssertionError: return False
        c['closed']=bounded_poll(lambda:sample(True),accept_closed,remaining,c['closed_attempts'])
        c['cleanup_elapsed_ms']=(time.monotonic()-started)*1000
        assert_closed(c['close'],c['exercise'],c['warmup']['fd_state'])
        c['status']='passed'; save()
    except Exception as error:
        c.update(status='failed',error=repr(error)); save()
    finally:
        started=time.monotonic(); st=c['teardown']
        try:
            if actor:
                st['actor']=actor.stop(grace=1)
                lines=(directory/'actor.log').read_text().splitlines()
                st['actor_eof']=json.loads(lines[-1])
        except Exception as error: st['actor_error']=repr(error)
        try:
            if daemon: st['backend']=daemon.stop(grace=1)
            elif reference:
                reference.send_signal(signal.SIGTERM)
                try: reference.wait(timeout=max(.001,1-(time.monotonic()-started)))
                except subprocess.TimeoutExpired:
                    os.killpg(reference.pid,signal.SIGKILL); reference.wait(timeout=1)
                    st['backend_timeout']=True
                st['backend']=dict(pid=reference.pid,method='kill' if st.get('backend_timeout') else 'sigterm',returncode=reference.returncode,command=reference.args)
                reference_log.close()
        except Exception as error: st['backend_error']=repr(error)
        groups=[p.process.pid for p in (actor,daemon) if p]
        if reference: groups.append(reference.pid)
        st['containment_attempts']=[]
        try:
            def probe():
                rows={str(g):group_members(g) for g in groups}
                for group,pids in rows.items():
                    if pids:
                        try: os.killpg(int(group),signal.SIGKILL)
                        except ProcessLookupError: pass
                return rows
            bounded_poll(probe,lambda rows:not any(rows.values()),max(.001,1000-(time.monotonic()-started)*1000),st['containment_attempts'])
            st['groups_absent']=True
        except Exception as error: st.update(groups_absent=False,containment_error=repr(error))
        st['actual_actor_absent']=actor_pid is not None and not (Path('/proc')/str(actor_pid)).exists()
        st['broker_absent']=broker_pid is not None and not (Path('/proc')/str(broker_pid)).exists()
        st['launcher_absent']=actor is not None and not (Path('/proc')/str(actor.process.pid)).exists()
        st['observer_unlink']=None
        if backend=='reference' and reference and reference.poll() is not None and socket_path.exists():
            info=socket_path.stat(); owned=c.get('socket_identity',{})
            matched=stat.S_ISSOCK(info.st_mode) and (info.st_dev,info.st_ino)==(owned.get('dev'),owned.get('ino'))
            st['observer_unlink']=dict(matched_inode=matched,after_backend_exit=True,dev=info.st_dev,ino=info.st_ino)
            if matched: socket_path.unlink()
        st['socket_absent']=not socket_path.exists(); st['elapsed_ms']=(time.monotonic()-started)*1000
        stop=st.get('backend',{}); actor_stop=st.get('actor',{})
        success=(stop.get('method')=='eof' and stop.get('returncode')==0 if backend=='gao' else stop.get('method')=='sigterm' and stop.get('returncode') in (0,-15))
        if not (success and actor_stop.get('method')=='eof' and actor_stop.get('returncode')==0 and st.get('actor_eof',{}).get('ok') is True
                and all(st.get(k) is True for k in ('groups_absent','actual_actor_absent','broker_absent','launcher_absent','socket_absent')) and st['elapsed_ms']<=1000):
            c['status']='failed'; c.setdefault('error','owned teardown acceptance failed')
        if backend=='reference' and 'reference_config_path' in c:
            try:
                c['reference_config_exported']=Path(c['reference_config_path']).read_text()
                assert c['reference_config_exported']==c['reference_config'] and sha(c['reference_config_path'])==c['reference_config_sha256']
            except Exception as error: c.update(status='failed',config_error=repr(error))
        save()
    return c['status']=='passed'


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope'):
        parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args(argv)
    assert os.geteuid()==0 and Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n', 'isolated guest only'
    assert str(args.evidence)=='/run/osbus-fd-quotas' and WORKLOAD['socket']=='/run/osbus-fd-quotas/bus'
    assert args.fixtures.resolve()==HERE and args.reference_executable.is_absolute() and str(args.reference_executable).startswith('/nix/store/')
    assert not (args.evidence/'bus').exists() and not (args.evidence/'report.json').exists(), 'occupied guest evidence'
    stripped=sorted(k for k in os.environ if k.startswith('DBUS_'))
    for key in stripped: del os.environ[key]
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    assert sha(args.candidate/'candidate.json')==WORKLOAD['candidate_manifest_sha256']
    manifest=json.loads((args.candidate/'candidate.json').read_text())
    assert manifest['not_a_release'] is True and len(manifest['files'])==80 and len(manifest['sources'])==71
    inputs=capture_inputs(args,manifest); candidate=candidate_inventory(args.candidate,manifest)
    spec=importlib.util.spec_from_file_location('fd01_readonly_channel',args.helpers/'channel.py')
    channels=importlib.util.module_from_spec(spec); spec.loader.exec_module(channels)
    args.evidence.mkdir(exist_ok=True)
    report=dict(schema=1,requirement='FD-01',subcase='unix-socket',profile='core',not_a_release=True,result='running',selection=SELECTION,
                workload=WORKLOAD,manifest=manifest,inputs_before=inputs,candidate_before=candidate,cwd=os.getcwd(),
                command=[sys.executable,'-B',str(HERE/'qualify.py'),*(argv if argv is not None else sys.argv[1:])],
                observer=process_identity(os.getpid()),stripped_dbus_keys=stripped,combinations=[],started_monotonic=time.monotonic())
    def save():
        report['counts']=counts(report['combinations'])
        (args.evidence/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    save()
    try:
        for backend in ('gao','reference'):
            if not run_backend(args,report,backend,channels,save):
                report['combinations'] += [dict(backend=b,status='blocked',reason='prior backend failure') for b in ('gao','reference')[len(report['combinations']):]]
                raise AssertionError('FD01 slice stopped on backend failure')
        report['result']=PASS
    except Exception as error: report.update(result='failed',error=repr(error))
    finally:
        try:
            report['inputs_after']=capture_inputs(args,manifest); report['candidate_after']=candidate_inventory(args.candidate,manifest)
        except Exception as error: report.update(result='failed',hash_error=repr(error))
        report['elapsed_seconds']=time.monotonic()-report['started_monotonic']
        save()
        try: assert_report(report)
        except Exception as error: report.update(result='failed',completion_error=repr(error))
        save()
    assert report['result']==PASS, report
    print(json.dumps(dict(result=PASS,counts=report['counts'],not_a_release=True)))


if __name__=='__main__': main()
