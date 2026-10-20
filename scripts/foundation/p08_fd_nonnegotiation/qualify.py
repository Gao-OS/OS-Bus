"""Independent FD-05 core controller and strict offline receipt oracle.

Runtime entry is confined to the disposable guest. Importing this module is pure.
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
import socket
import stat
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
WORKLOAD = json.loads((HERE / 'workload.json').read_text())
BUS = 'org.freedesktop.DBus'
METRICS = ('connections', 'authenticating', 'ingress_messages', 'ingress_bytes',
           'ingress_fds', 'egress_messages', 'egress_bytes', 'egress_fds', 'frame_bytes',
           'frame_fds', 'activation_messages', 'activation_bytes', 'activation_fds')
AUTHORITIES = ('GaoBus.Supervisor', 'GaoBus.Ids', 'GaoBus.NameRegistry', 'GaoBus.MatchRules',
               'GaoBus.Policy', 'GaoBus.Policy.Capability', 'GaoBus.Limits', 'GaoBus.Router', 'GaoBus.Listener')
CAPS = {'global': {'connections': 8, 'ingress_messages': 128, 'ingress_bytes': 1048576,
                  'ingress_fds': 64, 'egress_messages': 128, 'egress_bytes': 1048576, 'egress_fds': 3},
        'uid': {'connections': 8, 'egress_messages': 128, 'egress_bytes': 1048576, 'egress_fds': 2},
        'peer': {'ingress_messages': 16, 'ingress_bytes': 262144, 'ingress_fds': 16,
                 'egress_messages': 16, 'egress_bytes': 262144, 'egress_fds': 16}}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def integer(value, minimum=0):
    assert type(value) is int and value >= minimum, ('invalid integer', value)
    return value


def latency(value, limit):
    assert type(value) in (int, float) and math.isfinite(value) and 0 <= value <= limit, ('deadline', value, limit)


def string(value):
    raw = value.encode()
    return struct.pack('<I', len(raw)) + raw + b'\0'


def parse_frame(raw):
    """Parse exactly one bounded little-endian D-Bus frame, rejecting ambiguity."""
    assert type(raw) is bytes and len(raw) >= 16 and raw[0] == ord('l') and raw[3] == 1
    assert raw[1] in (1, 2, 3, 4)
    body_size, serial, header_size = struct.unpack_from('<III', raw, 4)
    integer(serial, 1)
    assert body_size + header_size < 2**21
    body_offset = 16 + header_size + (-header_size % 8)
    assert len(raw) == body_offset + body_size, 'truncated/trailing frame'
    assert not any(raw[16+header_size:body_offset]), 'nonzero header padding'
    fields, offset = {}, 16
    end = 16 + header_size
    while offset < end:
        aligned = offset + (-offset % 8)
        assert not any(raw[offset:aligned]) and aligned + 4 <= end
        offset = aligned
        code, length, sig, nul = raw[offset:offset+4]
        assert code in range(1,10) and str(code) not in fields and length == 1 and nul == 0, 'duplicate/malformed field'
        assert chr(sig)=={1:'o',2:'s',3:'s',4:'s',5:'u',6:'s',7:'s',8:'g',9:'u'}[code], 'wrong header field signature'
        offset += 4
        if sig in (ord('s'), ord('o')):
            assert offset+4 <= end
            size, = struct.unpack_from('<I', raw, offset)
            assert offset+5+size <= end and raw[offset+4+size] == 0
            value=raw[offset+4:offset+4+size].decode('utf8')
            assert '\0' not in value
            offset += 5+size
        elif sig == ord('g'):
            assert offset < end
            size=raw[offset]
            assert offset+2+size <= end and raw[offset+1+size] == 0
            value=raw[offset+1:offset+1+size].decode('ascii')
            offset += 2+size
        else:
            assert sig == ord('u') and offset+4 <= end
            value,=struct.unpack_from('<I',raw,offset)
            offset+=4
        fields[str(code)]=value
    assert offset == end
    return dict(type=raw[1],serial=serial,fields=fields,body_hex=raw[body_offset:].hex())


def assert_wire(row):
    raw=bytes.fromhex(row['wire_hex'])
    assert hashlib.sha256(raw).hexdigest() == row['wire_sha256'], 'wire hash mismatch'
    parsed=parse_frame(raw)
    for key,value in parsed.items():
        if key in row:
            assert row[key] == value, ('fabricated wire receipt',key)
    integer(row['rights'])
    assert parsed['fields'].get('9',0) == row['rights'], 'right count/header mismatch'
    if 'wire_bytes' in row:
        assert row['wire_bytes'] == len(raw)
    if 'fd_targets' in row:
        assert len(row['fd_targets'])==row['rights']
        for fd in row['fd_targets']:
            for key in ('fd','dev','ino','mode','size'): integer(fd[key])
    return {**parsed,'role':row['role'],'rights':row['rights']}


def assert_process(row):
    integer(row['pid'],1); integer(row['uid']); integer(row['gid']); integer(row['starttime_ticks'],1)
    assert row['executable'].startswith('/') and row['argv'] and all(type(v) is str for v in row['argv'])
    assert row['kernel_ids'] == dict(uids=[row['uid']]*4,gids=[row['gid']]*4), 'kernel identity mismatch'
    assert len(row['executable_sha256']) == 64


def assert_inventory(row):
    integer(row['pid'],1); integer(row['fds'])
    assert len(row['targets']) == row['fds'] and type(row['memfds']) is list
    assert row['memfds'] == sorted(v for v in row['targets'] if '/memfd:' in v), 'fabricated memfd census'
    assert len(row['uids']) == len(row['gids']) == 4
    for value in row['uids']+row['gids']: integer(value)


def assert_recovered(before, after):
    assert_inventory(before); assert_inventory(after)
    for key in ('pid','uids','gids','fds'): assert before[key] == after[key], ('numeric inventory leak',key)
    assert before['memfds'] == after['memfds'] == [], 'memfd leak'


def assert_connections(row):
    p=row['process']
    integer(p['starttime_ticks'],1)
    assert p['executable'].startswith('/') and p['argv']
    assert p['kernel_ids']['Uid']==[row['uid']]*4 and p['kernel_ids']['Gid']==[row['gid']]*4
    assert {k:row[k] for k in ('pid','uid','gid')} == {k:row['process'][k] for k in ('pid','uid','gid')}
    assert row['uid'] == WORKLOAD['actor_uid']
    roles=['source','target','ordinary']
    connections=row['connections']
    assert [c['role'] for c in connections] == roles and len({c['name'] for c in connections}) == len(roles)
    for c in connections:
        assert c['name'] == c['unique_name'] and c['name'].startswith(':')
        assert {k:c[k] for k in ('pid','uid','gid')} == {k:row[k] for k in ('pid','uid','gid')}, 'invented client processes'
        negotiated=c['role'] != 'ordinary'
        assert c['negotiated'] is negotiated and c['negotiation']['requested'] is negotiated
        auth=c['negotiation']['auth_reply']
        assert auth.startswith('OK ') and len(auth)==35
        assert c['negotiation']['fd_reply'] == ('AGREE_UNIX_FD' if negotiated else None)
    return {c['role']:c['name'] for c in connections}


def assert_reply(row, role, name, serial, body=None):
    assert row['role']==role and row['type']==2 and row['rights']==0
    f=row['fields']
    assert f.get('5')==serial and f.get('6')==name and f.get('7')==BUS and f.get('9',0)==0
    if body is not None:
        assert f.get('8')=='s' and row['body_hex']==body.hex(), 'wrong healthy reply'


def assert_exercise(row):
    assert row['case'] in WORKLOAD['cases']
    names=assert_connections(row)
    sent=[assert_wire(v) for v in row['sent']]
    received=[assert_wire(v) for v in row['received']]
    health=row['health']; barriers=row['barriers']
    assert row['assertions']['strict_first_message'] is True and row['assertions']['actor_fd_growth']==0
    # Stream order is per connection, not imposed across independent sockets.
    streams={role:[r for r in received if r['role']==role] for role in names}
    assert sum(map(len,streams.values()))==len(received), 'unknown receiving role'
    expected_health=([('ordinary',4),('source',5)] if row['case']=='unicast' else
                     [('source',110),('target',111),('ordinary',112),('source',210),('target',211),('ordinary',212)])
    assert [(h['role'],h['serial']) for h in health]==expected_health, 'incomplete/duplicate health'
    for h in health: latency(h['latency_ms'],WORKLOAD['healthy_ms'])
    assert row['assertions']['healthy_replies']==len(expected_health)
    if row['case']=='unicast':
        assert len(sent)==3 and len(received)==3 and barriers==[]
        resource=sent[0]
        assert resource['role']=='source' and resource['type']==1 and resource['serial']==3 and resource['rights']==1
        f=resource['fields']
        assert {k:f.get(k) for k in ('1','2','3','6','8','9')} == {'1':'/foundation','2':'org.foundation.Transport','3':'Resource','6':names['ordinary'],'8':'h','9':1}
        assert resource['body_hex']==bytes(4).hex()
        error=streams['source'][0]
        assert error['type']==3 and error['rights']==0
        f=error['fields']
        assert f.get('4')==WORKLOAD['unicast']['error'] and f.get('5')==3 and f.get('6')==names['source'] and f.get('7')==BUS
        assert_reply(streams['ordinary'][0],'ordinary',names['ordinary'],4,string(names['ordinary']))
        assert_reply(streams['source'][1],'source',names['source'],5,string(names['source']))
        assert streams['target']==[]
        assert row['error_name']==WORKLOAD['unicast']['error'] and row['error_reply_serial']==3
        assert len(row['resources'])==1
        r=row['resources'][0]; contents=b'DO-NOT-DELIVER'
        assert r['role']=='source' and r['target'].startswith('pipe:[') and stat.S_ISFIFO(r['mode'])
        assert r['contents_hex']==contents.hex() and r['contents_sha256']==hashlib.sha256(contents).hexdigest() and r['closed'] is True
        for key in ('fd','dev','ino','mode','size'): integer(r[key])
        assert row['assertions']['resource_deliveries']==row['assertions']['rights0_deliveries']==0
    else:
        assert len(sent)==10 and len(received)==11
        assert [b['serial'] for b in barriers]==[101,201]
        for b in barriers: latency(b['latency_ms'],WORKLOAD['socket_ms'])
        assert len(streams['source'])==4 and len(streams['target'])==4 and len(streams['ordinary'])==3
        for r,serial,member,sig,body,rights in [(streams['target'][0],100,'Resource','h',bytes(4),1),
                                               (streams['target'][2],200,'Plain','s',string('RIGHTS0-BROADCAST'),0),
                                               (streams['ordinary'][1],200,'Plain','s',string('RIGHTS0-BROADCAST'),0)]:
            f=r['fields']
            assert r['type']==4 and r['serial']==serial and r['rights']==rights and r['body_hex']==body.hex()
            assert {k:f.get(k) for k in ('1','2','3','7','8')} == {'1':'/broadcast','2':'org.foundation.Broadcast','3':member,'7':names['source'],'8':sig}
            assert f.get('6') is None
        for i,serial in [(0,101),(2,201)]: assert_reply(streams['source'][i],'source',names['source'],serial)
        for role,indices in [('source',(1,3)),('target',(1,3)),('ordinary',(0,2))]:
            offset=['source','target','ordinary'].index(role)
            for index,serial in zip(indices,(110+offset,210+offset)):
                assert_reply(streams[role][index],role,names[role],serial,string(names[role]))
        assert row['assertions']['resource_deliveries']==1 and row['assertions']['rights0_deliveries']==2
        resources=row['resources']
        assert len(resources)==2 and [r['role'] for r in resources]==['source','target']
        assert resources[0]['dev']==resources[1]['dev'] and resources[0]['ino']==resources[1]['ino']
        for resource in resources:
            assert resource['closed'] is True and resource['contents_hex']==WORKLOAD['mixed']['contents'].encode().hex()
            assert stat.S_ISREG(resource['mode'])
            assert resource['target']==f"/memfd:foundation-broadcast-{row['pid']} (deleted)"
            assert resource['size']==len(WORKLOAD['mixed']['contents'])
            assert resource['contents_sha256']==hashlib.sha256(WORKLOAD['mixed']['contents'].encode()).hexdigest()
        r=resources[1]; contents=WORKLOAD['mixed']['contents'].encode()
        assert r['role']=='target' and r['target']==f"/memfd:foundation-broadcast-{row['pid']} (deleted)"
        assert r['closed'] is True and r['size']==len(contents) and r['contents_hex']==contents.hex()
        assert r['contents_sha256']==hashlib.sha256(contents).hexdigest()
        for key in ('fd','dev','ino','mode'): integer(r[key])
        broadcasts=[s for s in sent if s['type']==4]
        assert len(broadcasts)==2
        for s,serial,member,sig,body,rights in [(broadcasts[0],100,'Resource','h',bytes(4),1),(broadcasts[1],200,'Plain','s',string('RIGHTS0-BROADCAST'),0)]:
            assert s['role']=='source' and s['serial']==serial and s['rights']==rights and s['body_hex']==body.hex()
            f=s['fields']; assert f.get('1')=='/broadcast' and f.get('2')=='org.foundation.Broadcast' and f.get('3')==member and f.get('8')==sig and '6' not in f
    calls=[s for s in sent if s['fields'].get('3')=='GetNameOwner']
    assert [(s['role'],s['serial']) for s in calls]==expected_health
    for s in calls:
        assert s['type']==1 and s['rights']==0 and s['fields'].get('6')==BUS and s['fields'].get('8')=='s'
        assert s['body_hex']==string(names[s['role']]).hex()
        assert s['fields'].get('1')=='/org/freedesktop/DBus' and s['fields'].get('2')==BUS
    barrier_calls=[s for s in sent if s['fields'].get('3')=='ListNames']
    assert [s['serial'] for s in barrier_calls]==[b['serial'] for b in barriers]
    for s in barrier_calls:
        assert s['role']=='source' and s['type']==1 and s['rights']==0 and s['body_hex']==''
        assert s['fields'].get('1')=='/org/freedesktop/DBus' and s['fields'].get('2')==BUS and s['fields'].get('6')==BUS and s['fields'].get('8')==''



def assert_actor_inventory(receipt, observed):
    assert {k:receipt[k] for k in ('pid','uid','gid')}==dict(pid=observed['pid'],uid=observed['uids'][0],gid=observed['gids'][0])
    rows=receipt['fds']['targets']
    assert receipt['fds']['count']==len(rows)==observed['fds']
    assert len({r['fd'] for r in rows})==len(rows)
    assert sorted(r['target'] for r in rows)==observed['targets']
    for r in rows:
        for key in ('fd','dev','ino','mode','size'): integer(r[key])


def assert_warmup(row):
    assert row['usable_transfer'] is True and row['closed'] is True and row['connections']==[] and row['actor_fd_growth']==0
    connections=row['warmup_connections']
    assert [c['role'] for c in connections]==['source','target']
    for c in connections:
        assert {k:c[k] for k in ('pid','uid','gid')}=={k:row[k] for k in ('pid','uid','gid')}
        assert c['negotiated'] is True and c['negotiation']['requested'] is True
        assert c['negotiation']['fd_reply']=='AGREE_UNIX_FD' and c['negotiation']['auth_reply'].startswith('OK ')
    names={c['role']:c['name'] for c in connections}
    sent=[assert_wire(r) for r in row['sent'] if r.get('phase')!='setup']
    received_rows=[r for r in row['received'] if r.get('phase')!='setup']
    received=[assert_wire(r) for r in received_rows]
    assert len(sent)==len(received)==3 and row['barriers']==[]
    resource=sent[0]; f=resource['fields']
    assert resource['role']=='source' and resource['type']==4 and resource['serial']==100 and resource['rights']==1
    assert f.get('1')=='/broadcast' and f.get('2')=='org.foundation.Broadcast' and f.get('3')=='Resource' and f.get('6')==names['target'] and f.get('8')=='h' and f.get('9')==1
    assert resource['body_hex']==bytes(4).hex()
    resource=received[0]; f=resource['fields']
    assert resource['role']=='target' and resource['type']==4 and resource['serial']==100 and resource['rights']==1 and resource['body_hex']==bytes(4).hex()
    assert f.get('1')=='/broadcast' and f.get('2')=='org.foundation.Broadcast' and f.get('3')=='Resource' and f.get('6')==names['target'] and f.get('7')==names['source'] and f.get('8')=='h' and f.get('9')==1
    assert [(h['role'],h['serial']) for h in row['health']]==[('source',110),('target',111)]
    for index,(role,serial) in enumerate([('source',110),('target',111)],1):
        assert_reply(received[index],role,names[role],serial,string(names[role]))
        assert sent[index]['role']==role and sent[index]['serial']==serial and sent[index]['fields'].get('3')=='GetNameOwner' and sent[index]['rights']==0
        assert sent[index]['body_hex']==string(names[role]).hex()
        latency(row['health'][index-1]['latency_ms'],1000)
    resources=row['resources']; assert len(resources)==2 and [r['role'] for r in resources]==['source','target']
    assert resources[0]['dev']==resources[1]['dev'] and resources[0]['ino']==resources[1]['ino']
    contents=WORKLOAD['mixed']['contents'].encode()
    for r in resources:
        assert r['target']==f"/memfd:foundation-broadcast-{row['pid']} (deleted)" and stat.S_ISREG(r['mode'])
        assert r['closed'] is True and r['size']==len(contents) and r['contents_hex']==contents.hex() and r['contents_sha256']==hashlib.sha256(contents).hexdigest()
    if 'fd_targets' in received_rows[0]:
        observed=received_rows[0]['fd_targets']; assert len(observed)==1
        assert all(observed[0][k]==resources[1][k] for k in ('fd','target','dev','ino','mode','size'))

def assert_native(state, baseline, connections=(), matches=0):
    assert state['pending']==0 and state['capabilities']==0
    assert state['authorities']==baseline['authorities'] and set(state['authorities'])==set(AUTHORITIES)
    assert all(type(v) is str and re.fullmatch(r'#PID<[0-9]+\.[0-9]+\.[0-9]+>',v) for v in state['authorities'].values())
    usage=state['usage']; assert usage['xml']['limits'] is None and usage['xml']['queues'] is None
    assert usage['reservations']==0 and set(usage['global'])==set(METRICS)
    for scope,values in CAPS.items():
        for key,value in values.items(): assert usage['limits'][scope][key]==value
    peers=state['peers']
    assert len(peers)==len(connections) and len({p['name'] for p in peers})==len(peers)
    expected_counts={k:0 for k in METRICS}; expected_counts['connections']=len(peers)
    assert usage['global']==expected_counts, 'transient credit retained'
    assert state['matches']==matches
    expected_peers={}
    for c in connections:
        p,=[p for p in peers if p['name']==c['name']]
        assert p['credentials']=={k:c[k] for k in ('pid','uid','gid')} and p['negotiated'] is c['negotiated']
        assert not p.get('departed') and p['queue']==p['buffer_bytes']==0 and p['output'] is None
        expected_peers[p['peer']]={**dict.fromkeys(METRICS,0),'connections':1}
    assert usage['peers']==expected_peers
    assert usage['uids']==({'1100':expected_counts} if peers else {})


def native_config():
    return dict(profile='system',socket=WORKLOAD['socket'],config_file=None,cluster=False,capability_restrictions=False,send_timeout_ms=5000,resource_limits=CAPS,
                policy_rules=[dict(action=action,effect='allow',match={'uid':uid}) for uid in (0,1100,1101) for action in ('connect','send','receive')])


def counts(combinations):
    result=dict(selected=2,executed=0,passed=0,failed=0,blocked=0,skipped=0)
    for c in combinations:
        status=c['status']; assert status in ('running','passed','failed','blocked','skipped')
        if status not in ('blocked','skipped'): result['executed']+=1
        if status in result: result[status]+=1
    return result


def assert_report(report):
    assert report['schema']==1 and report['requirement']=='FD-05' and report['profile']=='core'
    assert report['not_a_release'] is True
    latency(report['elapsed_seconds'],WORKLOAD['guest_seconds'])
    assert report['workload']==WORKLOAD and report['selection']==['FD-05/core/gao','FD-05/core/reference']
    assert report['inputs_before']==report['inputs_after'] and report['inputs_before'], 'input mutation'
    required={'actor','actor_test','qualify','oracle_test','workload','test_nix','readme','scope','channel','transport_actor','broadcast_actor','quota_daemon','collector','candidate_manifest','python','elixir','erl','beam','reference_executable','runuser'}
    assert set(report['inputs_before'])>=required
    for row in report['inputs_before'].values():
        assert row['path'].startswith('/') and len(row['sha256'])==64
    assert report['inputs_before']['candidate_manifest']['sha256']==WORKLOAD['candidate_manifest_sha256']
    manifest=report['manifest']
    assert manifest['not_a_release'] is True and len(manifest['files'])==80 and len(manifest['sources'])==71
    assert report['candidate_before']==report['candidate_after']==manifest['files']
    assert report['command'] and report['observer']['uid']==0
    assert all(key.startswith('DBUS_') for key in report['stripped_dbus_keys'])
    assert_process(report['observer'])
    combos=report['combinations']
    assert [c['backend'] for c in combos]==WORKLOAD['backends']
    assert report['counts']==counts(combos)==dict(selected=2,executed=2,passed=2,failed=0,blocked=0,skipped=0)
    for c in combos:
        assert c['status']=='passed'
        for key in ('broker','actor','launcher'): assert_process(c[key])
        pids=[c[k]['pid'] for k in ('broker','actor','launcher')]+[report['observer']['pid']]
        assert len(set(pids))==4, 'wrong actual process identity'
        assert c['actor']['uid']==1100 and c['broker']['uid']==0
        for identity,input_key in [(c['actor'],'python'),(c['launcher'],'runuser'),(c['broker'],'beam' if c['backend']=='gao' else 'reference_executable')]:
            assert identity['executable_sha256']==report['inputs_before'][input_key]['sha256'], 'executable binding mismatch'
        assert c['actor']['pgid']==c['launcher']['pid'] and c['broker']['pgid']==c['broker']['pid']
        assert c['versions']['actor']['returncode']==0 and c['versions']['broker']['returncode']==0
        assert c['versions']['actor']['stdout'] and c['versions']['broker']['stdout']
        assert c['versions']['actor']['command'][0]==report['inputs_before']['python']['path']
        assert c['versions']['broker']['command'][0]==report['inputs_before']['elixir' if c['backend']=='gao' else 'reference_executable']['path']
        for phase in ('before','warmed'):
            for subject in ('broker','actor'): assert_inventory(c[phase][subject])
        assert_recovered(c['before']['actor'],c['warmed']['actor'])
        warm=c['warmup']
        assert_warmup(warm)
        assert warm['pid']==c['actor']['pid'] and warm['connections']==[]
        assert warm['fds']['count']==c['warmed']['actor']['fds']
        assert warm['resources'] and all(r['closed'] is True and r['contents_hex'] for r in warm['resources'])
        if c['backend']=='gao':
            assert c['ready']['send_timeout_ms']==5000 and c['ready']['resource_limits']==CAPS
            assert c['ready']['config_file'] is None and c['ready']['profile']=='system'
            assert c['effective_config']==native_config()
            assert_native(c['warmed']['telemetry'],c['warmed']['telemetry'])
        else:
            assert c['reference_config']==reference_config(WORKLOAD['socket']) and c['ready']['profile']=='core'
            assert 'telemetry' not in c['warmed']
        assert [case['name'] for case in c['cases']]==WORKLOAD['cases'], 'incomplete/duplicate cases'
        for case in c['cases']:
            assert case['status']=='passed' and case['open']['case']==case['exercise']['case']==case['name']
            assert_connections(case['open']); assert_exercise(case['exercise'])
            assert case['open']['connections']==case['exercise']['connections']
            assert case['open']['pid']==case['exercise']['pid']==c['actor']['pid']
            for phase in ('connected','checked'):
                attempts=case[phase+'_attempts']; assert attempts and attempts[-1]['sample']==case[phase] and attempts[-1]['success'] is True
                for a in attempts: latency(a['elapsed_ms'],1000)
            for phase in ('connected','checked','closed'):
                for subject in ('broker','actor'): assert_inventory(case[phase][subject])
                assert case[phase]['actor']['pid']==c['actor']['pid'] and case[phase]['broker']['pid']==c['broker']['pid']
            assert_recovered(case['connected']['actor'],case['checked']['actor'])
            assert_recovered(c['warmed']['broker'],case['closed']['broker'])
            assert_recovered(c['warmed']['actor'],case['closed']['actor'])
            latency(case['cleanup_elapsed_ms'],1000)
            assert case['close']['connections']==[] and case['close']['closed'] is True
            assert case['close']['fds']['count']==case['closed']['actor']['fds']
            attempts=case['cleanup_attempts']; assert attempts
            assert [a['elapsed_ms'] for a in attempts]==sorted(a['elapsed_ms'] for a in attempts)
            for a in attempts: latency(a['elapsed_ms'],1000)
            assert attempts[-1]['sample']==case['closed'] and attempts[-1]['success'] is True
            if c['backend']=='gao':
                for phase in ('connected','checked'): assert_native(case[phase]['telemetry'],c['warmed']['telemetry'],case['open']['connections'],2 if case['name']=='mixed' else 0)
                assert_native(case['closed']['telemetry'],c['warmed']['telemetry'])
            else:
                assert all('telemetry' not in case[p] for p in ('connected','checked','closed'))
        stop=c['teardown']
        assert stop['actor']['method']=='eof' and stop['actor']['returncode']==0
        assert stop['actor']['pid']==c['launcher']['pid']
        assert stop['backend']['pid']==c['broker']['pid']
        if c['backend']=='gao': assert stop['backend']['method']=='eof' and stop['backend']['returncode']==0
        else: assert stop['backend']['method']=='sigterm' and stop['backend']['returncode'] in (0,-15)
        assert stop['groups_absent'] is True and stop['socket_absent'] is True
        assert stop['actual_actor_absent'] is True
        if c['backend']=='gao': assert stop['observer_unlink'] is None
        elif stop['observer_unlink'] is not None:
            assert stop['observer_unlink']['matched_inode'] is True and stop['observer_unlink']['after_backend_exit'] is True
    assert report['result']=='passed_independent_fd05_core'


def reference_config(path):
    assert path==WORKLOAD['socket']
    # Explicit private core transport, no includes, no service dirs/activation.
    return f'''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path={path}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <deny user="*"/>
    <allow user="1100"/>
    <deny own="*"/>
    <deny send_destination="*"/>
    <deny receive_sender="*"/>
  </policy>
  <policy user="1100">
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
  <limit name="auth_timeout">10000</limit>
  <limit name="max_incoming_unix_fds">64</limit>
  <limit name="max_outgoing_unix_fds">64</limit>
  <limit name="max_message_unix_fds">16</limit>
  <limit name="max_connections_per_user">8</limit>
  <limit name="max_completed_connections">8</limit>
</busconfig>
'''


def external(pid):
    root=Path('/proc')/str(pid)
    values={line.split(':',1)[0]:line.split(':',1)[1].split() for line in (root/'status').read_text().splitlines() if ':' in line}
    targets=[]
    for entry in (root/'fd').iterdir():
        try: targets.append(os.readlink(entry))
        except FileNotFoundError: pass
    return dict(pid=int(values['Pid'][0]),uids=list(map(int,values['Uid'])),gids=list(map(int,values['Gid'])),
                fds=len(targets),memfds=sorted(v for v in targets if '/memfd:' in v),targets=sorted(targets))


def process_identity(pid):
    root=Path('/proc')/str(pid); inventory=external(pid)
    executable=os.readlink(root/'exe')
    return dict(pid=pid,uid=inventory['uids'][0],gid=inventory['gids'][0],
                executable=executable,executable_sha256=sha(root/'exe'),
                argv=(root/'cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
                starttime_ticks=int((root/'stat').read_text().rsplit(')',1)[1].split()[19]),
                kernel_ids=dict(uids=inventory['uids'],gids=inventory['gids']),pgid=os.getpgid(pid))


def actor_identity(receipt):
    observed=process_identity(receipt['pid'])
    declared=receipt['process']
    for k in ('pid','uid','gid','executable','argv','starttime_ticks'):
        assert declared[k]==observed[k], ('actor/proc disagreement',k)
    assert declared['kernel_ids']['Uid']==observed['kernel_ids']['uids']
    assert declared['kernel_ids']['Gid']==observed['kernel_ids']['gids']
    assert_process(observed)
    return observed


def group_members(group):
    result=[]
    for root in Path('/proc').iterdir():
        if not root.name.isdigit(): continue
        try:
            if os.getpgid(int(root.name))==group: result.append(int(root.name))
        except ProcessLookupError: pass
    return sorted(result)


def bounded_poll(probe, accept, limit_ms, attempts):
    started=time.monotonic(); deadline=started+limit_ms/1000
    while True:
        row={'started_ms':(time.monotonic()-started)*1000}
        try:
            value=probe(); row.update(sample=value,success=bool(accept(value)))
        except Exception as error:
            row.update(error=repr(error),success=False)
        row['elapsed_ms']=(time.monotonic()-started)*1000
        attempts.append(row)
        if row['success']:
            assert time.monotonic()<=deadline, 'late cleanup/readiness observation'
            return row['sample']
        remaining=deadline-time.monotonic()
        assert remaining>0, ('bounded polling deadline',attempts)
        select.select([],[],[],min(.005,remaining))


def request(actor, record, operation, timeout=10, **options):
    command=dict(op=operation,**options)
    started=time.monotonic(); row={'command':command,'started_monotonic':started}; record.append(row)
    actor.begin(**command)
    try:
        response=actor.read(timeout=timeout)
        row['response']=response
        assert response['ok'] is True, response
        return response['result']
    finally:
        row['elapsed_ms']=(time.monotonic()-started)*1000


def version(executable, args=('--version',)):
    command=[str(executable),*args]
    completed=subprocess.run(command,capture_output=True,text=True,timeout=WORKLOAD['startup_ms']/1000)
    return dict(command=command,returncode=completed.returncode,stdout=completed.stdout,stderr=completed.stderr)


def assert_candidate_mode(path, original, actual):
    # Nix import removes write bits; read and execute bits remain exact.
    in_store=Path(path).is_relative_to('/nix/store')
    expected=original & ~0o222 if in_store else original
    assert actual==expected, ('candidate mode mismatch',str(path),original,actual,expected)


def candidate_inventory(candidate, manifest):
    result={}
    for relative,expected in manifest['files'].items():
        path=candidate/relative
        assert path.is_file() and sha(path)==expected, ('missing/changed candidate',relative)
        assert_candidate_mode(path,manifest['file_modes'][relative],stat.S_IMODE(path.stat().st_mode))
        result[relative]=sha(path)
    return result


def capture_inputs(args, manifest):
    elixir=Path(manifest['runtime']['elixir_store'])/'bin/elixir'
    erl=Path(manifest['runtime']['otp_store'])/'bin/erl'
    beams=list((Path(manifest['runtime']['otp_store'])/'lib/erlang').glob('erts-*/bin/beam.smp'))
    assert len(beams)==1, 'missing/ambiguous frozen BEAM runtime'
    runuser=Path(shutil.which('runuser') or '/missing-runuser')
    paths={name:args.fixtures/file for name,file in [('actor','actor.py'),('actor_test','actor_test.py'),('qualify','qualify.py'),
           ('oracle_test','oracle_test.py'),('workload','workload.json'),('test_nix','test.nix'),('readme','README.md')]}
    paths.update(scope=args.scope,channel=args.helpers/'channel.py',transport_actor=args.wire_dir/'transport_actor.py',
                 broadcast_actor=args.wire_dir/'broadcast_delivery_actor.py',quota_daemon=args.quota_daemon,collector=args.collector,
                 candidate_manifest=args.candidate/'candidate.json',python=Path(sys.executable),elixir=elixir,erl=erl,beam=beams[0],
                 reference_executable=args.reference_executable,runuser=runuser)
    result={}
    for name,path in paths.items():
        assert path.is_absolute() and path.is_file(), ('missing input',name,str(path))
        result[name]=dict(path=str(path),sha256=sha(path))
    return result


def reference_stop(process, log):
    process.send_signal(signal.SIGTERM)
    method='sigterm'
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        method='kill'; os.killpg(process.pid,signal.SIGKILL); process.wait(timeout=WORKLOAD['cleanup_ms']/1000)
    log.close()
    return dict(pid=process.pid,returncode=process.returncode,method=method,command=process.args)


def run_backend(args, report, backend, channel_module, save):
    directory=args.evidence/backend; directory.mkdir()
    c={'backend':backend,'status':'running','cases':[],'operations':[],'startup_attempts':[],'teardown':{},'versions':{}}
    report['combinations'].append(c); save()
    daemon=actor=reference=None; reference_log=None; socket_identity=None
    socket_path=Path(WORKLOAD['socket'])
    actor_pid=None
    try:
        assert not socket_path.exists(), 'private socket occupied'
        if backend=='gao':
            command=[report['inputs_before']['elixir']['path'],'--erl','+S 2:2']
            for path in sorted((args.candidate/'lib').glob('*/ebin')): command+=['-pa',str(path)]
            command += [str(args.quota_daemon),str(socket_path),str(args.collector)]
            c['backend_command']=command; save()
            daemon=channel_module.Channel(command,directory/'broker.log','FIXTURE ')
            c['ready']=daemon.read(timeout=10)
            assert c['ready']['event']=='ready'
            assert int(c['ready']['pid'])==daemon.process.pid, 'broker launcher is not actual BEAM'
            broker_pid=daemon.process.pid
            c['versions']['broker']=version(report['inputs_before']['elixir']['path'])
        else:
            config=reference_config(str(socket_path)); config_path=directory/'reference.conf'
            config_path.write_text(config); c['reference_config']=config; c['reference_config_sha256']=sha(config_path)
            command=[str(args.reference_executable),'--nofork','--nopidfile','--config-file='+str(config_path)]
            c['backend_command']=command; save()
            reference_log=(directory/'broker.log').open('wb')
            reference=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=reference_log,stderr=subprocess.STDOUT,start_new_session=True)
            broker_pid=reference.pid
            def socket_probe():
                assert reference.poll() is None, ('reference exited',reference.returncode)
                if not socket_path.exists(): return {'present':False}
                st=socket_path.stat(); return dict(present=stat.S_ISSOCK(st.st_mode),dev=st.st_dev,ino=st.st_ino)
            socket_identity=bounded_poll(socket_probe,lambda r:r['present'],10000,c['startup_attempts'])
            c['ready']={'profile':'core','pid':broker_pid}
            c['versions']['broker']=version(args.reference_executable)
        assert socket_path.is_socket()
        c['broker']=process_identity(broker_pid); assert c['broker']['uid']==0
        c['versions']['actor']=version(sys.executable)
        actor_command=[report['inputs_before']['runuser']['path'],'-u','foundationA','--',sys.executable,'-B',str(args.fixtures/'actor.py'),str(socket_path),str(args.wire_dir)]
        c['actor_command']=actor_command; save()
        actor=channel_module.Actor(actor_command,directory/'actor.log')
        initial=actor.read(timeout=10); c['initial']=initial; save()
        assert initial['ok'] is True and initial['result']['connections']==[]
        c['actor']=actor_identity(initial['result']); actor_pid=c['actor']['pid']
        c['launcher']=process_identity(actor.process.pid)
        assert actor_pid!=actor.process.pid, 'runuser launcher relabeled as actual actor'
        def sample(empty=False):
            row={}
            if daemon:
                # metrics includes the immutable daemon's complete quiescence/GC barrier.
                line='metrics' if empty else 'inspect'
                daemon.process.stdin.write((line+'\n').encode()); daemon.process.stdin.flush()
                row['telemetry']=daemon.read(timeout=1 if empty else 3)
            row.update(broker=external(broker_pid),actor=external(actor_pid))
            assert_inventory(row['broker']); assert_inventory(row['actor'])
            return row
        c['before']=sample(empty=True); save()
        assert_actor_inventory(initial['result'],c['before']['actor'])
        c['warmup']=request(actor,c['operations'],'warmup'); save()
        assert_warmup(c['warmup'])
        c['warmed']=sample(empty=True); save()
        assert_actor_inventory(c['warmup'],c['warmed']['actor'])
        assert_recovered(c['before']['actor'],c['warmed']['actor'])
        if daemon: assert_native(c['warmed']['telemetry'],c['warmed']['telemetry'])
        c['effective_config']=(native_config() if daemon else dict(profile='core',path=str(directory/'reference.conf'),activation_service_dirs=[],auth=['EXTERNAL']))
        save()
        for name in WORKLOAD['cases']:
            case={'name':name,'status':'running','cleanup_attempts':[]}; c['cases'].append(case); save()
            case['open']=request(actor,c['operations'],'open',case=name); save()
            assert_connections(case['open'])
            def settled_phase(phase):
                attempts=case.setdefault(phase+'_attempts',[])
                def acceptable(row):
                    try:
                        assert row['broker']['memfds']==row['actor']['memfds']==[]
                        if daemon: assert_native(row['telemetry'],c['warmed']['telemetry'],case['open']['connections'],2 if name=='mixed' else 0)
                        return True
                    except AssertionError: return False
                return bounded_poll(sample,acceptable,1000,attempts)
            case['connected']=settled_phase('connected'); save()
            assert_actor_inventory(case['open'],case['connected']['actor'])
            case['exercise']=request(actor,c['operations'],'exercise'); save()
            assert_exercise(case['exercise'])
            case['checked']=settled_phase('checked'); save()
            assert_actor_inventory(case['exercise'],case['checked']['actor'])
            assert_recovered(case['connected']['actor'],case['checked']['actor'])
            if daemon:
                for phase in ('connected','checked'):
                    assert_native(case[phase]['telemetry'],c['warmed']['telemetry'],case['open']['connections'],2 if name=='mixed' else 0)
            close_started=time.monotonic()
            case['close']=request(actor,c['operations'],'close',timeout=1); save()
            budget=1000-(time.monotonic()-close_started)*1000
            assert budget>0, 'actor close deadline'
            def accept_closed(row):
                try:
                    assert_recovered(c['warmed']['broker'],row['broker'])
                    assert_recovered(c['warmed']['actor'],row['actor'])
                    if daemon: assert_native(row['telemetry'],c['warmed']['telemetry'])
                    return True
                except AssertionError: return False
            case['closed']=bounded_poll(lambda:sample(empty=True),accept_closed,budget,case['cleanup_attempts'])
            assert_actor_inventory(case['close'],case['closed']['actor'])
            case['cleanup_elapsed_ms']=(time.monotonic()-close_started)*1000
            assert case['cleanup_elapsed_ms']<=1000
            case['status']='passed'; save()
        c['status']='passed'
    except Exception as error:
        c.update(status='failed',error=repr(error))
        save()
    finally:
        # Always retain failed actor/backend logs and real stop dispositions.
        teardown=c['teardown']
        try:
            if actor: teardown['actor']=actor.stop(grace=5)
        except Exception as error: teardown['actor_error']=repr(error)
        try:
            if daemon: teardown['backend']=daemon.stop(grace=5)
            elif reference: teardown['backend']=reference_stop(reference,reference_log)
        except Exception as error: teardown['backend_error']=repr(error)
        teardown['containment_attempts']=[]
        groups=[p.process.pid for p in (actor,daemon) if p]
        if reference: groups.append(reference.pid)
        def contain():
            members={str(group):group_members(group) for group in groups}
            for group,rows in members.items():
                if rows:
                    try: os.killpg(int(group),signal.SIGKILL)
                    except ProcessLookupError: pass
            return members
        try:
            bounded_poll(contain,lambda r:not any(r.values()),1000,teardown['containment_attempts'])
            teardown['groups_absent']=True
        except Exception as error:
            teardown.update(groups_absent=False,containment_error=repr(error))
        teardown['actual_actor_absent']=actor_pid is not None and not (Path('/proc')/str(actor_pid)).exists()
        teardown['observer_unlink']=None
        if backend=='reference' and reference and reference.poll() is not None and socket_path.exists():
            info=socket_path.stat()
            matched=socket_identity is not None and (info.st_dev,info.st_ino)==(socket_identity['dev'],socket_identity['ino']) and stat.S_ISSOCK(info.st_mode)
            teardown['observer_unlink']=dict(matched_inode=matched,after_backend_exit=True,dev=info.st_dev,ino=info.st_ino)
            if matched: socket_path.unlink()
        teardown['socket_absent']=not socket_path.exists()
        stop=teardown.get('backend',{})
        acceptable=(stop.get('method')=='eof' and stop.get('returncode')==0 if backend=='gao' else
                    stop.get('method')=='sigterm' and stop.get('returncode') in (0,-15))
        if not (acceptable and teardown.get('actor',{}).get('method')=='eof' and teardown.get('actor',{}).get('returncode')==0
                and teardown['groups_absent'] and teardown['actual_actor_absent'] and teardown['socket_absent']):
            c['status']='failed'; c.setdefault('error','teardown acceptance failed')
        save()
    return c['status']=='passed'


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('candidate','evidence','fixtures','wire-dir','helpers','quota-daemon','collector','reference-executable','scope'):
        parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args(argv)
    assert os.geteuid()==0 and Path('/etc/osbus-security-guest').read_text()=='isolated-vm\n', 'disposable guest only'
    assert str(args.evidence)=='/run/osbus-fd-quotas' and WORKLOAD['socket']=='/run/osbus-fd-quotas/bus'
    assert args.reference_executable.is_absolute() and str(args.reference_executable).startswith('/nix/store/'), 'pinned reference executable required'
    assert args.fixtures.resolve()==HERE
    assert not (args.evidence/'bus').exists() and not (args.evidence/'report.json').exists(), 'occupied evidence/socket'
    args.evidence.mkdir(exist_ok=True)
    stripped_dbus_keys=sorted(name for name in os.environ if name.startswith('DBUS_'))
    for name in stripped_dbus_keys: del os.environ[name]
    manifest_path=args.candidate/'candidate.json'
    assert sha(manifest_path)==WORKLOAD['candidate_manifest_sha256']
    manifest=json.loads(manifest_path.read_text())
    assert manifest['not_a_release'] is True and len(manifest['files'])==80 and len(manifest['sources'])==71
    inputs=capture_inputs(args,manifest)
    before=candidate_inventory(args.candidate,manifest)
    spec=importlib.util.spec_from_file_location('fd05_readonly_channel',args.helpers/'channel.py')
    channel_module=importlib.util.module_from_spec(spec); spec.loader.exec_module(channel_module)
    report=dict(schema=1,requirement='FD-05',profile='core',not_a_release=True,result='running',
                selection=['FD-05/core/gao','FD-05/core/reference'],workload=WORKLOAD,manifest=manifest,
                inputs_before=inputs,candidate_before=before,command=[sys.executable,'-B',str(HERE/'qualify.py'),*(argv if argv is not None else sys.argv[1:])],
                observer=process_identity(os.getpid()),stripped_dbus_keys=stripped_dbus_keys,combinations=[],started_monotonic=time.monotonic())
    def save():
        report['counts']=counts(report['combinations'])
        (args.evidence/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    save()
    try:
        for backend in WORKLOAD['backends']:
            if not run_backend(args,report,backend,channel_module,save):
                remaining=WORKLOAD['backends'][len(report['combinations']):]
                report['combinations'] += [dict(backend=b,status='blocked',reason='prior backend disagreement/failure') for b in remaining]
                raise AssertionError('FD-05 backend failed; slice halted unchanged')
        report['result']='passed_independent_fd05_core'
    except Exception as error:
        report.update(result='failed',error=repr(error))
    finally:
        try:
            report['inputs_after']=capture_inputs(args,manifest)
            report['candidate_after']=candidate_inventory(args.candidate,manifest)
        except Exception as error: report.update(result='failed',hash_error=repr(error))
        report['elapsed_seconds']=time.monotonic()-report['started_monotonic']
        save()
        try: assert_report(report)
        except Exception as error: report.update(result='failed',completion_error=repr(error))
        save()
    assert report['result']=='passed_independent_fd05_core', report
    print(json.dumps(dict(result=report['result'],counts=report['counts'],not_a_release=True)))


if __name__=='__main__': main()
