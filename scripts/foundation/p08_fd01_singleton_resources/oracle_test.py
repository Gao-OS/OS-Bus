"""Offline synthetic receipts: no broker, socket, subprocess or VM starts."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import unittest
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fd01_controller', HERE / 'qualify.py')
Q = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(Q)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def string(value):
    raw = value.encode()
    return struct.pack('<I', len(raw)) + raw + b'\0'


def string_array(values):
    contents=b''
    for value in values:
        contents+=bytes(-len(contents)%4)+string(value)
    return struct.pack('<I',len(contents))+contents


def frame(kind, serial, fields, body=b'', flags=0):
    header = b''
    for code, sig, value in fields:
        header += bytes(-len(header) % 8) + bytes([code, 1]) + sig.encode() + b'\0'
        if sig in ('s', 'o'):
            header += string(value)
        elif sig == 'g':
            header += bytes([len(value)]) + value.encode() + b'\0'
        else:
            header += struct.pack('<I', value)
    return b'l' + bytes([kind, flags, 1]) + struct.pack('<III', len(body), serial, len(header)) + header + bytes(-len(header) % 8) + body


def message(role, direction, kind, serial, fields, body=b'', rights=0, phase='active', targets=None):
    raw = frame(kind, serial, fields, body)
    row = dict(role=role, direction=direction, phase=phase, type=kind, serial=serial,
               fields={str(code): value for code, sig, value in fields}, body_hex=body.hex(),
               wire_hex=raw.hex(), wire_sha256=digest(raw), wire_bytes=len(raw), rights=rights)
    if direction == 'received':
        row['fd_targets'] = targets or []
    return row


def raw_flags(row, flags):
    raw=bytearray.fromhex(row['wire_hex']);raw[2]=flags;raw=bytes(raw)
    row.update(wire_hex=raw.hex(),wire_sha256=digest(raw))


def mutate_setup(report, reply_serial, role=None, fields=None, body=None, kind=None):
    """Re-encode every alias/copy, retaining full-report transcript consistency."""
    seen=set()
    def visit(value):
        if isinstance(value,(dict,list)):
            if id(value) in seen:return
            seen.add(id(value))
        if isinstance(value,dict):
            if (value.get('phase')=='setup' and value.get('direction')=='received'
                    and value.get('fields',{}).get('5')==reply_serial
                    and (role is None or value['role']==role)):
                headers={**value['fields'],**(fields or {})}
                contents=bytes.fromhex(value['body_hex']) if body is None else body(value) if callable(body) else body
                kinds={1:'o',2:'s',3:'s',4:'s',5:'u',6:'s',7:'s',8:'g',9:'u'}
                message_type=value['type'] if kind is None else kind
                raw=frame(message_type,value['serial'],[(int(k),kinds[int(k)],v) for k,v in headers.items()],contents,bytes.fromhex(value['wire_hex'])[2])
                value.update(type=message_type,fields=headers,body_hex=contents.hex(),wire_hex=raw.hex(),wire_bytes=len(raw),wire_sha256=digest(raw))
            for child in value.values():visit(child)
        elif isinstance(value,list):
            for child in value:visit(child)
    visit(report)


def fd(number, inode=None, pid=200, uid=1100, target=None, mode=0o140777):
    inode = inode if inode is not None else number + 1000
    return dict(fd=number, target=target or f'socket:[{inode}]', dev=9, ino=inode, mode=mode,
                pid=pid, uid=uid, gid=uid)


def inventory(records, pid=200, uid=1100):
    return dict(pid=pid, uids=[uid]*4, gids=[uid]*4, count=len(records), fds=copy.deepcopy(records))


def fd_state(records):
    return dict(count=len(records), fds=copy.deepcopy(records))


def process(pid, uid, executable):
    return dict(pid=pid, uid=uid, gid=uid, executable=executable, executable_sha256='a'*64,
                argv=[executable], starttime_ticks=100, kernel_ids=dict(uids=[uid]*4, gids=[uid]*4),
                pgid=199 if pid == 200 else pid)


IDENTITY = dict(pid=200, uid=1100, gid=1100, native_fixture='Python Linux socket/SCM_RIGHTS')
BASE = [fd(i, target=f'pipe:[{i}]', mode=0o10600) for i in range(3)]


def connection(role, index):
    name = f':1.{index}'
    setup = []
    for member, serial in [('Hello', 1), ('ListNames', 2)]:
        fields = [(1, 'o', '/org/freedesktop/DBus'), (2, 's', Q.BUS), (3, 's', member), (6, 's', Q.BUS), (8, 'g', '')]
        setup.append(message(role, 'sent', 1, serial, fields, phase='setup'))
        reply = [(5, 'u', serial), (6, 's', name), (7, 's', Q.BUS), (8, 'g', 's' if serial == 1 else 'as')]
        # The former synthetic positive returned an empty array (00000000).
        # Correct it to the names actually live at this singleton setup point.
        names=[Q.BUS,name] if role=='source' else [Q.BUS,':1.1',name]
        setup.append(message(role, 'received', 2, serial + 10, reply, string(name) if serial == 1 else string_array(names), phase='setup'))
    return dict(**IDENTITY, role=role, name=name, socket_fd=index+2, socket=fd(index+2),
                negotiated=True, negotiation=dict(requested=True, auth_reply='OK '+'a'*32, fd_reply='AGREE_UNIX_FD'), setup=setup)


def opened():
    cs = [connection('source', 1), connection('target', 2)]
    return dict(op='open', **IDENTITY, source=cs[0], target=cs[1], connections=cs,
                fd_state=fd_state(BASE+[c['socket'] for c in cs]))


def exercise():
    cs = opened()['connections']
    source, target = [c['name'] for c in cs]
    original, received = fd(5, 9001, target='pipe:[9001]', mode=0o10600), fd(6, 9001, target='pipe:[9001]', mode=0o10600)
    writer = fd(6, 9001, target='pipe:[9001]', mode=0o10600)
    fields = [(1, 'o', '/foundation'), (2, 's', 'org.foundation.Transport'), (3, 's', 'Resource'),
              (6, 's', target), (8, 'g', 'h'), (9, 'u', 1)]
    transfer = dict(serial=100, sender=source, target=target, signature='h', index=0, header9=1, rights=1,
                    content='PIPE', content_hex=b'PIPE'.hex(), content_sha256=digest(b'PIPE'),
                    written_bytes=4, writer_close=dict(**writer, role='writer', closed=True),
                    source_fd=original, received_fd=received,
                    sent=message('source', 'sent', 4, 100, fields, bytes(4), 1),
                    received=message('target', 'received', 4, 100, fields+[(7, 's', source)], bytes(4), 1, targets=[received]))
    health = []
    for c, serial in zip(cs, (110, 111)):
        sent = [(1, 'o', '/org/freedesktop/DBus'), (2, 's', Q.BUS), (3, 's', 'GetNameOwner'), (6, 's', Q.BUS), (8, 'g', 's')]
        reply = [(5, 'u', serial), (6, 's', c['name']), (7, 's', Q.BUS), (8, 'g', 's')]
        health.append(dict(role=c['role'], serial=serial, reply_serial=serial, owner=c['name'], rights=0, latency_ms=1,
                           sent=message(c['role'], 'sent', 1, serial, sent, string(c['name'])),
                           received=message(c['role'], 'received', 2, serial+1000, reply, string(c['name']))))
    return dict(op='exercise', **IDENTITY, connections=cs, transfer=transfer, health=health,
                held=True, fd_state=fd_state(BASE+[c['socket'] for c in cs]+[original, received]))


def closed(ex, op='close'):
    transfer = ex['transfer']
    owned = [('received', transfer['received_fd']), ('original', transfer['source_fd'])]
    owned += [(c['role'], c['socket']) for c in ex['connections']]
    events = {c['role']:copy.deepcopy(c['setup']) for c in ex['connections']}
    events['source'].append(ex['health'][0]['received'])
    events['target'] += [transfer['received'], ex['health'][1]['received']]
    return dict(op=op, **IDENTITY, closure=[dict(**r, role=role, closed=True) for role, r in owned],
                events=events, connections=[], held=False, fd_state=fd_state(BASE), fd_growth=0,
                baseline_equal=True, latency_ms=1)


def telemetry(connections=()):
    counts = dict.fromkeys(Q.METRICS, 0)
    counts['connections'] = len(connections)
    peers = [dict(peer=f'#PID<0.{i+20}.0>', name=c['name'], credentials={k:c[k] for k in ('pid','uid','gid')},
                  negotiated=True, mailbox=0, queue=0, buffer_bytes=0, output=None) for i,c in enumerate(connections)]
    defaults = {
        'global':dict(connections=256,authenticating=64,ingress_messages=512,ingress_bytes=4194304,ingress_fds=2048,
                      egress_messages=512,egress_bytes=4194304,egress_fds=2048,frame_bytes=16777216,frame_fds=1024,
                      activation_messages=512,activation_bytes=4194304,activation_fds=2048),
        'uid':dict(connections=64,authenticating=16,ingress_messages=128,ingress_bytes=1048576,ingress_fds=512,
                   egress_messages=128,egress_bytes=1048576,egress_fds=512,frame_bytes=4194304,frame_fds=256,
                   activation_messages=128,activation_bytes=1048576,activation_fds=512),
        'peer':dict(ingress_messages=32,ingress_bytes=1048576,ingress_fds=128,egress_messages=32,egress_bytes=1048576,
                    egress_fds=128,frame_bytes=1048576,frame_fds=64,activation_messages=32,activation_bytes=1048576,activation_fds=128)}
    limits={scope:{**defaults[scope],**Q.CAPS[scope]} for scope in defaults}
    return dict(event='snapshot', pid='100', now_ms=100, authorities={name:f'#PID<0.{i+1}.0>' for i,name in enumerate(Q.AUTHORITIES)},
                names=[Q.BUS]+[c['name'] for c in connections], matches=0, capabilities=0, pending=0, peers=peers,
                usage=dict(**{'global':counts}, uids={'1100':counts} if peers else {},
                           peers={p['peer']:{**dict.fromkeys(Q.METRICS,0),'connections':1} for p in peers},
                           reservations=0, limits=limits, xml={'limits':None,'queues':None,'global':{'incomplete':0,'completed':0},'uids':{}}))


def valid_report():
    keys = Q.INPUT_KEYS
    inputs = {k:dict(path='/nix/store/test/'+k, sha256='a'*64) for k in keys}
    inputs['candidate_manifest']['sha256'] = Q.WORKLOAD['candidate_manifest_sha256']
    files = {f'file{i}':'a'*64 for i in range(80)}
    report = dict(schema=1, requirement='FD-01', subcase='pipe', profile='core', not_a_release=True,
                  workload=copy.deepcopy(Q.WORKLOAD), selection=Q.SELECTION, result=Q.PASS,
                  elapsed_seconds=1, command=['python','-B','qualify.py'], observer=process(300,0,inputs['python']['path']),
                  cwd='/run/osbus-fd-quotas', stripped_dbus_keys=[], inputs_before=inputs, inputs_after=copy.deepcopy(inputs),
                  manifest=dict(not_a_release=True, files=files, sources={f'source{i}':{} for i in range(71)}),
                  candidate_before=files, candidate_after=copy.deepcopy(files), combinations=[])
    for backend in Q.WORKLOAD['backends']:
        ex = exercise()
        if backend=='reference':
            # Actual VM3 reference uses standard NO_REPLY_EXPECTED on broker
            # setup/health replies; the Resource signal still has flags zero.
            for c in ex['connections']:
                for event in c['setup']:
                    if event['direction']=='received': raw_flags(event,1)
            for health in ex['health']: raw_flags(health['received'],1)
        close = closed(ex)
        broker_base = [fd(0, pid=100, uid=0, target='pipe:[100]', mode=0o10600)]
        def sample(actor_fds, connections=()):
            row = dict(broker=inventory(broker_base,100,0), actor=inventory(actor_fds))
            if backend == 'gao': row['telemetry'] = telemetry(connections)
            return row
        warm = dict(op='warmup', **IDENTITY, exercise=copy.deepcopy(ex), close=closed(ex,'warmup-close'),
                    connections=[],held=False,fd_state=fd_state(BASE),fd_growth=0)
        combo = dict(backend=backend,status='passed',broker=process(100,0,inputs['beam' if backend=='gao' else 'reference_executable']['path']),
                     actor=process(200,1100,inputs['python']['path']),launcher=process(199,0,inputs['runuser']['path']),
                     initial={'ok':True,'result':dict(op='ready',**IDENTITY,connections=[],fd_state=fd_state(BASE))},
                     versions={name:dict(command=[inputs[key]['path'],'--version'],returncode=0,stdout='version',stderr='')
                               for name,key in [('actor','python'),('broker','elixir' if backend=='gao' else 'reference_executable')]},
                     before=sample(BASE),warmed=sample(BASE),warmup=warm,open=opened(),exercise=ex,close=close,
                     connected=sample(opened()['fd_state']['fds'],ex['connections']),checked=sample(ex['fd_state']['fds'],ex['connections']),
                     closed=sample(BASE),cleanup_elapsed_ms=1,operations=[],startup_attempts=[],
                     socket_identity=dict(dev=9,ino=999,mode=0o140777),
                     teardown=dict(actor=dict(pid=199,method='eof',returncode=0),backend=dict(pid=100,method='eof' if backend=='gao' else 'sigterm',returncode=0),
                                   actor_eof={'ok':True,'result':dict(op='eof',**IDENTITY,connections=[],held=False,closure=[],events={},
                                                                   fd_state=fd_state(BASE),fd_growth=0,baseline_equal=True,latency_ms=1)},
                                   actual_actor_absent=True,broker_absent=True,launcher_absent=True,groups_absent=True,socket_absent=True,
                                   observer_unlink=None,elapsed_ms=1,containment_attempts=[dict(sample={'100':[],'199':[]},success=True,elapsed_ms=1)]))
        combo['open']['connections']=copy.deepcopy(ex['connections'])
        combo['open']['source'],combo['open']['target']=combo['open']['connections']
        for phase in ('warmed','connected','checked','closed'):
            combo[phase+'_attempts']=[dict(sample=combo[phase],success=True,elapsed_ms=1)]
        combo['operations'] = [dict(command={'op':op},response={'ok':True,'result':combo[key]},elapsed_ms=1)
                               for op,key in [('warmup','warmup'),('open','open'),('exercise','exercise'),('close','close')]]
        if backend == 'gao':
            combo['ready']=dict(event='ready',pid='100',profile='system',config_file=None,send_timeout_ms=5000,resource_limits=copy.deepcopy(Q.CAPS))
            combo['effective_config']=Q.native_config()
        else:
            config=Q.reference_config(Q.WORKLOAD['socket'])
            combo.update(reference_config=config,reference_config_exported=config,reference_config_sha256=digest(config.encode()),
                         reference_config_path='/run/osbus-fd-quotas/reference/reference.conf',
                         backend_command=[inputs['reference_executable']['path'],'--nofork','--nopidfile','--config-file=/run/osbus-fd-quotas/reference/reference.conf'],
                         ready=dict(profile='core',pid=100,startup_status='running',config_validated_by_startup=True))
            combo['startup_attempts']=[dict(sample=combo['socket_identity'],success=True,elapsed_ms=1)]
        report['combinations'].append(combo)
    report['counts']=Q.counts(report['combinations'])
    return report


class Oracles(unittest.TestCase):
    def reject(self, fn, value):
        with self.assertRaises((AssertionError,KeyError,ValueError,TypeError,IndexError,struct.error)):
            fn(value)

    def test_complete_report(self): Q.assert_report(valid_report())

    def test_reference_policy(self):
        root=ET.fromstring(Q.reference_config(Q.WORKLOAD['socket']))
        self.assertEqual([c.tag for c in root],['type','listen','auth','policy','policy']+['limit']*6)
        self.assertEqual([c.text for c in list(root)[:3]],['system','unix:path='+Q.WORKLOAD['socket'],'EXTERNAL'])
        default,uid=root.findall('policy')
        self.assertEqual(default.attrib,{'context':'default'})
        self.assertEqual([(c.tag,c.attrib) for c in default],[('deny',{'user':'*'}),('allow',{'user':'1100'}),('deny',{'own':'*'}),('deny',{'send_destination':'*'}),('deny',{'receive_sender':'*'})])
        self.assertEqual(uid.attrib,{'user':'1100'})
        self.assertEqual([(c.tag,c.attrib) for c in uid],[('allow',{'send_destination':'*'}),('allow',{'receive_sender':'*'})])
        self.assertEqual([(c.attrib,c.text) for c in root.findall('limit')],[({'name':name},str(value)) for name,value in
                         [('auth_timeout',10000),('max_incoming_unix_fds',64),('max_outgoing_unix_fds',64),('max_message_unix_fds',16),('max_connections_per_user',8),('max_completed_connections',8)]])

    def test_parser_rejects_ambiguous_raw(self):
        for raw in [frame(2,1,[(5,'u',1),(5,'u',1)]), frame(2,1,[(5,'u',1)])[:-1], frame(2,1,[(5,'u',1)])+b'x', frame(2,0,[(5,'u',1)])]:
            with self.subTest(raw=raw.hex()): self.reject(Q.parse_frame,raw)

    def test_broker_flags_preserved(self):
        raw=frame(2,1,[(5,'u',110)],flags=1)
        self.assertEqual(Q.parse_frame(raw)['flags'],1)

    def test_standard_unknown_flags_rejected(self):
        for flags in (2,4,8,255): self.reject(Q.parse_frame,frame(2,1,[(5,'u',110)],flags=flags))

    def test_listnames_order_is_not_invented(self):
        row=valid_report()
        mutate_setup(row,2,body=lambda event:string_array([event['fields']['6'],Q.BUS] if event['role']=='source' else [event['fields']['6'],':1.1',Q.BUS]))
        Q.assert_report(row)

    def test_listnames_decoder_consumes_complete_strings(self):
        for names in ([Q.BUS,':1.1'],[':1.2',Q.BUS,':1.1']):
            self.assertEqual(Q.list_names(string_array(names)),names)

    def test_listnames_decoder_rejects_bad_element_bounds(self):
        encoded=string_array([':1.1',Q.BUS])
        bad_nul=bytearray(encoded);bad_nul[12]=1
        bad_padding=bytearray(encoded);bad_padding[13]=1
        bad_utf8=struct.pack('<II',6,1)+b'\xff\0'
        embedded_nul=struct.pack('<II',8,3)+b'a\0b\0'
        for raw in (b'',b'\0',struct.pack('<I',2**32-1),encoded[:-1],encoded+b'\0',bytes(bad_nul),bytes(bad_padding),bad_utf8,embedded_nul):
            with self.subTest(body=raw.hex()):self.reject(Q.list_names,raw)

    def test_incomplete_report_is_never_success(self):
        for value in ({},{'result':Q.PASS},{'result':Q.PASS,'counts':{'passed':2}}):
            self.reject(Q.assert_report,value)

    def test_broker_pipe_leak_is_rejected_after_consistent_inventory_update(self):
        report=valid_report();Q.assert_report(report)
        branch=report['combinations'][0]
        leaked=dict(branch['exercise']['transfer']['source_fd'],fd=9,pid=100,uid=0,gid=0)
        branch['checked']['broker']['fds'].append(leaked)
        branch['checked']['broker']['count']+=1
        with self.assertRaisesRegex(AssertionError,'broker retained endpoint'):
            Q.assert_report(report)

    def test_equal_count_changed_numeric_fd_is_not_recovery(self):
        report=valid_report();Q.assert_report(report)
        branch=report['combinations'][0]
        branch['closed']['broker']['fds'][0]['fd']=99
        with self.assertRaisesRegex(AssertionError,'numeric FD identities not reclaimed'):
            Q.assert_report(report)

    def test_external_inventory_disagreement_is_not_held_resource_proof(self):
        report=valid_report();Q.assert_report(report)
        branch=report['combinations'][0]
        # Count is coherent: only external ownership differs from actor's receipt.
        branch['checked']['actor']['fds'][-1]['ino']=99999
        self.reject(Q.assert_report,report)

    def test_closed_writer_cannot_be_the_still_held_original_reader(self):
        report=valid_report();Q.assert_report(report)
        transfer=report['combinations'][0]['exercise']['transfer']
        transfer['writer_close']['fd']=transfer['source_fd']['fd']
        self.reject(Q.assert_report,report)


# Every mutation starts from a fully accepted report; these are independent
# contract controls, not assertions that labels or self-reported counts suffice.
def mutation_test(change):
    def test(self):
        row=valid_report()
        Q.assert_report(row)
        change(row)
        self.reject(Q.assert_report,row)
    return test


MUTATIONS = {
    'hello_setup_destination':lambda r:mutate_setup(r,1,fields={'6':':1.999'}),
    'listnames_setup_destination':lambda r:mutate_setup(r,2,fields={'6':':1.999'}),
    'hello_setup_sender':lambda r:mutate_setup(r,1,fields={'7':':1.999'}),
    'listnames_setup_sender':lambda r:mutate_setup(r,2,fields={'7':':1.999'}),
    'hello_setup_body':lambda r:mutate_setup(r,1,body=string(':1.999')),
    'hello_setup_type':lambda r:mutate_setup(r,1,kind=4),
    'listnames_setup_type':lambda r:mutate_setup(r,2,kind=4),
    'hello_setup_reply_serial':lambda r:mutate_setup(r,1,fields={'5':3}),
    'listnames_setup_reply_serial':lambda r:mutate_setup(r,2,fields={'5':3}),
    'hello_setup_signature':lambda r:mutate_setup(r,1,fields={'8':'u'}),
    'listnames_setup_signature':lambda r:mutate_setup(r,2,fields={'8':'au'}),
    'listnames_no_array_length':lambda r:mutate_setup(r,2,body=b''),
    'listnames_empty_array':lambda r:mutate_setup(r,2,body=bytes(4)),
    'listnames_non_string_element':lambda r:mutate_setup(r,2,body=struct.pack('<II',4,100)),
    'listnames_truncated_body':lambda r:mutate_setup(r,2,body=lambda e:bytes.fromhex(e['body_hex'])[:-1]),
    'listnames_trailing_body':lambda r:mutate_setup(r,2,body=lambda e:bytes.fromhex(e['body_hex'])+b'\0'),
    'listnames_trailing_string':lambda r:mutate_setup(r,2,body=lambda e:bytes.fromhex(e['body_hex'])+string(':1.999')),
    'listnames_malformed_length':lambda r:mutate_setup(r,2,body=struct.pack('<I',2**32-1)),
    'listnames_duplicate':lambda r:mutate_setup(r,2,'source',body=string_array([Q.BUS,':1.1',':1.1'])),
    'listnames_foreign':lambda r:mutate_setup(r,2,'source',body=string_array([Q.BUS,':1.999'])),
    'listnames_missing_bus':lambda r:mutate_setup(r,2,'source',body=string_array([':1.1'])),
    'listnames_missing_self':lambda r:mutate_setup(r,2,'source',body=string_array([Q.BUS])),
    'listnames_missing_previous_source':lambda r:mutate_setup(r,2,'target',body=string_array([Q.BUS,':1.2'])),
    'listnames_future_target':lambda r:mutate_setup(r,2,'source',body=string_array([Q.BUS,':1.1',':1.2'])),
    'failed_result':lambda r:r.update(result='failed'),
    'missing_backend':lambda r:r['combinations'].pop(),
    'duplicate_backend':lambda r:r['combinations'].__setitem__(1,copy.deepcopy(r['combinations'][0])),
    'failed_backend':lambda r:r['combinations'][0].update(status='failed'),
    'fabricated_counts':lambda r:r['counts'].update(passed=3),
    'input_mutated':lambda r:r['inputs_after']['actor'].update(sha256='b'*64),
    'candidate_mutated':lambda r:r['candidate_after'].update(file0='b'*64),
    'extended_deadline':lambda r:r['workload'].update(cleanup_ms=2000),
    'report_deadline':lambda r:r.update(elapsed_seconds=121),
    'nan_latency':lambda r:r['combinations'][0]['exercise']['health'][0].update(latency_ms=float('nan')),
    'bad_digest':lambda r:r['combinations'][0]['exercise']['transfer']['received'].update(wire_sha256='b'*64),
    'fabricated_body':lambda r:r['combinations'][0]['exercise']['transfer']['received'].update(body_hex='01000000'),
    'wrong_sender':lambda r:r['combinations'][0]['exercise']['transfer'].update(sender=':1.99'),
    'wrong_recipient':lambda r:r['combinations'][0]['exercise']['transfer'].update(target=':1.99'),
    'wrong_index':lambda r:r['combinations'][0]['exercise']['transfer'].update(index=1),
    'wrong_count':lambda r:r['combinations'][0]['exercise']['transfer'].update(rights=2),
    'wrong_contents':lambda r:r['combinations'][0]['exercise']['transfer'].update(content='WRONG!'),
    'wrong_content_digest':lambda r:r['combinations'][0]['exercise']['transfer'].update(content_sha256='b'*64),
    'wrong_resource_kind':lambda r:r['combinations'][0]['exercise']['transfer']['source_fd'].update(mode=0o100600),
    'wrong_pipe_target':lambda r:r['combinations'][0]['exercise']['transfer']['received_fd'].update(target='socket:[9001]'),
    'wrong_pipe_dev':lambda r:r['combinations'][0]['exercise']['transfer']['received_fd'].update(dev=999),
    'same_numeric_reader':lambda r:r['combinations'][0]['exercise']['transfer']['received_fd'].update(fd=5),
    'writer_unclosed':lambda r:r['combinations'][0]['exercise']['transfer']['writer_close'].update(closed=False),
    'writer_wrong_inode':lambda r:r['combinations'][0]['exercise']['transfer']['writer_close'].update(ino=99999),
    'writer_wrong_role':lambda r:r['combinations'][0]['exercise']['transfer']['writer_close'].update(role='partner'),
    'short_pipe_write':lambda r:r['combinations'][0]['exercise']['transfer'].update(written_bytes=3),
    'warmup_held':lambda r:r['combinations'][0]['warmup'].update(held=True),
    'warmup_unclosed_reader':lambda r:r['combinations'][0]['warmup']['close']['closure'][0].update(closed=False),
    'warmup_growth':lambda r:r['combinations'][0]['warmup'].update(fd_growth=1),
    'warmup_content':lambda r:r['combinations'][0]['warmup']['exercise']['transfer'].update(content='WRNG'),
    'wrong_received_inode':lambda r:r['combinations'][0]['exercise']['transfer']['received_fd'].update(ino=99999),
    'missing_held':lambda r:r['combinations'][0]['exercise'].update(held=False),
    'invented_client_pid':lambda r:r['combinations'][0]['open']['connections'][0].update(pid=201),
    'negotiation_missing':lambda r:r['combinations'][0]['open']['connections'][0].update(negotiated=False),
    'health_duplicate':lambda r:r['combinations'][0]['exercise']['health'].__setitem__(1,copy.deepcopy(r['combinations'][0]['exercise']['health'][0])),
    'health_late':lambda r:r['combinations'][0]['exercise']['health'][0].update(latency_ms=1001),
    'kernel_uid':lambda r:r['combinations'][0]['actor']['kernel_ids']['uids'].__setitem__(1,0),
    'launcher_as_actor':lambda r:r['combinations'][0]['actor'].update(pid=199),
    'executable_binding':lambda r:r['combinations'][0]['actor'].update(executable_sha256='b'*64),
    'numeric_fd_leak':lambda r:r['combinations'][0]['closed']['actor']['fds'][0].update(fd=99),
    'numeric_inode_leak':lambda r:r['combinations'][0]['closed']['broker']['fds'][0].update(ino=99999),
    'missing_external_resource':lambda r:r['combinations'][0]['checked']['actor']['fds'].pop(),
    'broker_retains_resource':lambda r:r['combinations'][0]['checked']['broker']['fds'].append(copy.deepcopy(r['combinations'][0]['exercise']['transfer']['source_fd'])),
    'fake_fd_count':lambda r:r['combinations'][0]['checked']['actor'].update(count=99),
    'missing_closure':lambda r:r['combinations'][0]['close']['closure'].pop(),
    'failed_closure':lambda r:r['combinations'][0]['close']['closure'][0].update(closed=False),
    'extra_active_frame':lambda r:r['combinations'][0]['close']['events']['target'].insert(0,copy.deepcopy(r['combinations'][0]['exercise']['transfer']['received'])),
    'actor_fd_growth':lambda r:r['combinations'][0]['close'].update(fd_growth=1),
    'credit_leak':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['global'].update(egress_fds=1),
    'open_connection_credits':lambda r:r['combinations'][0]['connected']['telemetry']['usage']['global'].update(connections=1),
    'closed_connection_credits':lambda r:r['combinations'][0]['closed']['telemetry']['usage']['global'].update(connections=1),
    'credential_mismatch':lambda r:r['combinations'][0]['checked']['telemetry']['peers'][0]['credentials'].update(pid=201),
    'authority_restart':lambda r:r['combinations'][0]['checked']['telemetry']['authorities'].update({'GaoBus.Router':'#PID<0.999.0>'}),
    'pending_retained':lambda r:r['combinations'][0]['checked']['telemetry'].update(pending=1),
    'match_retained':lambda r:r['combinations'][0]['checked']['telemetry'].update(matches=1),
    'capability_retained':lambda r:r['combinations'][0]['checked']['telemetry'].update(capabilities=1),
    'queue_retained':lambda r:r['combinations'][0]['checked']['telemetry']['peers'][0].update(queue=1),
    'output_retained':lambda r:r['combinations'][0]['checked']['telemetry']['peers'][0].update(output={}),
    'normalized_cap_changed':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['limits']['uid'].update(frame_fds=257),
    'normalized_cap_missing':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['limits']['uid'].pop('frame_fds'),
    'xml_unknown_key':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['xml'].update(unknown=0),
    'xml_completed_leak':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['xml']['global'].update(completed=1),
    'xml_incomplete_leak':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['xml']['global'].update(incomplete=1),
    'xml_uid_leak':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['xml']['uids'].update({'1100':1}),
    'xml_queue_enabled':lambda r:r['combinations'][0]['checked']['telemetry']['usage']['xml'].update(queues={}),
    'resource_sent_flags':lambda r:raw_flags(r['combinations'][0]['exercise']['transfer']['sent'],1),
    'resource_received_flags':lambda r:raw_flags(r['combinations'][0]['exercise']['transfer']['received'],1),
    'health_sent_flags':lambda r:raw_flags(r['combinations'][0]['exercise']['health'][0]['sent'],1),
    'setup_sent_flags':lambda r:raw_flags(r['combinations'][0]['open']['connections'][0]['setup'][0],1),
    'reference_fake_telemetry':lambda r:r['combinations'][1]['checked'].update(telemetry=telemetry()),
    'reference_admission_wildcard':lambda r:r['combinations'][1].update(reference_config=r['combinations'][1]['reference_config'].replace('user="1100"','user="*"')),
    'reference_config_export_mutated':lambda r:r['combinations'][1].update(reference_config_exported='bad'),
    'reference_config_hash_mutated':lambda r:r['combinations'][1].update(reference_config_sha256='b'*64),
    'reference_static_only':lambda r:r['combinations'][1]['ready'].update(config_validated_by_startup=False),
    'reference_startup_failed':lambda r:r['combinations'][1]['ready'].update(startup_status='exited'),
    'missing_startup_attempt':lambda r:r['combinations'][1].update(startup_attempts=[]),
    'missing_observation':lambda r:r['combinations'][0].update(checked_attempts=[]),
    'late_observation':lambda r:r['combinations'][0]['checked_attempts'][0].update(elapsed_ms=1001),
    'wrong_last_observation':lambda r:r['combinations'][0]['closed_attempts'][0].update(success=False),
    'cleanup_late':lambda r:r['combinations'][0].update(cleanup_elapsed_ms=1001),
    'operations_missing':lambda r:r['combinations'][0]['operations'].pop(),
    'operation_failure':lambda r:r['combinations'][0]['operations'][0]['response'].update(ok=False),
    'actor_killed':lambda r:r['combinations'][0]['teardown']['actor'].update(method='kill'),
    'actor_nonzero':lambda r:r['combinations'][0]['teardown']['actor'].update(returncode=1),
    'gao_nonzero':lambda r:r['combinations'][0]['teardown']['backend'].update(returncode=1),
    'reference_killed':lambda r:r['combinations'][1]['teardown']['backend'].update(returncode=-9),
    'actor_eof_bad':lambda r:r['combinations'][0]['teardown']['actor_eof'].update(ok=False),
    'eof_leak':lambda r:r['combinations'][0]['teardown']['actor_eof']['result'].update(fd_growth=1),
    'process_remains':lambda r:r['combinations'][0]['teardown'].update(actual_actor_absent=False),
    'group_remains':lambda r:r['combinations'][0]['teardown'].update(groups_absent=False),
    'socket_remains':lambda r:r['combinations'][0]['teardown'].update(socket_absent=False),
    'unsafe_unlink':lambda r:r['combinations'][1]['teardown'].update(observer_unlink=dict(matched_inode=False,after_backend_exit=True,dev=9,ino=999)),
}
for name,change in MUTATIONS.items():
    setattr(Oracles,'test_reject_'+name,mutation_test(change))


if __name__ == '__main__': unittest.main()
