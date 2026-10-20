"""New offline saved-data controls; synthetic records never qualify runtime.

The in-memory driver constructs finite transcripts, not sockets or processes.
Existing test modules are not imported or executed.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

import contract
import controller
import run as adapter
from actor_overlay import _call
from vectors import CASES, call, frame, receipt, wire_string
from wire_replay import BUS

BUS_ID = '0123456789abcdef' * 2


def identity(pid, uid):
    return dict(pid=pid, uid=uid, gid=uid)


def status(value):
    return ('Pid:\t%d\nUid:\t%d %d %d %d\nGid:\t%d %d %d %d\nVmRSS:\t8 kB\n' %
            (value['pid'], *([value['uid']] * 4), *([value['gid']] * 4)))


def sample(value):
    fields = ['0'] * 22
    fields[11], fields[12], fields[19] = '7', '8', '456'
    raw = str(value['pid']) + ' (synthetic actor) ' + ' '.join(fields)
    return dict(identity=value, complete=True, errors=[], starttime_ticks=456,
                fd_targets={'0':'pipe:[1]', '3':'socket:[2]'}, fd_count=2, rss_bytes=8192,
                cpu_ticks=dict(user=7, system=8), proc_stat=raw, proc_stat_after=raw,
                proc_status=status(value))


def message_parts(fields, signature='', values=()):
    """Finite synthetic reply encoder, independent of the saved-data decoder."""
    def encode(buffer, kind, value):
        if kind == 'g':
            raw = value.encode()
            buffer.extend(bytes([len(raw)]) + raw + b'\0')
            return
        buffer.extend(bytes(-len(buffer) % 4))
        if kind in ('s', 'o'):
            raw = value.encode()
            buffer.extend(struct.pack('<I', len(raw)) + raw + b'\0')
        elif kind in ('u', 'b'):
            buffer.extend(struct.pack('<I', value))
        else:
            assert kind == 'as'
            array = bytearray()
            for item in value:
                encode(array, 's', item)
            buffer.extend(struct.pack('<I', len(array)) + array)
    headers = bytearray()
    for code, kind, value in fields + ([(8, 'g', signature)] if signature else []):
        headers.extend(bytes(-len(headers) % 8))
        headers.append(code)
        encode(headers, 'g', kind)
        encode(headers, kind, value)
    body = bytearray()
    kinds = ['as'] if signature == 'as' else list(signature)
    for kind, value in zip(kinds, values, strict=True):
        encode(body, kind, value)
    return headers, body


def packet(kind, serial, fields, signature='', values=()):
    headers, body = message_parts(fields, signature, values)
    size = len(headers)
    headers.extend(bytes(-size % 8))
    raw = struct.pack('<BBBBIII', ord('l'), kind, 0, 1, len(body), serial, size) + headers + body
    field_values = {code:value for code, _, value in fields}
    row = dict(type=kind, serial=serial, reply_serial=field_values.get(5), error=field_values.get(4),
               sender=field_values.get(7), interface=field_values.get(2),
               member=field_values.get(3), body=list(values))
    return raw, row


def reply(destination, serial, signature, values, error=None):
    fields = [(5, 'u', serial), (6, 's', destination), (7, 's', BUS)]
    if error is not None:
        fields.insert(0, (4, 's', error))
    return packet(3 if error else 2, 90 + serial, fields, signature, values)


def response(writes, raw, result, budget=3000):
    wire = [dict(direction='send', **receipt(data), sent=True, elapsed_ms=i+1)
            for i, data in enumerate(writes)]
    if raw is not None:
        wire.append(dict(direction='receive', hex=raw.hex(), flags=0,
                         ancillary_count=0, elapsed_ms=len(wire)+1))
    return dict(ok=True, result=result, wire=wire, elapsed_ms=10, budget_ms=budget)


def retired(value):
    return dict(identity=value, method='eof', returncode=0, pid_absent=True,
                actor_pid_absent=True, group_absent=True, before_containment=dict(
                    stdin_closed=True, wrapper_waited=True, wrapper_returncode=0,
                    pid_absent=True, actor_pid_absent=True, group_absent=True,
                    timed_out=False, errors=[], elapsed_ms=1))


class SyntheticDriver:
    """Data-only controller adapter; every operation stores synthetic bytes."""
    def __init__(self, backend, owner_signal_first=False):
        self.backend, self.sources, self.serial = backend, [], 4
        self.now = 10.0
        self.core = {name:'#PID<0.%d.0>' % (10+i) for i, name in enumerate(contract.CORE)}
        self.observer = dict(identity=identity(100, 1100), unique=':1.1',
                             bus_id=BUS_ID, owner=adapter.OWNER)
        config = '<synthetic isolated system EXTERNAL policy>'
        path = contract.ROOT + '/' + backend + ('/reference.conf' if backend == 'reference' else '/policy.exs')
        daemon = dict(identity=identity(50, 0), proc_status=status(identity(50, 0)))
        self.record = dict(backend=backend, profile='core', status='running', observer=self.observer,
            configuration=dict(backend=backend, profile='core', endpoint=contract.ROOT+'/'+backend+'/bus',
                               bytes=config, sha256=hashlib.sha256(config.encode()).hexdigest(), path=path,
                               system_mode=True, external_only=True, isolated=True),
            daemon=daemon, actors=[], receipts=[], scenario_events=[], daemon_events=[], snapshots=[],
            settles=[], retirements=[], shutdown_errors=[], shutdown_ms=1, endpoint_removed=True)
        if backend == 'reference':
            executable = '/nix/store/synthetic/bin/dbus-daemon'
            daemon.update(version='D-Bus Message Bus Daemon synthetic\n',
                          argv=[executable, '--nofork', '--nopidfile', '--config-file='+path])
            self.record['reference_version'] = dict(argv=[executable, '--version'], returncode=0,
                stdout=daemon['version'], stderr='', executable=dict(bytes=1, sha256='a'*64, mode=365))
            self.record['commands'] = [self.record['reference_version']['argv'], daemon['argv']]
        else:
            daemon.update(version='OTP synthetic / Elixir synthetic',
                argv=['elixir', '--erl', '+S 2:2', '/nix/store/'+('0'*32)+'-os-bus-pro05-fixtures/daemon.exs',
                      contract.ROOT+'/gao_bus/bus', path])
            self.record['commands'] = [daemon['argv']]
            self.record['ready'] = dict(event='ready', pid='50', otp='OTP synthetic', elixir='synthetic',
                identity=dict(uid=0, gid=0, real_uid=0, real_gid=0), core=self.core,
                configuration=dict(profile='system', lifecycle='embedded', config_file=None,
                    inherited_listener=False, socket_path=contract.ROOT+'/gao_bus/bus',
                    authentication=['EXTERNAL'], cluster=False, capability_restrictions=False,
                    auth_limits=dict(timeout_ms=1500, idle_timeout_ms=500),
                    resource_limits=dict(peer=dict(frame_bytes=1048576))))
        self.actor(self.observer, 'observer')
        owned_raw, owned = reply(self.observer['unique'], 3, 'u', [1])
        raw, acquired = packet(4, 99, [(2,'s',BUS), (3,'s','NameAcquired'),
            (6,'s',self.observer['unique']), (7,'s',BUS)], 's', [adapter.OWNER])
        self.retain(self.observer, dict(op='call', member='RequestName', signature='su', body=[adapter.OWNER, 0]),
            response([_call('RequestName', 3, 'su', wire_string(adapter.OWNER)+bytes(4))],
                     raw+owned_raw if owner_signal_first else owned_raw, owned))
        self.retain(self.observer, dict(op='poll', timeout=0.05),
                    response([], None if owner_signal_first else raw, [acquired]))
        raw, matched = reply(self.observer['unique'], 4, '', [])
        self.retain(self.observer, dict(op='call', member='AddMatch', signature='s', body=[adapter.MATCH]),
            response([_call('AddMatch', 4, 's', wire_string(adapter.MATCH))], raw, matched))
        self.retain(self.observer, dict(op='poll', timeout=0.05), response([], None, []))
        self.baseline = None

    def retain(self, actor, command, value):
        self.record['receipts'].append(dict(identity=copy.deepcopy(actor['identity']),
            request=dict(command, deadline_monotonic=100), response=copy.deepcopy(value), elapsed_ms=10))
        self.now += 0.010
        return value

    def actor(self, public, phase):
        first, hello = reply(public['unique'], 1, 's', [public['unique']])
        last, get_id = reply(public['unique'], 2, 's', [BUS_ID])
        middle, acquired = packet(4, 99, [(2,'s',BUS), (3,'s','NameAcquired'),
            (6,'s',public['unique']), (7,'s',BUS)], 's', [public['unique']])
        rows = [acquired, hello, get_id]  # legal signal-before-Hello ordering
        result = dict(hello, unique=public['unique'], bus_id=BUS_ID, registration=rows,
                      buffered_hex='', pending_messages=0)
        auth = b'\0AUTH EXTERNAL ' + str(public['identity']['uid']).encode().hex().encode() + b'\r\n'
        value = response([auth, b'BEGIN\r\n'+adapter.query_wire('Hello', 1)+adapter.query_wire('GetId', 2)],
                         b'OK '+b'a'*32+b'\r\n'+middle+first+last, result)
        self.retain(public, dict(op='register'), value)
        self.record['actors'].append(dict(public, phase=phase, serial=2,
                                          registration=value, proc_status=status(public['identity'])))

    def public(self, member, signature='', body=(), value=None):
        self.serial += 1
        reply_signature = dict(ListNames='as', GetNameOwner='s', GetId='s',
            GetConnectionUnixUser='u', GetConnectionUnixProcessID='u', NameHasOwner='b')[member]
        raw, row = reply(self.observer['unique'], self.serial, reply_signature, [value])
        result = response([adapter.query_wire(member, self.serial, signature, body)], raw, row)
        return self.retain(self.observer, dict(op='call', member=member, signature=signature, body=body), result)

    def start_source(self, family, iteration):
        source = dict(identity=identity(200+len(self.sources), 1101),
                      unique=':1.'+str(2+len(self.sources)), bus_id=BUS_ID)
        self.sources.append(source)
        self.actor(source, family+'-'+str(iteration))
        return source

    def capture(self, source=None, departed=None):
        self.now += 0.001
        def process(pid):
            return dict(status='live', pid=pid, complete=True, error=None,
                        metrics={key:1 for key in contract.PROCESS_METRICS})
        processes = {name:process(pid) for name, pid in self.core.items()}
        processes['observer'] = process('#PID<0.100.0>')
        processes['source'] = (process('#PID<0.%d.0>' % source['identity']['pid']) if source else
            dict(status='absent', pid=departed, complete=True, error=None, metrics=None))
        resource = dict(complete=True, core=self.core, processes=processes, vm=dict(
            identity='50', reductions=1, atom_count=100, process_count=20, port_count=5,
            memory={key:1024 for key in contract.MEMORY_METRICS}))
        authority = dict(core=self.core, router=self.core['Elixir.GaoBus.Router'],
            peers=[] if source is None else [dict(name=source['unique'])], names=[], queues=[],
            usage=dict(global_usage={}, reservations={}, peers=[], uids=[]), policy='synthetic',
            match_rules_state='AA==', capability_state='AA==', match_rules_table='AA==', capabilities_table='AA==')
        return dict(complete=True, errors=[], authority=authority, resources=resource)

    def make_snapshot(self, source=None):
        observer = dict(self.observer, uid=1100, pid=100)
        names = sorted([BUS, self.observer['unique'], adapter.OWNER] + ([] if source is None else [source['unique']]))
        public = None if source is None else dict(source, uid=1101, pid=source['identity']['pid'])
        resource = dict(daemon=sample(identity(50, 0)), observer=sample(self.observer['identity']))
        if source:
            resource['daemon']['fd_targets']['4'] = 'socket:[active]'
            resource['daemon']['fd_count'] += 1
        self.public('ListNames', value=list(reversed(names)))
        self.public('GetNameOwner', 's', [adapter.OWNER], self.observer['unique'])
        self.public('GetConnectionUnixUser', 's', [self.observer['unique']], 1100)
        self.public('GetConnectionUnixProcessID', 's', [self.observer['unique']], 100)
        self.public('GetId', value=BUS_ID)
        if source:
            self.public('GetConnectionUnixUser', 's', [source['unique']], 1101)
            self.public('GetConnectionUnixProcessID', 's', [source['unique']], source['identity']['pid'])
        core = dict(identity=identity(50, 0), starttime_ticks=456)
        if self.backend == 'gao_bus':
            captured = self.capture(source)
            self.record['daemon_events'].append(dict(captured, event='sample', observer=self.observer['unique'],
                source=None if source is None else source['unique'], elapsed_ms=1))
            core, resource['native'] = captured['authority'], captured['resources']
        return dict(authority=dict(observer=observer, source=public, names=names,
                                   core=core, endpoint=dict(device=1, inode=2)), resources=resource)

    def snapshot(self, source, remaining_ms=None):
        began = self.now
        samples = [self.make_snapshot(source), self.make_snapshot(source)]
        self.record['snapshots'].extend(copy.deepcopy(samples))
        expected = adapter.settled_projection(self.baseline) if source is None and self.baseline else None
        self.record['settles'].append(dict(samples=2, elapsed_ms=(self.now-began)*1000,
            budget_ms=1500 if remaining_ms is None else remaining_ms, expected=expected))
        if self.baseline is None:
            self.baseline = samples[-1]
        return samples[-1]

    def watch(self, source):
        public = dict(source_identity=source['identity'], name=source['unique'])
        if self.backend == 'reference':
            return dict(public, kind='public-name', watch_receipt=self.public('NameHasOwner', 's', [source['unique']], True))
        raw = dict(self.capture(source), event='watched', observer=self.observer['unique'],
            name=source['unique'], peer='#PID<0.%d.0>' % source['identity']['pid'],
            reference='#Reference<%d>' % source['identity']['pid'], elapsed_ms=1,
            peer_options=dict(frame_options=dict(max_bytes=1048576), xml_limits=None,
                frame_timeout_ms=5000, auth_limits=dict(timeout_ms=1500, idle_timeout_ms=500)))
        self.record['daemon_events'].append(copy.deepcopy(raw))
        return dict(public, kind='beam-monitor', peer=raw['peer'], reference=raw['reference'], watch_event=raw)

    def request(self, source, command):
        case = command.get('case')
        if command['op'] == 'close':
            value = response([], None, dict(disposition='controller-close', socket_closed=True))
        elif command['op'] == 'terminal':
            value = response([], b'', dict(case=case, disposition='automatic-eof', source_socket_open=True,
                terminal_hex='', eof_ms=1, authorization=command['authorization'], buffered_hex='', pending_messages=0))
        else:
            serial = CASES[case]['serial']
            result = dict(case=case, frame=receipt(frame(case)), serial=serial,
                          source_socket_open=True, buffered_hex='', pending_messages=0)
            writes, raw = [frame(case)], None
            if CASES[case]['oracle'] == 'close':
                result['disposition'] = 'sent-awaiting-controller'
            else:
                writes += [call('GetNameOwner', serial+1, 's', wire_string(source['unique'])), call('GetId', serial+2)]
                first, one = reply(source['unique'], serial+1, 's', [source['unique']])
                second, two = reply(source['unique'], serial+2, 's', [BUS_ID])
                raw, result['source_health'] = first+second, [one, two]
                result['disposition'] = 'signal-sent'
                if CASES[case]['oracle'] == 'invalid_args':
                    error, result['error'] = reply(source['unique'], serial, 's', ['Invalid arguments'], BUS+'.Error.InvalidArgs')
                    raw = error+raw
                    result['disposition'] = 'invalid-args'
            value = response(writes, raw, result)
        return self.retain(source, command, value)

    def await_down(self, source, watch, remaining_ms=None):
        began = self.now
        public = dict(source_identity=source['identity'], name=source['unique'])
        if self.backend == 'reference':
            received = self.public('NameHasOwner', 's', [source['unique']], False)
            return dict(public, kind='public-name', has_owner=False, public_reply=received, attempts=[received],
                        elapsed_ms=(self.now-began)*1000)
        raw = dict(self.capture(departed=watch['peer']), event='down', observer=self.observer['unique'],
            name=source['unique'], peer=watch['peer'], reference=watch['reference'], reason='normal',
            elapsed_ms=1, down_elapsed_ms=0, elapsed_basis='await_down matching receive and fresh capture',
            monitored=True, watch_removed=True, watches=0)
        self.record['daemon_events'].append(copy.deepcopy(raw))
        return dict(public, kind='beam-monitor', peer=watch['peer'], reference=watch['reference'],
                    reason='normal', native_down=raw, elapsed_ms=(self.now-began)*1000)

    def observe(self, source_name=None):
        serial = self.serial+1
        self.serial = serial+1
        first, one = reply(self.observer['unique'], serial, 's', [self.observer['unique']])
        second, two = reply(self.observer['unique'], serial+1, 's', [BUS_ID])
        raw, signal = first+second, None
        if source_name:
            positive, signal = packet(4, 3, [(1,'o','/probe'), (2,'s','org.foundation.Probe'),
                (3,'s','Changed'), (7,'s',source_name)], 's', ['/probe'])
            raw = positive+raw
        value = response([call('GetNameOwner', serial, 's', wire_string(adapter.OWNER)), call('GetId', serial+1)],
            raw, dict(signal=signal, health=[one,two], bus_id=BUS_ID, observer_health_ms=1,
                      buffered_hex='', pending_messages=0), 1000)
        self.retain(self.observer, dict(op='observe', serial=serial, owner=adapter.OWNER, source_name=source_name), value)
        return dict(response=value, serial=serial)

    def retire(self, source):
        value = retired(source['identity'])
        self.record['retirements'].append(copy.deepcopy(value))
        return value

    def persist(self, event):
        self.record['scenario_events'].append(copy.deepcopy(event))

    def complete(self):
        # Recorded10ms requests and1ms native captures advance this virtual
        # clock. Controller totals/budgets/tokens therefore agree with those
        # synthetic observations without sleeping or measuring host runtime.
        with patch.object(controller.time, 'monotonic', side_effect=lambda: self.now):
            scenario = controller.run_cases(self)
        scenario.pop('events')
        self.record['scenario'] = scenario
        self.retire(self.observer)
        if self.backend == 'gao_bus':
            self.record['daemon_events'].append(dict(event='stopped', normal=True, watches=0))
            stop = retired(identity(50, 0))
        else:
            stop = dict(method='sigterm', returncode=0, pid_absent=True, group_absent=True, forced=False, elapsed_ms=1)
        self.record['daemon_retirement'] = stop
        return self.record


class ContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = SyntheticDriver('reference').complete()
        cls.gao = SyntheticDriver('gao_bus').complete()

    def test_complete_synthetic_backends_recompute_before_status_or_measurement(self):
        for record in (self.reference, self.gao):
            with self.subTest(backend=record['backend']):
                self.assertNotIn('invariant_measurement', record)
                self.assertEqual(contract.measure_backend(record), contract.expected_invariant())
                observed = copy.deepcopy(record)
                observed.update(status='passed_pending_independent_review', invariant_measurement=contract.expected_invariant())
                contract.validate_backend(observed)

    def test_unsorted_raw_list_names_matches_sorted_public_projection(self):
        names = next(row['response']['result']['body'][0] for row in self.reference['receipts']
                     if row['request'].get('member') == 'ListNames')
        self.assertNotEqual(names, sorted(names))
        self.assertEqual(sorted(names), self.reference['snapshots'][0]['authority']['names'])
        self.assertEqual(contract.measure_backend(self.reference), contract.expected_invariant())

    def test_request_name_queued_signal_before_reply_needs_no_new_poll_receive(self):
        value = SyntheticDriver('reference', owner_signal_first=True).complete()
        owned, polled = value['receipts'][1:3]
        self.assertEqual(len(owned['response']['wire']), 2)
        self.assertEqual(polled['response']['wire'], [])
        self.assertEqual(polled['response']['result'][0]['member'], 'NameAcquired')
        self.assertEqual(contract.measure_backend(value), contract.expected_invariant())
        altered = copy.deepcopy(value)
        altered['receipts'][2]['response']['result'][0]['body'] = ['org.foundation.Unobserved']
        with self.assertRaises(AssertionError):
            contract.measure_backend(altered)
        late_reply = copy.deepcopy(value)
        acquired_raw, _ = packet(4, 99, [(2,'s',BUS), (3,'s','NameAcquired'),
            (6,'s',value['observer']['unique']), (7,'s',BUS)], 's', [adapter.OWNER])
        owned_raw, _ = reply(value['observer']['unique'], 3, 'u', [1])
        late_reply['receipts'][1]['response']['wire'][-1]['hex'] = acquired_raw.hex()
        poll = late_reply['receipts'][2]['response']
        poll['wire'] = response([], owned_raw, poll['result'])['wire']
        with self.assertRaises(AssertionError):
            contract.measure_backend(late_reply)

    def test_nix_export_daemon_path_is_accepted_and_source_suffix_rejected(self):
        self.assertEqual(self.gao['daemon']['argv'][-3],
            '/nix/store/'+('0'*32)+'-os-bus-pro05-fixtures/daemon.exs')
        contract.metadata(self.gao)
        for path in ('/synthetic/pro05_complete/daemon.exs',
                     '/nix/store/'+('e'*32)+'-os-bus-pro05-fixtures/daemon.exs',
                     '/nix/store/'+('0'*32)+'-other-fixtures/daemon.exs'):
            altered = copy.deepcopy(self.gao)
            altered['daemon']['argv'][-3] = path
            with self.subTest(path=path), self.assertRaises(AssertionError):
                contract.metadata(altered)

    def test_elapsed_join_allows_only_native_quantization_and_python_roundoff(self):
        contract.elapsed_within(20, 20)
        contract.elapsed_within(20+contract.FLOAT_ROUNDOFF_MS/2, 20)
        contract.elapsed_within(21, 20, native_intervals=1)
        for elapsed, enclosing, native_count in ((20.01, 20, 0), (21.01, 20, 1), (23, 20, 2)):
            with self.subTest(elapsed=elapsed, native_count=native_count), self.assertRaisesRegex(
                    AssertionError, 'sequential observations exceed enclosing elapsed'):
                contract.elapsed_within(elapsed, enclosing, native_count)

    def test_sequential_receipt_and_native_sample_totals_must_fit_settle(self):
        for backend, mutation in (('reference', 'receipts'), ('gao_bus', 'receipts'), ('gao_bus', 'native')):
            value = copy.deepcopy(self.reference if backend == 'reference' else self.gao)
            if mutation == 'receipts':
                value['settles'][0]['elapsed_ms'] = 10
            else:
                for event in value['daemon_events'][:2]:
                    self.assertEqual(event['event'], 'sample')
                    event['elapsed_ms'] = 600
            with self.subTest(backend=backend, mutation=mutation), self.assertRaisesRegex(
                    AssertionError, 'sequential observations exceed enclosing elapsed'):
                contract.measure_backend(value)

    def test_reference_public_and_native_down_duration_totals_must_fit_outer_down(self):
        for backend in contract.BACKENDS:
            value = copy.deepcopy(self.reference if backend == 'reference' else self.gao)
            down = value['scenario']['groups'][0]['down']
            if backend == 'reference':
                down['elapsed_ms'] = 1  # retained public receipt still costs10ms
            else:
                down['native_down']['elapsed_ms'] = 40  # enclosing DOWN is1ms
                native = next(event for event in value['daemon_events'] if event['event'] == 'down')
                native['elapsed_ms'] = 40
            event = next(event for event in value['scenario_events'] if event['event'] == 'down')
            event['value'] = copy.deepcopy(down)
            # Later terminal tokens intentionally stay unchanged: these controls
            # must reject the contradictory duration before reaching that join.
            with self.subTest(backend=backend), self.assertRaisesRegex(
                    AssertionError, 'sequential observations exceed enclosing elapsed'):
                contract.measure_backend(value)

    def test_registration_replays_authentication_and_raw_frames_not_only_actor_claims(self):
        actor = self.reference['actors'][1]
        contract.registration(actor, actor['registration'])
        for mutation in ('assertion', 'claim', 'raw_tail'):
            altered = copy.deepcopy(actor)
            value = altered['registration']
            if mutation == 'assertion':
                value['wire'][0]['sha256'] = '0'*64
            elif mutation == 'claim':
                value['result']['registration'][0]['body'] = [':1.999']
            else:
                value['wire'][-1]['hex'] += '00'
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.registration(altered, value)

    def test_missing_reordered_and_extra_events_fail(self):
        for mutation in ('missing', 'reordered', 'extra'):
            value = copy.deepcopy(self.reference)
            if mutation == 'missing':
                value['scenario_events'].pop(3)
            elif mutation == 'reordered':
                value['scenario_events'][3:5] = reversed(value['scenario_events'][3:5])
            else:
                value['scenario_events'].append(copy.deepcopy(value['scenario_events'][-1]))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.measure_backend(value)

    def test_missing_or_changed_target_cannot_be_replaced_by_claimed_summary(self):
        for mutation in ('missing', 'case', 'wire'):
            value = copy.deepcopy(self.reference)
            target = value['scenario']['groups'][0]['targets'][0]
            if mutation == 'missing':
                value['scenario']['groups'][0]['targets'].pop(0)
            elif mutation == 'case':
                target['case'] = 'collection'
            else:
                target['response']['wire'][0]['sha256'] = '0'*64
            value.update(status='passed_pending_independent_review', invariant_measurement=contract.expected_invariant())
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.validate_backend(value)

    def test_actor_identity_registration_and_receipt_joins_fail_closed(self):
        for mutation in ('uid', 'pid', 'registration', 'receipt', 'extra_receipt'):
            value = copy.deepcopy(self.reference)
            if mutation == 'uid':
                value['actors'][1]['identity']['uid'] = 1100
            elif mutation == 'pid':
                value['actors'][1]['identity']['pid'] = value['actors'][0]['identity']['pid']
            elif mutation == 'registration':
                value['actors'][1]['registration']['result']['bus_id'] = '0'*32
            elif mutation == 'receipt':
                value['receipts'][6]['identity'] = identity(999, 1101)
            else:
                value['receipts'].append(copy.deepcopy(value['receipts'][-1]))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.measure_backend(value)

    def test_saved_kernel_metrics_are_checked_against_raw_bytes(self):
        for mutation in ('incomplete', 'rss', 'overbound', 'cpu', 'incarnation', 'fd', 'credential'):
            value = sample(identity(50, 0))
            if mutation == 'incomplete':
                value.update(complete=False, errors=[dict(reason='enoent', observation='incomplete')])
            elif mutation == 'rss':
                value['rss_bytes'] += 1024
            elif mutation == 'overbound':
                value['rss_bytes'] = contract.BOUNDS['memory_bytes']+1024
                value['proc_status'] = value['proc_status'].replace('VmRSS:\t8 kB', 'VmRSS:\t262145 kB')
            elif mutation == 'cpu':
                value['cpu_ticks']['user'] = 99
            elif mutation == 'incarnation':
                value['starttime_ticks'] += 1
            elif mutation == 'fd':
                value['fd_count'] += 1
            else:
                value['proc_status'] = status(identity(50, 1100))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.process_sample(value, identity(50, 0))
        contract.process_sample(sample(identity(50, 0)), identity(50, 0))

    def test_native_pid_samples_accept_elixir_inspect_for_live_and_departed_processes(self):
        value = copy.deepcopy(self.gao['scenario']['groups'][0]['active']['resources']['native'])
        name = contract.CORE[0]
        value['core'][name] = value['processes'][name]['pid'] = '#PID<0.111.0>'
        value['processes']['source']['pid'] = '#PID<0.127.0>'
        contract.native_resources(value, identity(50, 0))
        value['processes']['source'].update(status='absent', metrics=None)
        contract.native_resources(value, identity(50, 0))

    def test_native_pid_samples_reject_noncanonical_forms_in_every_process_role(self):
        baseline = self.gao['snapshots'][0]['resources']['native']
        malformed = ('<0.111.0>', 'PID<0.111.0>', '#PID<0.111>', '#PID<0.-1.0>',
                     '#PID<0.111.0>extra', ' #PID<0.111.0>', '#PID<0.111.0>\n',
                     '#PID<\u0660.111.0>', '', 111)
        for pid in malformed:
            for role in ('core', 'observer', 'source'):
                value = copy.deepcopy(baseline)
                if role == 'core':
                    name = contract.CORE[0]
                    value['core'][name] = value['processes'][name]['pid'] = pid
                else:
                    value['processes'][role]['pid'] = pid
                with self.subTest(pid=pid, role=role), self.assertRaises(AssertionError):
                    contract.native_resources(value, identity(50, 0))

    def test_canonical_native_pid_replacement_still_fails_baseline_and_sample_joins(self):
        baseline = self.gao['snapshots'][0]['resources']['native']
        name = contract.CORE[0]
        for joined in (False, True):
            value = copy.deepcopy(baseline)
            value['core'][name] = '#PID<0.999.0>'
            if joined:
                value['processes'][name]['pid'] = value['core'][name]
            with self.subTest(joined=joined), self.assertRaises(AssertionError):
                contract.native_resources(value, identity(50, 0), baseline)

    def test_native_complete_memory_atom_and_process_samples_are_required(self):
        baseline = self.gao['snapshots'][0]['resources']['native']
        for mutation in ('memory', 'atom', 'incomplete', 'missing_metric', 'observer', 'replaced_core'):
            value = copy.deepcopy(baseline)
            if mutation == 'memory':
                value['vm']['memory']['total'] = contract.BOUNDS['memory_bytes']+1
            elif mutation == 'atom':
                value['vm']['atom_count'] += contract.BOUNDS['atom_growth']+1
            elif mutation == 'incomplete':
                value['processes']['observer']['complete'] = False
            elif mutation == 'missing_metric':
                value['processes']['observer']['metrics'].pop('message_queue_len')
            elif mutation == 'observer':
                value['processes']['observer']['pid'] = '#PID<0.999.0>'
            else:
                value['core'][contract.CORE[0]] = '#PID<0.999.0>'
            with self.subTest(mutation=mutation), self.assertRaises((AssertionError, KeyError)):
                contract.native_resources(value, identity(50, 0), baseline)

    def test_reference_cannot_claim_beam_monitor_or_native_resource_observations(self):
        value = copy.deepcopy(self.reference)
        value['snapshots'][0]['resources']['native'] = self.gao['snapshots'][0]['resources']['native']
        with self.assertRaises(AssertionError):
            contract.measure_backend(value)
        watch = copy.deepcopy(self.reference['scenario']['groups'][0]['watch'])
        watch['peer'] = '#PID<0.999.0>'
        with self.assertRaises(AssertionError):
            controller._watch(watch, self.reference['scenario']['groups'][0]['source'], 'reference', self.reference['observer'])

    def test_configuration_profile_version_and_monitor_drift_reject(self):
        for mutation in ('hash', 'profile', 'path', 'version', 'native_down'):
            value = copy.deepcopy(self.gao)
            if mutation == 'hash':
                value['configuration']['bytes'] += ' changed'
            elif mutation == 'profile':
                value['profile'] = 'network'
            elif mutation == 'path':
                value['configuration']['path'] = '/run/dbus/system_bus_socket'
            elif mutation == 'version':
                value['daemon']['version'] = 'unobserved version'
            else:
                value['scenario']['groups'][0]['down']['native_down']['monitored'] = False
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.measure_backend(value)

    def test_settle_count_order_endpoint_and_shared_bound_cannot_be_relaxed(self):
        for mutation in ('count', 'expected', 'endpoint', 'shared', 'deadline'):
            value = copy.deepcopy(self.reference)
            if mutation == 'count':
                value['settles'][0]['samples'] = 1
            elif mutation == 'expected':
                value['settles'][1]['expected'] = None
            elif mutation == 'endpoint':
                value['snapshots'][0]['authority']['endpoint']['inode'] += 1
            elif mutation == 'shared':
                # First group's restoration is settle4: each individual
                # observation is under1500ms but their shared total is false.
                value['settles'][4]['elapsed_ms'] = 1000
            else:
                value['scenario']['groups'][0]['down_restoration_ms'] = 1501
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.measure_backend(value)

    def test_failed_natural_teardown_cannot_count_as_passing(self):
        for mutation in ('source', 'observer', 'daemon', 'endpoint', 'time', 'error'):
            value = copy.deepcopy(self.reference)
            if mutation == 'source':
                value['retirements'][0]['before_containment']['timed_out'] = True
            elif mutation == 'observer':
                value['retirements'][-1]['before_containment']['wrapper_returncode'] = 1
            elif mutation == 'daemon':
                value['daemon_retirement']['forced'] = True
            elif mutation == 'endpoint':
                value['endpoint_removed'] = False
            elif mutation == 'time':
                value['shutdown_ms'] = 5001
            else:
                value['shutdown_errors'] = ['synthetic failure']
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                contract.measure_backend(value)

    def _complete_report(self, artifact_sha):
        artifact = dict(sources={str(i):dict(sha256='a'*64) for i in range(71)},
            files={str(i):dict(sha256='b'*64) for i in range(80)}, not_a_release=True,
            origin_pin=dict(sha256=contract.ORIGIN_SHA))
        backends = [copy.deepcopy(self.reference), copy.deepcopy(self.gao)]
        report = dict(version=1, fixture='PRO05-complete-core-source3', scenario=contract.SCENARIO,
            profile='core', selected=contract.SELECTED, backends=backends, bounds=contract.BOUNDS,
            candidate_artifact_sha256=artifact_sha, candidate_source_sha256=contract.source_sha(artifact),
            artifact=artifact, bindings=dict(artifact_sha256=artifact_sha, production_sources=71,
                artifact_files=80, runtime_manifest_sha256=contract.ORIGIN_SHA, not_a_release=True,
                profiles_prepared=['core'], network_profile_prepared=False, runtime_qualification=False),
            fixture_pins={('reference.conf' if row['backend'] == 'reference' else 'policy.exs'):
                dict(sha256=row['configuration']['sha256'], bytes=len(row['configuration']['bytes'].encode()))
                for row in backends}, result='passed_complete_core_PRO05_runtime_pending_independent_review',
            authority_elapsed_ms=1, readiness='L0', accepted_index_mutation=False,
            runtime_qualification=False, requirement_qualification=False, product_qualified=False,
            counts=dict(selected=2, executed=2, passed=2, failed=0, blocked=0, skipped=0))
        return report

    def test_complete_report_artifact_identity_matches_prepared_bindings_exactly(self):
        prepared_sha = json.loads(Path(__file__).with_name('bindings.json').read_text())['artifact_sha256']
        report = self._complete_report(prepared_sha)
        old_sha = '5d7c269f5a72ddbdcc37a1ae4654907743b0464785114974439c3e7dab7cd6f3'
        with patch.object(contract, 'validate_backend'):
            contract.validate_complete(report)
            for report_sha, binding_sha in ((old_sha, old_sha), ('0'*64, '0'*64),
                                            (prepared_sha, old_sha), (old_sha, prepared_sha)):
                value = copy.deepcopy(report)
                value['candidate_artifact_sha256'] = report_sha
                value['bindings']['artifact_sha256'] = binding_sha
                with self.subTest(report=report_sha, binding=binding_sha), self.assertRaises(AssertionError):
                    contract.validate_complete(value)

    def test_complete_report_selection_identity_bounds_and_false_flags(self):
        report = self._complete_report(contract.ARTIFACT_SHA)
        # This control isolates top-level joins; backend recomputation is tested
        # above against both complete synthetic backend records without mocks.
        with patch.object(contract, 'validate_backend') as backend_check:
            contract.validate_complete(report)
            self.assertEqual(backend_check.call_count, 2)
            for mutation in ('selection', 'count', 'bounds', 'source', 'artifact', 'policy_pin', 'qualification', 'deadline'):
                value = copy.deepcopy(report)
                if mutation == 'selection':
                    value['selected'].pop()
                elif mutation == 'count':
                    value['counts']['executed'] = 0
                elif mutation == 'bounds':
                    value['bounds']['atom_growth'] = 17
                elif mutation == 'source':
                    value['candidate_source_sha256'] = '0'*64
                elif mutation == 'artifact':
                    value['candidate_artifact_sha256'] = '0'*64
                elif mutation == 'policy_pin':
                    value['fixture_pins']['policy.exs']['sha256'] = '0'*64
                elif mutation == 'qualification':
                    value['runtime_qualification'] = True
                else:
                    value['authority_elapsed_ms'] = 240001
                with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                    contract.validate_complete(value)


if __name__ == '__main__':
    unittest.main()
