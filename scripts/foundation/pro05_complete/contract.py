"""Pure checks for retained PRO05 core observations, never runtime qualification.

Only supplied data is inspected. No paths, processes or endpoints are opened.
The finite endpoint measurements make no claim about peaks, soak or scaling.
"""
import hashlib
import json
import re

import controller
from vectors import CASES, wire_string
from wire_replay import (BUS, bounded, decode_frames, verify_observer, verify_target,
                         verify_terminal, verify_trace)

SCENARIO = 'PRO-05/complete-requirement'
BACKENDS = ('reference', 'gao_bus')
SELECTED = [SCENARIO + '/' + backend + '/core' for backend in BACKENDS]
INVARIANT = ('Work/memory/atom counts bounded; no arithmetic, pattern-match, or '
             'string-function crash in authority.')
BOUNDS = dict(source_ms=3000, observer_ms=1000, down_restoration_ms=1500,
              shutdown_ms=5000, memory_bytes=268435456, atom_growth=16)
ROOT = '/run/osbus-security/pro05-complete'
ARTIFACT_SHA = 'b77d142e49fdd1919b2d3692674d3e2416d6ff8ee348a663dbf1219052532db1'
ORIGIN_SHA = '6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5'
CORE = tuple('Elixir.GaoBus.' + name for name in (
    'Supervisor', 'Ids', 'PeerRegistry', 'Router', 'NameRegistry', 'Limits',
    'Policy', 'MatchRules', 'Policy.Capability', 'PeerSupervisor', 'Listener'))
PROCESS_METRICS = ('reductions', 'memory', 'total_heap_size', 'stack_size', 'message_queue_len')
VM_METRICS = ('reductions', 'atom_count', 'process_count', 'port_count')
MEMORY_METRICS = ('total', 'processes_used', 'binary', 'ets', 'atom_used')
AUTHORITY_FIELDS = {'core', 'router', 'peers', 'names', 'queues', 'usage', 'policy',
                    'match_rules_state', 'capability_state', 'match_rules_table', 'capabilities_table'}
FLOAT_ROUNDOFF_MS = 0.000001


def elapsed_within(elapsed, enclosing, native_intervals=0):
    """Join nested durations without extending any operation deadline.

    Python retains fractional monotonic milliseconds. Native samples subtract
    two integer millisecond timestamps, so each disjoint native interval can
    overstate its actual duration by less than 1ms. Python sums receive only a
    one-nanosecond allowance for floating-point subtraction/addition roundoff.
    """
    assert type(native_intervals) is int and native_intervals >= 0
    bounded(enclosing, 240000)
    bounded(elapsed, 240000)
    assert elapsed <= enclosing + native_intervals + FLOAT_ROUNDOFF_MS, 'sequential observations exceed enclosing elapsed'


def source_sha(artifact):
    return hashlib.sha256(json.dumps(artifact['sources'], sort_keys=True).encode()).hexdigest()


def expected_invariant():
    return dict(categories=['deep signatures/containers', 'adversarial match argument values',
                            'large collections', 'repeated invalid prefixes'],
                source_groups=37, targets=41, prefix_incarnations=32,
                exact_finite_inputs=True, raw_receipts_bound=True,
                distinct_kernel_actors=True, observer_identity_preserved=True,
                authority_fd_restored=True, sampled_memory_bounded=True,
                sampled_atom_growth_bounded=True, normal_source_retirement=True,
                natural_teardown=True)


def process_sample(value, identity):
    """Check saved kernel bytes and numeric projections without reading /proc."""
    from run import kernel
    assert value['identity'] == identity
    assert value['complete'] is True and value['errors'] == []
    kernel(value['proc_status'], identity)
    rows = {row.split(':', 1)[0]: row.split(':', 1)[1].split()
            for row in value['proc_status'].splitlines() if ':' in row}
    assert rows['VmRSS'][1:] == ['kB']
    assert type(value['rss_bytes']) is int and value['rss_bytes'] == int(rows['VmRSS'][0]) * 1024
    assert 0 < value['rss_bytes'] <= BOUNDS['memory_bytes']
    assert type(value['starttime_ticks']) is int and value['starttime_ticks'] > 0
    for raw in (value['proc_stat'], value['proc_stat_after']):
        assert raw.split(' ', 1)[0] == str(identity['pid'])
        fields = raw[raw.rfind(')') + 2:].split()
        assert int(fields[19]) == value['starttime_ticks']
    fields = value['proc_stat'][value['proc_stat'].rfind(')') + 2:].split()
    assert value['cpu_ticks'] == dict(user=int(fields[11]), system=int(fields[12]))
    assert all(type(n) is int and n >= 0 for n in value['cpu_ticks'].values())
    assert type(value['fd_targets']) is dict and value['fd_targets']
    assert all(type(fd) is str and fd.isdecimal() and type(target) is str and target
               for fd, target in value['fd_targets'].items())
    assert type(value['fd_count']) is int and value['fd_count'] == len(value['fd_targets'])


def _metrics(value, keys):
    assert type(value) is dict and set(value) == set(keys)
    assert all(type(value[key]) is int and value[key] >= 0 for key in keys)


def native_resources(value, daemon_identity, baseline=None):
    assert value['complete'] is True and set(value['core']) == set(CORE)
    assert all(type(pid) is str and re.fullmatch(r'#PID<[0-9]+\.[0-9]+\.[0-9]+>', pid)
               for pid in value['core'].values())
    assert len(set(value['core'].values())) == len(CORE)
    assert set(value['processes']) == set(CORE) | {'source', 'observer'}
    for name, sample in value['processes'].items():
        assert sample['complete'] is True and sample['error'] is None
        if sample['status'] == 'live':
            assert type(sample['pid']) is str and re.fullmatch(r'#PID<[0-9]+\.[0-9]+\.[0-9]+>', sample['pid'])
            _metrics(sample['metrics'], PROCESS_METRICS)
        else:
            assert sample['status'] == 'absent' and sample['metrics'] is None
            assert sample['pid'] is None or (type(sample['pid']) is str and
                                             re.fullmatch(r'#PID<[0-9]+\.[0-9]+\.[0-9]+>', sample['pid']))
        if name in CORE:
            assert sample['status'] == 'live' and sample['pid'] == value['core'][name]
    assert value['processes']['observer']['status'] == 'live'
    vm = value['vm']
    assert vm['identity'] == str(daemon_identity['pid'])
    _metrics({key: vm[key] for key in VM_METRICS}, VM_METRICS)
    _metrics(vm['memory'], MEMORY_METRICS)
    assert vm['atom_count'] > 0 and 0 < vm['memory']['total'] <= BOUNDS['memory_bytes']
    if baseline is not None:
        assert value['core'] == baseline['core']
        assert value['processes']['observer']['pid'] == baseline['processes']['observer']['pid']
        assert vm['identity'] == baseline['vm']['identity']
        assert vm['atom_count'] - baseline['vm']['atom_count'] <= BOUNDS['atom_growth']


def resources(value, backend, daemon_identity, observer, baseline=None):
    assert set(value) == ({'daemon', 'observer', 'native'} if backend == 'gao_bus'
                          else {'daemon', 'observer'})
    process_sample(value['daemon'], daemon_identity)
    process_sample(value['observer'], observer['identity'])
    if backend == 'gao_bus':
        native_resources(value['native'], daemon_identity,
                         None if baseline is None else baseline['native'])


def retirement(value, identity):
    controller._retirement(value)
    assert value['identity'] == identity
    assert value['pid_absent'] is value['actor_pid_absent'] is value['group_absent'] is True
    before = value['before_containment']
    assert before['stdin_closed'] is before['wrapper_waited'] is True
    assert before['wrapper_returncode'] == 0
    bounded(before['elapsed_ms'], BOUNDS['shutdown_ms'])


def registration(actor, response):
    """Bind kernel actor, EXTERNAL assertion and actual registration frames."""
    from run import kernel, query_wire
    identity = actor['identity']
    controller._actor(actor, identity['uid'])
    assert identity['uid'] in (1100, 1101) and actor['serial'] == 2
    kernel(actor['proc_status'], identity)
    assert actor['registration'] == response
    assertion = str(identity['uid']).encode().hex().encode()
    raw = verify_trace(response, [b'\0AUTH EXTERNAL ' + assertion + b'\r\n',
                       b'BEGIN\r\n' + query_wire('Hello', 1) + query_wire('GetId', 2)], 3000)
    auth, separator, binary = raw.partition(b'\r\n')
    assert separator and re.fullmatch(rb'OK [0-9a-fA-F]{32}', auth)
    frames = decode_frames(binary)
    rows = [frame['message'] for frame in frames]
    result = response['result']
    assert len(rows) == 3 and result['registration'] == rows
    replies = [frame for frame in frames if frame['message']['type'] == 2]
    signals = [frame for frame in frames if frame['message']['type'] == 4]
    assert len(replies) == 2 and len(signals) == 1
    for frame, serial, body in zip(replies, (1, 2), ([actor['unique']], [actor['bus_id']])):
        row = frame['message']
        assert row['reply_serial'] == serial and row['body'] == body
        assert row['sender'] == BUS and row['error'] is None
        assert frame['fields'].get(6) == actor['unique'] and frame['fields'].get(8) == 's'
    signal = signals[0]
    assert signal['message']['sender'] == signal['message']['interface'] == BUS
    assert signal['message']['member'] == 'NameAcquired' and signal['message']['body'] == [actor['unique']]
    assert signal['fields'].get(6) == actor['unique'] and signal['fields'].get(8) == 's'
    assert {key: result[key] for key in replies[0]['message']} == replies[0]['message']
    assert result['unique'] == actor['unique'] and result['bus_id'] == actor['bus_id']
    assert result['buffered_hex'] == '' and result['pending_messages'] == 0


class Receipts:
    """One exact cursor prevents missing, reused or unaccounted actor operations."""
    def __init__(self, values):
        self.values, self.index = values, 0
        self.elapsed_ms = 0

    def take(self, identity, command, response=None):
        assert self.index < len(self.values), 'missing receipt'
        value = self.values[self.index]
        self.index += 1
        assert value['identity'] == identity
        request = dict(value['request'])
        deadline = request.pop('deadline_monotonic')
        assert type(deadline) in (int, float) and 0 < deadline < float('inf')
        # JSON serializes tuple bodies as arrays.
        assert json.loads(json.dumps(request)) == json.loads(json.dumps(command))
        bounded(value['elapsed_ms'], 1000 if command['op'] == 'observe' else 3000)
        elapsed_within(value['response']['elapsed_ms'], value['elapsed_ms'])
        self.elapsed_ms += value['elapsed_ms']
        if response is not None:
            assert value['response'] == response
        assert value['response']['ok'] is True
        return value['response']

    def finish(self):
        assert self.index == len(self.values), 'unaccounted receipts'


def metadata(record):
    from run import kernel
    backend = record['backend']
    assert backend in BACKENDS and record['profile'] == 'core'
    config, daemon = record['configuration'], record['daemon']
    assert config['system_mode'] is config['external_only'] is config['isolated'] is True
    assert type(config['bytes']) is str and config['bytes']
    assert hashlib.sha256(config['bytes'].encode()).hexdigest() == config['sha256']
    filename = 'policy.exs' if backend == 'gao_bus' else 'reference.conf'
    assert config['backend'] == backend and config['profile'] == 'core'
    assert config['path'] == ROOT + '/' + backend + '/' + filename
    assert config['endpoint'] == ROOT + '/' + backend + '/bus'
    controller._identity(daemon['identity'], 0)
    kernel(daemon['proc_status'], daemon['identity'])
    assert type(daemon['version']) is str and daemon['version'].strip()
    argv = daemon['argv']
    assert type(argv) is list and argv and all(type(x) is str and x for x in argv)
    assert argv in record['commands']
    if backend == 'reference':
        version = record['reference_version']
        assert version['returncode'] == 0 and version['stdout'] == daemon['version']
        assert 'D-Bus Message Bus Daemon' in daemon['version']
        assert argv[0].startswith('/nix/store/') and argv[0].endswith('/bin/dbus-daemon')
        assert argv[1:] == ['--nofork', '--nopidfile', '--config-file=' + config['path']]
        assert version['argv'] == [argv[0], '--version'] and version['argv'] in record['commands']
        assert re.fullmatch('[0-9a-f]{64}', version['executable']['sha256'])
        assert type(version['executable']['bytes']) is int and version['executable']['bytes'] > 0
        assert record['daemon_events'] == []
        assert 'ready' not in record
    else:
        ready = record['ready']
        assert ready['event'] == 'ready' and int(ready['pid']) == daemon['identity']['pid']
        assert ready['identity']['uid'] == ready['identity']['gid'] == 0
        assert ready['identity']['real_uid'] == ready['identity']['real_gid'] == 0
        assert daemon['version'] == ready['otp'] + ' / Elixir ' + ready['elixir']
        assert argv[:3] == ['elixir', '--erl', '+S 2:2']
        assert re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-os-bus-pro05-fixtures/daemon\.exs', argv[-3])
        assert argv[-2:] == [ROOT + '/gao_bus/bus', config['path']]
        observed = ready['configuration']
        assert observed['profile'] == 'system' and observed['lifecycle'] == 'embedded'
        assert observed['config_file'] is None and observed['inherited_listener'] is False
        assert observed['socket_path'] == ROOT + '/gao_bus/bus'
        assert observed['authentication'] == ['EXTERNAL']
        assert observed['cluster'] is observed['capability_restrictions'] is False
        assert observed['auth_limits'] == dict(timeout_ms=1500, idle_timeout_ms=500)
        assert observed['resource_limits']['peer']['frame_bytes'] == 1048576


def measure_backend(record):
    """Recompute only after natural teardown; summary/status are not inputs."""
    from actor_overlay import _call
    from run import MATCH, OWNER, checked_reply, settled_projection
    metadata(record)
    assert 'failure' not in record
    backend, observer = record['backend'], record['observer']
    controller._actor(observer, 1100)
    assert observer['owner'] == OWNER
    actors = record['actors']
    assert len(actors) == 38 and actors[0]['phase'] == 'observer'
    assert {key: actors[0][key] for key in ('identity', 'unique', 'bus_id')} == {
        key: observer[key] for key in ('identity', 'unique', 'bus_id')}
    assert len({actor['identity']['pid'] for actor in actors} | {record['daemon']['identity']['pid']}) == 39
    assert len({actor['unique'] for actor in actors}) == 38
    receipts = Receipts(record['receipts'])
    registration(actors[0], receipts.take(observer['identity'], dict(op='register')))
    serial = 2

    def ordinary(member, signature='', body=(), expected=None):
        nonlocal serial
        serial += 1
        response = receipts.take(observer['identity'], dict(op='call', member=member,
                                  signature=signature, body=body))
        row = checked_reply(response, member, serial, signature, body, observer['unique'])
        if expected is not None:
            assert row['body'] == [expected]
        return response

    def setup_call(member, signature, body, expected, acquired=False):
        nonlocal serial
        serial += 1
        response = receipts.take(observer['identity'], dict(op='call', member=member,
                                  signature=signature, body=body))
        payload = b''.join(wire_string(item) if type(item) is str else item.to_bytes(4, 'little') for item in body)
        raw = verify_trace(response, [_call(member, serial, signature, payload)], 3000)
        polled = None
        if acquired:
            polled = receipts.take(observer['identity'], dict(op='poll', timeout=0.05))
            binary = raw + verify_trace(polled, [], 3000)
        else:
            binary = raw
        frames = decode_frames(binary)
        replies = [frame for frame in frames if frame['message']['type'] == 2]
        assert len(replies) == 1 and replies[0]['message'] == response['result']
        row = response['result']
        assert row['type'] == 2 and row['sender'] == BUS and row['reply_serial'] == serial
        assert row['body'] == expected and row['error'] is None
        assert replies[0]['fields'].get(6) == observer['unique']
        assert replies[0]['fields'].get(8, '') == ('u' if member == 'RequestName' else '')
        if acquired:
            signals = [frame for frame in frames if frame['message']['type'] == 4]
            assert len(frames) == 2 and len(signals) == 1
            signal = signals[0]
            assert polled['result'] == [signal['message']]
            row = signal['message']
            assert row['sender'] == row['interface'] == BUS
            assert row['member'] == 'NameAcquired' and row['body'] == [OWNER]
            assert signal['fields'].get(6) == observer['unique'] and signal['fields'].get(8) == 's'
            # The reply must already have arrived during RequestName, even
            # when the signal is queued before it or buffered into the poll.
            offset = 0
            for frame in frames:
                endian = 'little' if binary[offset] == ord('l') else 'big'
                body_size = int.from_bytes(binary[offset+4:offset+8], endian)
                header_size = int.from_bytes(binary[offset+12:offset+16], endian)
                offset += 16 + header_size + (-header_size % 8) + body_size
                if frame['message']['type'] == 2:
                    assert offset <= len(raw)
        else:
            assert len(frames) == 1

    setup_call('RequestName', 'su', [OWNER, 0], [1], acquired=True)
    setup_call('AddMatch', 's', [MATCH], [])
    polled = receipts.take(observer['identity'], dict(op='poll', timeout=0.05))
    assert verify_trace(polled, [], 3000) == b'' and polled['result'] == []

    scenario = record['scenario']
    assert scenario['backend'] == backend and scenario['result'] == 'pending-independent-runtime-review'
    assert scenario['runtime_qualification'] is False
    assert scenario['counts'] == dict(source_groups=37, targets=41)
    groups = scenario['groups']
    assert len(groups) == len(controller.GROUPS)
    events, event_index = record['scenario_events'], 0
    native_events = record['daemon_events']
    native_index = 0
    native_elapsed_ms = 0
    sample_index, settle_index = 0, 0
    baseline = None

    def event(kind, **data):
        nonlocal event_index
        assert event_index < len(events), 'missing scenario event'
        assert events[event_index] == dict(event=kind, runtime_qualification=False, **data)
        event_index += 1

    def native(kind, authority, resource, source_name=None, retained=None):
        nonlocal native_index, native_elapsed_ms
        assert native_index < len(native_events), 'missing native observation'
        value = native_events[native_index]
        native_index += 1
        if retained is not None:
            assert value == retained
        assert value['event'] == kind and value['complete'] is True and value['errors'] == []
        assert value['observer'] == observer['unique']
        bounded(value['elapsed_ms'], 1500)
        assert type(value['elapsed_ms']) is int
        native_elapsed_ms += value['elapsed_ms']
        assert value['authority'] == authority and value['resources'] == resource
        assert set(authority) == AUTHORITY_FIELDS
        assert authority['core'] == resource['core'] == record['ready']['core']
        native_resources(resource, record['daemon']['identity'],
                         None if baseline is None else baseline['resources']['native'])
        if kind == 'sample':
            assert value['source'] == source_name
        return value

    def snapshot(value, source=None, expected=None):
        nonlocal sample_index, settle_index, baseline
        event('snapshot', source=None if source is None else source['identity'], value=value)
        assert settle_index < len(record['settles'])
        settle = record['settles'][settle_index]
        settle_index += 1
        count = settle['samples']
        assert type(count) is int and 2 <= count <= 128
        bounded(settle['budget_ms'], 1500)
        assert settle['budget_ms'] > 0
        bounded(settle['elapsed_ms'], settle['budget_ms'])
        expected_projection = (settled_projection(baseline) if source is None and baseline is not None else None)
        assert settle['expected'] == expected_projection
        samples = record['snapshots'][sample_index:sample_index+count]
        sample_index += count
        assert len(samples) == count and samples[-1] == value
        receipt_elapsed_start, native_elapsed_start = receipts.elapsed_ms, native_elapsed_ms
        for sampled in samples:
            controller._snapshot(sampled, observer, source)
            resources(sampled['resources'], backend, record['daemon']['identity'], observer,
                      None if baseline is None else baseline['resources'])
            names = ordinary('ListNames')['result']['body']
            assert len(names) == 1 and sorted(names[0]) == sampled['authority']['names']
            ordinary('GetNameOwner', 's', [OWNER], observer['unique'])
            ordinary('GetConnectionUnixUser', 's', [observer['unique']], 1100)
            ordinary('GetConnectionUnixProcessID', 's', [observer['unique']], observer['identity']['pid'])
            ordinary('GetId', expected=observer['bus_id'])
            if source is not None:
                ordinary('GetConnectionUnixUser', 's', [source['unique']], 1101)
                ordinary('GetConnectionUnixProcessID', 's', [source['unique']], source['identity']['pid'])
            if backend == 'gao_bus':
                native('sample', sampled['authority']['core'], sampled['resources']['native'],
                       None if source is None else source['unique'])
                assert sampled['resources']['native']['processes']['source']['status'] == (
                    'absent' if source is None else 'live')
            else:
                assert sampled['authority']['core'] == dict(identity=record['daemon']['identity'],
                    starttime_ticks=sampled['resources']['daemon']['starttime_ticks'])
            if baseline is not None:
                assert sampled['authority']['endpoint'] == baseline['authority']['endpoint']
                for role in ('daemon', 'observer'):
                    assert sampled['resources'][role]['starttime_ticks'] == baseline['resources'][role]['starttime_ticks']
        elapsed_within(receipts.elapsed_ms - receipt_elapsed_start + native_elapsed_ms - native_elapsed_start,
                       settle['elapsed_ms'], count if backend == 'gao_bus' else 0)
        assert settled_projection(samples[-1]) == settled_projection(samples[-2])
        if expected_projection is not None:
            assert settled_projection(value) == expected_projection
        if expected is not None:
            assert settled_projection(value) == settled_projection(expected)
        if baseline is None:
            baseline = value

    def observe(summary, source_name=None):
        nonlocal serial
        serial += 1
        value = events[event_index]['value']
        event('observer', value=value)
        assert value['serial'] == serial
        receipts.take(observer['identity'], dict(op='observe', serial=serial,
                      owner=OWNER, source_name=source_name), value['response'])
        assert summary == verify_observer(value['response'], OWNER, observer['unique'],
                                           observer['bus_id'], serial, source_name)
        serial += 1

    assert events and events[0]['event'] == 'snapshot'
    snapshot(events[0]['value'])
    for actor, group, (family, iteration, cases) in zip(actors[1:], groups, controller.GROUPS):
        assert group['family'] == family and group['iteration'] == iteration
        assert actor['phase'] == family + '-' + str(iteration)
        source = group['source']
        controller._actor(source, 1101, observer['bus_id'])
        assert {key: actor[key] for key in ('identity', 'unique', 'bus_id')} == source
        assert [target['case'] for target in group['targets']] == list(cases)
        snapshot(group['before'], expected=baseline)
        registration(actor, receipts.take(source['identity'], dict(op='register')))
        event('source', family=family, iteration=iteration, value=source)
        snapshot(group['active'], source)
        watch = group['watch']
        event('watch', value=watch)
        controller._watch(watch, source, backend, observer)
        if backend == 'reference':
            assert ordinary('NameHasOwner', 's', [source['unique']], True) == watch['watch_receipt']
        else:
            raw = watch['watch_event']
            native('watched', raw['authority'], raw['resources'], retained=raw)
            assert raw['resources']['processes']['source']['pid'] == watch['peer']
            assert raw['resources']['processes']['source']['status'] == 'live'
            assert watch['peer'] == group['active']['resources']['native']['processes']['source']['pid']
            options = raw['peer_options']
            assert options['frame_options']['max_bytes'] == 1048576
            assert options['xml_limits'] is None and options['frame_timeout_ms'] == 5000
            assert options['auth_limits'] == dict(timeout_ms=1500, idle_timeout_ms=500)
        terminal_case = None
        for target in group['targets']:
            case, response = target['case'], target['response']
            event('target', case=case, iteration=iteration, response=response)
            receipts.take(source['identity'], dict(op='target', case=case), response)
            assert target['verification'] == verify_target(case, response, source['unique'], source['bus_id'])
            if CASES[case]['oracle'] == 'close':
                terminal_case = case
                assert set(target) == {'case', 'response', 'verification'}
            else:
                observe(target['observer'], source['unique'] if case == 'match_string' else None)
                snapshot(target['after'], source, group['active'])
        if terminal_case is None:
            assert 'terminal' not in group
            closed = group['close']
            event('explicit-close', response=closed)
            receipts.take(source['identity'], dict(op='close'), closed)
            assert verify_trace(closed, [], 3000) == b'' and closed['wire'] == []
            assert closed['result'] == dict(disposition='controller-close', socket_closed=True)
        else:
            assert 'close' not in group
        down = group['down']
        event('down', value=down)
        controller._down(down, watch, source, backend, observer)
        bounded(group['down_restoration_ms'], 1500)
        assert down['elapsed_ms'] <= group['down_restoration_ms']
        if backend == 'reference':
            attempts = down['attempts']
            assert 1 <= len(attempts) <= 128 and attempts[-1] == down['public_reply']
            receipt_elapsed_start = receipts.elapsed_ms
            for index, response in enumerate(attempts):
                assert ordinary('NameHasOwner', 's', [source['unique']], index < len(attempts)-1) == response
            elapsed_within(receipts.elapsed_ms - receipt_elapsed_start, down['elapsed_ms'])
        else:
            raw = down['native_down']
            native('down', raw['authority'], raw['resources'], retained=raw)
            assert raw['reason'] == 'normal' and raw['monitored'] is raw['watch_removed'] is True
            assert raw['watches'] == 0 and raw['elapsed_basis'] == 'await_down matching receive and fresh capture'
            bounded(raw['down_elapsed_ms'], raw['elapsed_ms'])
            elapsed_within(raw['elapsed_ms'], down['elapsed_ms'], native_intervals=1)
            assert raw['resources']['processes']['source']['status'] == 'absent'
            assert raw['resources']['processes']['source']['pid'] == watch['peer']
        snapshot(group['restoration'], expected=baseline)
        restoration_settle = record['settles'][settle_index-1]
        elapsed_within(down['elapsed_ms'] + restoration_settle['elapsed_ms'], group['down_restoration_ms'])
        assert restoration_settle['budget_ms'] <= 1500 - down['elapsed_ms'] + FLOAT_ROUNDOFF_MS
        if terminal_case is not None:
            terminal = group['terminal']
            token = controller.authorization(down, group['restoration'])
            assert terminal['authorization'] == token
            event('terminal-authorization', authorization=token, down=down, restoration=group['restoration'])
            event('terminal', response=terminal['response'])
            receipts.take(source['identity'], dict(op='terminal', case=terminal_case,
                          authorization=token), terminal['response'])
            assert terminal['verification'] == verify_terminal(terminal_case, terminal['response'], token)
        observe(group['observer'])
        event('retirement', value=group['retirement'])
        retirement(group['retirement'], source['identity'])
        snapshot(group['after'], expected=baseline)
        event('group-complete', family=family, iteration=iteration, target_count=len(cases))
    event('pending-independent-runtime-review', counts=scenario['counts'])
    assert event_index == len(events)
    assert sample_index == len(record['snapshots']) and settle_index == len(record['settles'])
    receipts.finish()
    if backend == 'gao_bus':
        assert native_events[native_index:] == [dict(event='stopped', normal=True, watches=0)]
    assert len(record['retirements']) == 38
    expected_retirements = [group['retirement'] for group in groups]
    assert record['retirements'][:-1] == expected_retirements
    retirement(record['retirements'][-1], observer['identity'])
    assert record['shutdown_errors'] == [] and record['endpoint_removed'] is True
    bounded(record['shutdown_ms'], 5000)
    stop = record['daemon_retirement']
    assert stop['method'] == ('eof' if backend == 'gao_bus' else 'sigterm')
    assert stop['returncode'] == 0 and stop['pid_absent'] is stop['group_absent'] is True
    if backend == 'gao_bus':
        retirement(stop, record['daemon']['identity'])
    else:
        assert stop['forced'] is False
        bounded(stop['elapsed_ms'], 5000)
    return expected_invariant()


def validate_backend(record):
    assert record['status'] == 'passed_pending_independent_review'
    assert record['invariant_measurement'] == measure_backend(record) == expected_invariant()


def validate_complete(report):
    assert report['version'] == 1 and report['fixture'] == 'PRO05-complete-core-source3'
    assert report['scenario'] == SCENARIO and report['profile'] == 'core'
    assert report['selected'] == SELECTED and [row['backend'] for row in report['backends']] == list(BACKENDS)
    assert report['counts'] == dict(selected=2, executed=2, passed=2, failed=0, blocked=0, skipped=0)
    assert report['bounds'] == BOUNDS
    assert report['candidate_artifact_sha256'] == report['bindings']['artifact_sha256'] == ARTIFACT_SHA
    assert report['candidate_source_sha256'] == source_sha(report['artifact'])
    bindings, artifact = report['bindings'], report['artifact']
    assert bindings['production_sources'] == len(artifact['sources']) == 71
    assert bindings['artifact_files'] == len(artifact['files']) == 80
    assert bindings['runtime_manifest_sha256'] == artifact['origin_pin']['sha256'] == ORIGIN_SHA
    assert artifact['not_a_release'] is bindings['not_a_release'] is True
    assert bindings['profiles_prepared'] == ['core'] and bindings['network_profile_prepared'] is False
    assert bindings['runtime_qualification'] is False
    assert report['result'] == 'passed_complete_core_PRO05_runtime_pending_independent_review'
    bounded(report['authority_elapsed_ms'], 240000)
    assert report['readiness'] == 'L0'
    for key in ('accepted_index_mutation', 'runtime_qualification', 'requirement_qualification', 'product_qualified'):
        assert report[key] is False
    assert 'failure' not in report
    for record in report['backends']:
        filename = 'policy.exs' if record['backend'] == 'gao_bus' else 'reference.conf'
        pin = report['fixture_pins'][filename]
        assert pin['sha256'] == record['configuration']['sha256']
        assert pin['bytes'] == len(record['configuration']['bytes'].encode())
        validate_backend(record)
