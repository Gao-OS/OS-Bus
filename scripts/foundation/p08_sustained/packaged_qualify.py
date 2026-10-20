"""Disposable-VM packaged console soak; pure completion/accounting oracles."""
import base64
from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import random
import re
import secrets
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time

from channel import Actor, Channel
from packaged_diagnostic_channel import DiagnosticActor
from packaged_diagnostics import Diagnostics
from packaged_console import Console
from packaged_capture import policy_contract
import packaged_policy_probe
from qualify import external, verify_settled

FIXTURES = Path(__file__).resolve().parent
WORKLOAD = json.loads((FIXTURES / 'workload.json').read_text())
BASE = Path('/run/osbus-p08')
EVIDENCE = BASE / 'evidence'
METRICS = set(('connections authenticating ingress_messages ingress_bytes ingress_fds '
               'egress_messages egress_bytes egress_fds frame_bytes frame_fds '
               'activation_messages activation_bytes activation_fds').split())
QUEUE_KEYS = set(('buffer_bytes incoming_fds output_messages output_fds output_bytes '
                  'current_output route_wait auth_continuing messages_continuing '
                  'read_scheduled frame_timer pending_fd_timer mailbox').split())
AUTHORITIES = set(('GaoBus.Supervisor GaoBus.Ids GaoBus.PeerRegistry GaoBus.Limits GaoBus.Policy '
                   'GaoBus.NameRegistry GaoBus.MatchRules GaoBus.Policy.Capability GaoBus.Router '
                   'GaoBus.Activation.HelperSupervisor GaoBus.Activation GaoBus.PeerSupervisor GaoBus.Listener').split())
XML_CONNECTION_KEYS = {'max_completed_connections', 'max_incomplete_connections', 'max_connections_per_user', 'auth_timeout'}
XML_QUEUE_KEYS = {'max_incoming_bytes', 'max_outgoing_bytes', 'max_incoming_unix_fds', 'max_outgoing_unix_fds'}
REFERENCE_UNIT = 'osbus-p08-policy-reference.service'
REFERENCE_GROUP = '/system.slice/' + REFERENCE_UNIT
ROWS = ['policy-reference', 'policy-start', 'policy-start_iex', 'startup-equivalence',
        'whole-accounting', 'peer-kill', 'three-batches', 'sustained', 'cleanup']


class HealthGate:
    """Atomic captures and actor calls, with queued regular health admitted first."""
    def __init__(self):
        self.condition = threading.Condition()
        self.pending = []
        self.active = False
        self.receipts = []

    @contextmanager
    def section(self, kind, operation_index):
        receipt = dict(kind=kind, operation_index=operation_index, queued=time.monotonic())
        with self.condition:
            self.pending.append(receipt)
            self.receipts.append(receipt)
            while True:
                selected = next((row for row in self.pending if row['kind'] == 'health-regular'),
                                self.pending[0])
                if not self.active and selected is receipt:
                    break
                self.condition.wait()
            self.pending.remove(receipt)
            self.active = True
            receipt['acquired'] = time.monotonic()
            receipt['wait_ms'] = (receipt['acquired'] - receipt['queued']) * 1000
        try:
            yield receipt
        finally:
            with self.condition:
                receipt['released'] = time.monotonic()
                receipt['hold_ms'] = (receipt['released'] - receipt['acquired']) * 1000
                self.active = False
                self.condition.notify_all()


def reference_policy_xml(original):
    listener = b'<listen>unix:path=/run/osbus-p08/socket/bus</listen>'
    assert original.count(listener) == original.count(b'<listen>') == 1, 'exact sole private listener required'
    return original.replace(listener, b'<listen>unix:path=/run/osbus-p08/reference/bus</listen>')


def verify_policy_contract(contract):
    assert contract == policy_contract(), 'exact adopted standard-XML policy contract required'
    return contract


def verify_policy_probes(probes):
    assert set(probes) == {'reference', 'start', 'start_iex'}, 'all three policy backends required'
    for backend, result in probes.items():
        assert result['backend'] == backend and result['status'] == 'passed', 'policy backend/status binding'
        assert all(type(value) is int for value in result['counts'].values()), 'integer policy accounting required'
        packaged_policy_probe.validate_complete(result['rows'], result['counts'])
        assert len(result['shutdown']) == 2, 'both policy actors must be reaped'
        assert all(row['method'] == 'eof' and type(row['returncode']) is int and row['returncode'] == 0
                   for row in result['shutdown']), 'policy actor emergency/failed shutdown'
    return probes


def verify_reference_cleanup(receipt):
    assert receipt['main_gone'] is True and receipt['socket_removed'] is True, 'reference process/endpoint retained'
    assert receipt['cgroup_pids'] == [] and receipt['properties']['MainPID'] == '0', 'reference cgroup/main retained'
    assert receipt['properties']['ControlGroup'] in ('', REFERENCE_GROUP), 'unowned reference cgroup'
    return receipt


def integer(value, minimum=0):
    assert type(value) is int and value >= minimum, ('invalid nonnegative integer', value)
    return value


def finite(value):
    assert type(value) in (int, float) and math.isfinite(value) and value >= 0, ('invalid clock', value)
    return value


def operation_counts(counts, total):
    assert isinstance(counts, dict) and set(counts) == set(WORKLOAD['operations']), 'operation set drift'
    assert all(integer(value, 1) for value in counts.values()), 'unexecuted operation'
    assert sum(counts.values()) == total, ('operation total', counts, total)



def verify_health(health, warmup_started, sustained):
    """Account every absolute50ms due time, including scheduling/lock delay."""
    started, finished = finite(health['started']), finite(health['finished'])
    assert started <= finite(warmup_started) <= sustained['started'], 'health started after workload'
    assert finished >= sustained['finished'], 'health ended before sustained work'
    interval = WORKLOAD['health_interval_ms'] / 1000
    observations = health['observations']
    expected = math.floor((finished - started) / interval + 1e-7) + 1
    assert integer(health['count'], 1) == len(observations) == expected, 'missing/unfinished healthy probe'
    assert health['errors'] == [], 'health failure'
    maximum, previous_finish = 0, started
    for index, row in enumerate(observations):
        assert integer(row['index']) == index, 'health observation order'
        due, requested = finite(row['due']), finite(row['requested'])
        actual_start, end = finite(row['started']), finite(row['finished'])
        assert math.isclose(due, started + index * interval, rel_tol=0, abs_tol=1e-9), 'health due gap/drift'
        assert due <= finished + 1e-9 and requested >= max(due, previous_finish), 'stale/overlapping healthy probe'
        assert requested <= actual_start <= end, 'health clock order'
        latency = max((end - due) * 1000, finite(row['actor']['latency_ms']))
        for key, actual in [('dispatch_lag_ms', (actual_start - due) * 1000),
                            ('actual_ms', (end - actual_start) * 1000), ('latency_ms', latency)]:
            assert math.isclose(finite(row[key]), actual, rel_tol=0, abs_tol=1e-6), ('fabricated health receipt', key)
        assert latency <= WORKLOAD['healthy_probe_ms'], 'end-to-end healthy deadline'
        maximum, previous_finish = max(maximum, latency), end
    assert math.isclose(finite(health['max_ms']), maximum, rel_tol=0, abs_tol=1e-6), 'fabricated/stale maximum latency'
    return {'planned_count': expected, 'observed_count': len(observations),
            'first_due': observations[0]['due'], 'last_due': observations[-1]['due'],
            'coverage_until': finished, 'observed_until': previous_finish, 'max_ms': maximum}


def verify_iex_initialization(environment, passwd_home, work):
    assert 'IEX_HOME' not in environment, 'unexpected service IEX_HOME'
    assert environment.get('HOME') == passwd_home and Path(passwd_home).is_absolute(), 'actual service HOME differs from passwd'
    lookup_home, work = Path(environment['HOME']), Path(work)
    for directory in (lookup_home, work):
        candidate = directory / '.iex.exs'
        assert not candidate.exists() and not candidate.is_symlink(), ('unrequested actual IEx initialization', str(candidate))
    return {'HOME': environment['HOME'], 'IEX_HOME': None, 'lookup_home': str(lookup_home),
            'work': str(work), 'absent': True}


def owned_cgroup(unit, group):
    assert unit in ('osbus-p08-plain.service', 'osbus-p08-console.service'), 'unowned private unit'
    assert group == '/system.slice/' + unit, 'unowned/substituted service cgroup'
    return group


def validate_completion(record):
    assert isinstance(record, dict), 'completion record'
    mode = record.get('mode')
    assert mode in ('soak', 'preflight'), 'explicit packaged run mode required'
    duration = 600 if mode == 'soak' else 10
    assert record.get('duration_seconds') == duration, 'frozen duration changed'
    operation_counts(record['warmup_counts'], WORKLOAD['warmup_operations'])
    batches = record['batches']
    assert len(batches) == WORKLOAD['batches'] == 3, 'three verified batches required'
    for index, batch in enumerate(batches, 1):
        assert batch['number'] == index and batch['status'] == 'passed', 'batch receipt'
        assert batch['operations'] == WORKLOAD['operations_per_batch'] == 1000, 'batch size'
        operation_counts(batch['counts'], 1000)
        finite(batch['verified_at'])
    sustained = record['sustained']
    started, finished = finite(sustained['started']), finite(sustained['finished'])
    assert started >= max(row['verified_at'] for row in batches), 'sustained clock before verified batches'
    assert finished - started >= duration, 'insufficient additional sustained duration'
    integer(sustained['operations'], 7)
    operation_counts(sustained['counts'], sustained['operations'])
    total = 100 + 3000 + sustained['operations']
    assert integer(record['operation_count']) == total, 'complete worker index sum'
    assert record['worker_barriers'] == [100, 1100, 2100, 3100, total], 'actual worker barrier index mismatch'
    samples = list(range(100, total + 1, 100))
    if total % 100:
        samples.append(total)
    assert record['sampled_operations'] == samples, 'every100 and partial-tail observation required'
    assert record['final_sample_operation'] == total, 'final observation missing'
    record['health_coverage'] = verify_health(record['healthy'], record['warmup_started'], sustained)
    record['sample_coverage'] = {'planned': len(samples), 'observed': len(record['sampled_operations']),
                                 'final_operation': total}
    return record


def qualifies_res06(record):
    validate_completion(record)
    return record['mode'] == 'soak' and record['duration_seconds'] == WORKLOAD['packaged_duration_seconds']


class ETF:
    """Bounded decoder for the independent Limits term, never executable terms."""
    def __init__(self, data):
        assert isinstance(data, bytes) and 1 <= len(data) <= 1_048_576 and data[0] == 131, 'ETF framing/size'
        self.data, self.position, self.items = data, 1, 0

    def take(self, length):
        assert 0 <= length <= len(self.data) - self.position, 'truncated ETF'
        value = self.data[self.position:self.position + length]
        self.position += length
        return value

    def number(self, size):
        return int.from_bytes(self.take(size), 'big')

    def term(self, depth=0):
        self.items += 1
        assert depth <= 64 and self.items <= 65_536, 'ETF depth/item budget'
        tag = self.number(1)
        if tag == 97:
            return self.number(1)
        if tag == 98:
            return int.from_bytes(self.take(4), 'big', signed=True)
        if tag in (110, 111):
            length = self.number(1 if tag == 110 else 4)
            assert length <= 16, 'ETF integer budget'
            sign = self.number(1)
            assert sign in (0, 1), 'ETF integer sign'
            return int.from_bytes(self.take(length), 'little') * (-1 if sign else 1)
        if tag in (100, 115, 118, 119):
            length = self.number(2 if tag in (100, 118) else 1)
            assert length <= 255, 'ETF atom budget'
            value = self.take(length).decode('utf8' if tag in (118, 119) else 'latin1')
            return {'true': True, 'false': False, 'nil': None}.get(value, value)
        if tag == 109:
            return self.take(self.number(4)).decode('utf8')
        if tag in (103, 88):
            node = self.term(depth + 1)
            identity, serial = self.number(4), self.number(4)
            creation = self.number(1 if tag == 103 else 4)
            assert node == 'nonode@nohost' and creation == 0, 'nonlocal ETF PID'
            assert identity <= 0x7FFFFFFF and serial <= 0x7FFFFFFF, 'ETF PID budget'
            return '#PID<0.%d.%d>' % (identity, serial)
        if tag == 116:
            length = self.number(4)
            assert length <= 16_384, 'ETF map budget'
            value = {}
            for _ in range(length):
                key = self.term(depth + 1)
                assert type(key) in (int, str), 'unsupported ETF map key'
                key = str(key)
                assert key not in value, 'colliding ETF display keys'
                value[key] = self.term(depth + 1)
            return value
        if tag in (104, 105, 108):
            length = self.number(1 if tag == 104 else 4)
            assert length <= 16_384, 'ETF collection budget'
            value = [self.term(depth + 1) for _ in range(length)]
            if tag == 108:
                assert self.term(depth + 1) == [], 'improper ETF list'
            return value
        if tag == 107:
            return list(self.take(self.number(2)))
        if tag == 106:
            return []
        raise AssertionError(('unsupported ETF tag', tag))

    def decode(self):
        value = self.term()
        assert self.position == len(self.data), 'trailing ETF bytes'
        return value


def verify_etf(envelope, usage):
    assert set(envelope) == {'encoding', 'base64', 'bytes', 'sha256'}, 'complete ETF envelope'
    assert envelope['encoding'] == 'erlang-external-term/base64', 'ETF encoding'
    try:
        assert isinstance(envelope['base64'], str) and len(envelope['base64']) <= 1_398_104, 'ETF encoded budget'
        data = base64.b64decode(envelope['base64'], validate=True)
        assert len(data) == integer(envelope['bytes'], 1), 'ETF byte length'
        assert hashlib.sha256(data).hexdigest() == envelope['sha256'], 'ETF digest'
        assert ETF(data).decode() == usage, 'authoritative ETF/JSON usage mismatch'
    except (ValueError, UnicodeError, struct.error) as error:
        raise AssertionError(('malformed ETF', str(error))) from error


def verify_sample(state, baseline=None):
    assert isinstance(state, dict), 'sample object'
    usage = state['usage']
    assert set(usage) == {'global', 'uids', 'peers', 'reservations', 'reload_reservations', 'limits', 'xml'}, 'full Limits snapshot'
    verify_etf(state['usage_etf'], usage)
    peers = state['peers']
    assert isinstance(peers, list), 'live Peer list'
    peer_ids = [row['peer'] for row in peers]
    names = [row['name'] for row in peers]
    assert len(set(peer_ids)) == len(peers) and len(set(names)) == len(peers), 'duplicate live Peer'
    for peer in peers:
        assert re.fullmatch(r'#PID<0\.\d+\.\d+>', peer['peer']), 'nonlocal Peer PID'
        assert re.fullmatch(r':\d+\.\d+', peer['name']), 'unregistered Peer name'
        integer(peer['uid'])
        integer(peer['gid'])
        assert peer['uid'] in (0, 1100, 1101), 'unexpected admitted UID'
        assert isinstance(peer['groups'], list) and peer['gid'] in peer['groups'], 'kernel groups'
    consumer = state['startup_plan']
    assert integer(consumer['listener'].get('pending_peer')) == 0, 'unfinished listener Peer handoff'
    assert integer(consumer['peer_supervisor'].get('active')) == len(peers), 'unregistered/untracked supervised Peer'
    expected_uids = dict(Counter(str(row['uid']) for row in peers))
    assert set(usage['uids']) == set(expected_uids), 'stale/missing UID accounting'
    assert set(usage['peers']) == set(peer_ids), 'stale/missing Peer accounting'
    assert len(peers) <= WORKLOAD['active_connection_ceiling'], 'connection observation ceiling'
    scopes = [('global', usage['global'], len(peers))]
    scopes += [('uid', counts, expected_uids[uid]) for uid, counts in usage['uids'].items()]
    scopes += [('peer', counts, 1) for counts in usage['peers'].values()]
    for scope, counts, connections in scopes:
        assert set(counts) == METRICS, ('complete thirteen metrics', scope)
        assert counts['connections'] == connections, ('connection accounting', scope)
        for metric, value in counts.items():
            integer(value)
            if metric != 'connections':
                suffix = metric.rsplit('_', 1)[-1]
                ceiling = WORKLOAD['queue'].get(('peer' if scope == 'peer' else 'global') + '_' + suffix)
                if ceiling is not None:
                    assert value <= ceiling, ('unchanged observation ceiling', scope, metric)
                assert value == 0, ('nonquiescent credit', scope, metric)
    assert integer(usage['reservations']) == integer(usage['reload_reservations']) == 0, 'reservation/reload leak'
    assert isinstance(usage['limits'], dict) and usage['limits'], 'safety map omitted'
    xml = usage['xml']
    assert set(xml) == {'limits', 'queues', 'global', 'uids'}, 'full XML accounting'
    assert isinstance(xml['limits'], dict) and xml['limits'] and isinstance(xml['queues'], dict) and xml['queues'], 'XML consumers omitted'
    assert xml['global'] == {'incomplete': 0, 'completed': len(peers)} and xml['uids'] == expected_uids, 'XML orphaned connection'
    assert all(type(value) is int for value in xml['global'].values()) and all(type(value) is int for value in xml['uids'].values()), 'XML integer counters'
    accounting = state['accounting']
    for key in ('usage', 'peers', 'peer_queues', 'authorities'):
        assert accounting[key] == state[key], ('inconsistent duplicate accounting', key)
    for key in ('pending', 'retired', 'bound_handles'):
        assert integer(state[key]) == integer(accounting[key]) == 0, ('unfinished cleanup', key)
    assert integer(accounting['reload']) == integer(accounting['activation']) == 0, 'reload/activation work'
    assert set(state['peer_queues']) == set(peer_ids), 'complete per-Peer queues'
    for queue in state['peer_queues'].values():
        assert set(queue) == QUEUE_KEYS and all(type(value) is int and value == 0 for value in queue.values()), 'Peer frame/FD/continuation/mailbox work'
    for key, per_peer_limit in [('names_by_peer', 'max_names_per_peer'), ('matches_by_peer', 'max_matches_per_peer')]:
        assert set(state[key]) <= set(peer_ids), ('stale peer index', key)
        assert all(integer(value) <= WORKLOAD[per_peer_limit] for value in state[key].values()), ('per-peer ceiling', key)
    assert len(state['names']) <= WORKLOAD['max_name_entries'] and len(state['names']) == len(set(state['names'])), 'name observation ceiling'
    assert integer(state['matches']) <= WORKLOAD['max_match_entries'], 'match observation ceiling'
    assert integer(state['capabilities']) == 0, 'stale fixture capability'
    assert integer(state['memory']) <= WORKLOAD['ceilings']['memory_bytes'], 'BEAM memory ceiling'
    assert integer(state['external']['rss_bytes']) <= WORKLOAD['ceilings']['rss_bytes'], 'RSS ceiling'
    assert set(state['queues']) == AUTHORITIES, 'complete authority mailbox observations'
    for value in state['queues'].values():
        assert integer(value) <= WORKLOAD['queue']['global_messages'], 'authority queue observation ceiling'
    for key in ('atoms', 'processes', 'ports'):
        integer(state[key])
    integer(state['external']['fds'])
    if baseline is not None:
        assert state['authorities'] == baseline['authorities'], 'authority replacement'
        assert state['external']['fds'] <= baseline['external']['fds'] + WORKLOAD['ceilings']['fd_above_baseline'], 'FD observation ceiling'
    return state


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory(root):
    root = Path(root)
    rows = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        assert not mode & 0o6000, 'privileged package mode'
        row = {'mode': mode}
        if path.is_symlink():
            assert path.resolve().is_relative_to(root.resolve()) or str(path.resolve()).startswith('/nix/store/'), 'escaping package symlink'
            row.update(type='symlink', target=os.readlink(path))
        elif path.is_file():
            row.update(type='file', sha256=digest(path), size=info.st_size)
        elif path.is_dir():
            row['type'] = 'directory'
        else:
            raise AssertionError(('special package file', str(path)))
        rows[str(path.relative_to(root))] = row
    return rows


def package_root(root, mode):
    info = Path(root).lstat()
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode, 'package root type/mode drift'
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid)


def verify_nix_inventory(root, expected):
    """Require exact builtins.path modes without relaxing bytes/links/paths."""
    identity = package_root(root, 0o555)
    normalized = {}
    for name, row in expected.items():
        path = Path(name)
        assert name and '\0' not in name and not path.is_absolute() and '..' not in path.parts and path.as_posix() == name and name != '.', 'unsafe package inventory path'
        mode = row['mode']
        assert type(mode) is int and 0 <= mode <= 0o777, 'privileged/invalid original package mode'
        assert row['type'] in ('file', 'directory', 'symlink'), 'invalid original package type'
        assert row['type'] == 'symlink' or not mode & 0o022, 'writable original package mode'
        imported = mode if row['type'] == 'symlink' else (0o555 if row['type'] == 'directory' or mode & 0o111 else 0o444)
        normalized[name] = dict(row, mode=imported)
    assert inventory(root) == normalized, 'complete imported package bytes/links/paths/modes drift'
    assert package_root(root, 0o555) == identity, 'imported package root replaced'
    return identity


def install_release(source, destination, expected):
    """Restore safe recorded modes only on the fresh private guest copy."""
    source, destination = Path(source), Path(destination)
    assert destination == BASE / 'package/release', 'unowned copied package destination'
    base_identity = package_root(BASE, 0o755)
    assert base_identity[2] == os.geteuid(), 'unowned private guest directory'
    source_identity = verify_nix_inventory(source, expected)
    assert not destination.parent.exists() and not destination.parent.is_symlink(), 'preserve preexisting package directory'
    destination.parent.mkdir(mode=0o755)
    parent_identity = package_root(destination.parent, 0o755)
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)
    copied_identity = verify_nix_inventory(destination, expected)
    assert verify_nix_inventory(source, expected) == source_identity, 'source package root replaced during copy'
    # Manifest inventories omit the root; its original guest contract is 0755.
    destination.chmod(0o755)
    for name, row in expected.items():
        if row['type'] != 'symlink':
            (destination / name).chmod(row['mode'])
    assert inventory(destination) == expected, 'copied package inventory/modes drift'
    assert package_root(destination, 0o755) == copied_identity, 'copied package root replaced'
    assert package_root(destination.parent, 0o755) == parent_identity, 'copied package parent replaced'
    assert package_root(BASE, 0o755) == base_identity, 'private guest root replaced'


def normalize_sources(sources):
    # Inodes/devices/syscall observations belong to the actual guest receipt;
    # the frozen preview explicitly does not promise inode equality.
    volatile = {'identity', 'read_identity', 'directory', 'syscall_attempts', 'read_attempts'}
    return [{key: value for key, value in row.items() if key not in volatile} for row in sources]


def verify_runtime(state, manifest):
    plan = manifest['runtime_plan']['semantic']
    consumer = state['startup_plan']
    assert consumer['profile'] == 'system' and consumer['lifecycle'] == 'release', 'normal system release lifecycle'
    native = consumer['native_identity']
    assert all(native[key] == 4 for key in ('uid', 'real_uid', 'gid', 'real_gid')), 'native daemon identity'
    assert state['usage']['limits'] == plan['safety_limits'] == consumer['safety_limits'], 'complete safety consumers'
    assert consumer['xml_limits'] == plan['xml_limits'], 'complete effective XML'
    for label, keys in [('limits', XML_CONNECTION_KEYS), ('queues', XML_QUEUE_KEYS)]:
        actual = state['usage']['xml'][label]
        assert actual == {key: plan['xml_limits'][key] for key in keys}, ('actual Limits XML consumer drift', label)
        for value in actual.values():
            integer(value)
    assert consumer['pending_limits'] == dict(plan['router_options'])['pending_limits'] == state['pending_limits'], 'actual pending consumer'
    assert consumer['max_output_bytes'] == dict(plan['router_options'])['max_output_bytes'], 'output consumer'
    assert consumer['peer_supervisor']['max_children'] == dict(plan['peer_supervisor_options'])['max_children'], 'Peer supervisor capacity'
    assert consumer['listener']['socket_path'] == manifest['startup']['socket'], 'actual private listener'
    assert consumer['listener']['peer_options'] == plan['peer_options'], 'actual frame/auth/queue consumer'
    assert consumer['listener']['inherited'] is False, 'unexpected inherited listener'
    limits = manifest['capacities']['packaged']
    for label, per_key, global_key in [('names', 'max_names_per_peer', 'max_name_entries'),
                                      ('matches', 'max_matches_per_peer', 'max_match_entries')]:
        expected = limits['name_limits' if label == 'names' else 'match_limits']
        assert consumer[label][per_key] == expected['per_peer'] and consumer[label][global_key] == expected['global'], 'name/match capacity'
        assert consumer[label]['xml_limits?'] is True, 'XML consumer binding'
    compiled = state['compiled_policy']
    expected = manifest['runtime_plan']['compiled_policy_semantic']
    for key in ('blocks', 'daemon_uid', 'needs_groups'):
        assert compiled[key] == expected[key], ('complete ordered compiled policy', key)
    configuration = state['configuration']
    assert compiled['configuration'] == configuration, 'same-generation published policy/configuration'
    for key in ('settings', 'limits', 'services', 'directives'):
        assert configuration[key] == expected['configuration'][key], ('published configuration', key)
    assert normalize_sources(configuration['sources']) == normalize_sources(expected['configuration']['sources']), 'complete source/path/hash semantics'
    assert len(configuration['sources']) == 1 and configuration['sources'][0]['sha256'] == manifest['xml']['sha256'], 'exact sole XML source'
    actual_accounts = configuration['accounts']
    for name, record in manifest['accounts']['user_records'].items():
        assert actual_accounts['users'][name] == record['uid'], ('named user binding', name)
        observed = actual_accounts['user_records'][name]
        for key in ('name', 'uid', 'gid', 'groups'):
            assert observed[key] == record[key], ('actual captured account record', name, key)
        uid = str(record['uid'])
        assert actual_accounts['memberships'][uid] == record['groups'] == compiled['memberships'][uid], ('exact frozen membership', uid)
    for name, gid in manifest['accounts']['groups'].items():
        assert actual_accounts['groups'][name] == gid, ('named group binding', name)
    assert configuration['captures']['files'][manifest['startup']['environment']['OS_BUS_CONFIG']][1]['sha256'] == manifest['xml']['sha256'], 'actual config capture hash'
    assert state['node'] == 'nonode@nohost', 'distributed node'
    assert set(state['authorities']) == AUTHORITIES and len(set(state['authorities'].values())) == len(AUTHORITIES), 'complete core authority identities'
    forbidden = {'gao_bus_web', 'gao_config', 'gao_bus_test', 'phoenix', 'bandit', 'dns_cluster'}
    apps = set(state['applications'])
    assert {'gao_bus', 'ex_d_bus'} <= apps and not forbidden.intersection(apps), 'headless application inventory'
    observed = state['code_identity']
    expected_code = manifest['runtime_code_expected']
    anchors = {'Elixir.GaoBus.Application', 'Elixir.GaoBus.Router', 'Elixir.GaoBus.Peer', 'Elixir.GaoBus.Limits'}
    assert anchors <= set(observed), 'loaded production code anchors'
    assert set(observed) <= set(expected_code), 'unexpected core module'
    for module, row in observed.items():
        assert row == expected_code[module], ('loaded code replacement/path drift', module)
    return state


PUBLIC_CODE = r'''
import json,os,sys,time,re
sys.path.insert(0,sys.argv[1])
from transport import Client,call,frame,string,u32,padding,read_string
from actor import request_name_body
path=sys.argv[2]; clients=[]; serial=100
def rpc(client,member,signature='',body=b'',interface='org.freedesktop.DBus'):
    global serial
    serial+=1
    fields=[(1,'o','/org/freedesktop/DBus'),(2,'s',interface),(3,'s',member),(6,'s','org.freedesktop.DBus'),(8,'g',signature)]
    client.sock.sendall(frame(1,serial,fields,body));return client.reply(serial)
try:
    source=Client(path);clients.append(source)
    owned={0:'org.foundation.Root.Boot',1100:'org.foundation.Observer',1101:'org.foundation.Service.Boot'}[os.getuid()]
    assert rpc(source,'RequestName','su',request_name_body(owned,0))['body']==u32(1)
    denied=rpc(source,'RequestName','su',request_name_body('org.foundation.Forbidden',0))
    assert denied['type']==3 and denied['fields'][4]=='org.freedesktop.DBus.Error.AccessDenied'
    for n in range(4): assert rpc(source,'AddMatch','s',string("type='signal',interface='org.foundation.Boot%d'"%n))['type']==2
    overflow=rpc(source,'AddMatch','s',string("type='signal',interface='org.foundation.BootOverflow'"))
    assert overflow['type']==3 and overflow['fields'][4]=='org.freedesktop.DBus.Error.LimitsExceeded'
    target=Client(path);clients.append(target)
    serial+=1;pending=serial
    fields=[(1,'o','/foundation'),(2,'s','org.foundation.Transport'),(3,'s','NeverReply'),(6,'s',target.name),(8,'g','')]
    source.sock.sendall(frame(1,pending,fields));assert target.receive()['fields'][7]==source.name
    expired=source.reply(pending)
    assert expired['type']==3 and expired['fields'][4]=='org.freedesktop.DBus.Error.NoReply'
    machine=rpc(source,'GetMachineId',interface='org.freedesktop.DBus.Peer')
    assert machine['type']==2;machine_id=read_string(machine['body']);assert re.fullmatch('[0-9a-f]{32}',machine_id)
    print(json.dumps(dict(uid=os.getuid(),gid=os.getgid(),groups=sorted(set(os.getgroups()+[os.getgid()])),
      admission=True,ownership=True,denied_ownership=True,matches=4,match_overflow=True,pending_timeout=True,machine_id=machine_id)))
finally:
    for client in clients:client.close()
'''


class Guest:
    def __init__(self, frozen, capture):
        assert __debug__ and os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n', 'disposable root guest required'
        assert EVIDENCE.is_symlink() and EVIDENCE.is_dir(), 'disk-backed evidence symlink required'
        assert str(EVIDENCE.resolve()).startswith('/var/lib/osbus-p08-evidence'), 'evidence must remain on guest disk'
        self.frozen, self.capture = Path(frozen), Path(capture)
        self.manifest = json.loads((self.capture / 'packaged.json').read_text())
        m = self.manifest
        assert m['schema'] == 2 and m['fixture'] == 'packaged-local-console-soak', 'explicit packaged capture'
        verify_policy_contract(m.get('policy_contract'))
        assert digest(self.capture / 'policy-design.md') == m['policy_contract']['design']['sha256'], 'captured adopted policy design bytes'
        assert m['mode'] in ('soak', 'preflight') and m['qualifying'] == (m['mode'] == 'soak'), 'run mode binding'
        assert m['duration_seconds'] == (600 if m['mode'] == 'soak' else 10), 'duration binding'
        assert m['warmup_operations'] == 100 and m['batches'] == 3 and m['operations_per_batch'] == 1000 and m['duration_starts_after_verified_batches'], 'frozen schedule'
        assert m['workload']['content'] == WORKLOAD and digest(FIXTURES / 'workload.json') == m['workload']['sha256'], 'unchanged workload'
        self.release = Path(m['package']['guest_release_path'])
        assert self.release == BASE / 'package/release' and m['startup']['socket'] == str(BASE / 'socket/bus'), 'private paths'
        self.report = {'result': 'running', 'mode': m['mode'], 'duration_seconds': m['duration_seconds'],
          'manifest_sha256': digest(self.capture / 'packaged.json'), 'manifest': m,
          'scope': 'unchanged packaged start and local-console start_iex, private disposable VM only',
          'commands': [], 'rows': {row: {'status': 'blocked', 'executed': False, 'reason': 'not reached'} for row in ROWS},
          'samples': [], 'sampled_operations': [], 'operation_count': 0, 'worker_barriers': [],
          'batches': [], 'actors': [], 'cleanup': [], 'modes': {}, 'unqualified': m['capacities']['unqualified_boundary_claims']}
        self.channels, self.units, self.identities = [], [], {}
        self.stop = threading.Event()
        self.health_lock = HealthGate()
        self.report['exclusions'] = self.health_lock.receipts
        self.health = {'count': 0, 'max_ms': 0, 'errors': [], 'observations': []}
        self.thread = None
        self.diagnostics = Diagnostics(secrets.token_hex(16))
        self.report['diagnostics'] = dict(schema=1, nonce=self.diagnostics.nonce, sidecar='diagnostics.jsonl',
          clock='Linux monotonic_ns shared by controller and healthy actor')
        self.started = time.monotonic()

    def save(self):
        self.report['elapsed_seconds'] = time.monotonic() - self.started
        self.report['healthy'] = self.health
        statuses = [row['status'] for row in self.report['rows'].values()]
        self.report['counts'] = {'selected': len(ROWS), 'executed': sum(row['executed'] for row in self.report['rows'].values()),
          **{key: statuses.count(value) for key, value in [('passed', 'passed'), ('failed', 'failed'), ('blocked', 'blocked'), ('skipped', 'skipped')]}}
        if hasattr(self, 'diagnostics'):
            self.diagnostics.save_report(self.report, EVIDENCE / 'qualification.json', self.report['operation_count'])
            self.diagnostics.persist(EVIDENCE / 'diagnostics.jsonl')
        else:
            (EVIDENCE / 'qualification.json').write_text(json.dumps(self.report, indent=2, sort_keys=True) + '\n')

    def command(self, argv, timeout=15, check=True):
        started = time.monotonic()
        result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
        self.report['commands'].append({'argv': argv, 'exit_code': result.returncode, 'stdout': result.stdout,
                                       'stderr': result.stderr, 'started': started, 'elapsed': time.monotonic() - started})
        if check:
            assert result.returncode == 0, (argv, result.returncode, result.stderr)
        return result

    def properties(self, unit):
        keys = ['Type', 'NotifyAccess', 'MainPID', 'ControlGroup', 'ActiveState', 'SubState', 'Result',
          'KillMode', 'NRestarts', 'TimeoutStartUSec', 'TimeoutStopUSec', 'TasksMax', 'MemoryMax',
          'Restart', 'User', 'Group', 'WorkingDirectory', 'ActiveEnterTimestampMonotonic', 'ExecMainStatus']
        result = self.command(['systemctl', 'show', unit, '--property=' + ','.join(keys)], timeout=3, check=False)
        return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)

    def poll(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while True:
            result = predicate()
            if result:
                return result
            assert time.monotonic() < deadline, 'manager/process observation deadline'
            self.stop.wait(min(.05, max(0, deadline - time.monotonic())))

    def normal_bus(self):
        props = self.properties('dbus.service')
        assert props['ActiveState'] == 'active' and int(props['MainPID']) > 0, 'guest normal bus must remain active'
        pid = int(props['MainPID'])
        socket = Path('/run/dbus/system_bus_socket').stat()
        return {'pid': pid, 'starttime': Path('/proc/%d/stat' % pid).read_text().split(') ', 1)[1].split()[19],
                'socket': {'device': socket.st_dev, 'inode': socket.st_ino, 'mode': stat.S_IMODE(socket.st_mode)},
                'configuration_sha256': digest('/etc/dbus-1/system.conf')}

    def install(self):
        m = self.manifest
        expected = m['package']['manifest']['inventory']
        for directory in [self.frozen, self.capture]:
            assert digest(directory / 'release.json') == m['package']['manifest_sha256'], 'package manifest drift'
            verify_nix_inventory(directory / 'release', expected)
        for name, row in m['fixtures'].items():
            assert digest(FIXTURES / name) == row['sha256'] and (FIXTURES / name).stat().st_size == row['bytes'], ('fixture drift', name)
        assert digest(self.capture / 'plan.json') == m['plan_json_sha256'], 'preview display binding'
        assert digest(self.capture / 'plan.etf') == m['runtime_plan']['etf_sha256'], 'preview term binding'
        assert (self.capture / 'plan.etf').stat().st_size == m['runtime_plan']['bytes'], 'preview term size'
        install_release(self.capture / 'release', self.release, expected)
        for name, record in m['accounts']['user_records'].items():
            account = pwd.getpwnam(name)
            assert account.pw_uid == record['uid'] and account.pw_gid == record['gid'], ('guest account drift', name)
            assert sorted(set(os.getgrouplist(name, account.pw_gid))) == record['groups'], ('guest group drift', name)
        for name, mode, uid, gid in [('config', 0o755, 0, 0), ('socket', 0o755, 4, 4), ('work', 0o700, 4, 4)]:
            path = BASE / name
            assert not path.exists(), ('preserve preexisting private directory', str(path))
            path.mkdir(mode=mode)
            os.chown(path, uid, gid)
        target = BASE / 'config/bus.conf'
        target.write_bytes((self.capture / 'config/bus.conf').read_bytes())
        target.chmod(0o644)
        assert digest(target) == m['xml']['sha256'], 'frozen XML drift'
        home = Path(pwd.getpwnam('messagebus').pw_dir)
        assert not (home / '.iex.exs').exists() and not (BASE / 'work/.iex.exs').exists(), 'unrequested IEx initialization'
        self.report['iex_initialization'] = {'home': str(home), 'work': str(BASE / 'work'), 'absent': True,
                                           'controller_HOME': os.environ.get('HOME')}
        self.report['inventory_before'] = inventory(self.release)

    def launch(self, mode):
        unit = 'osbus-p08-' + ('plain' if mode == 'start' else 'console') + '.service'
        prior = self.properties(unit)
        assert prior.get('MainPID', '0') == '0' and prior.get('ActiveState', 'inactive') not in ('active', 'activating'), 'preexisting private unit'
        command = ['env']
        for key in self.manifest['startup']['unset_environment']:
            command += ['-u', key]
        command += ['systemd-run', '--pipe', '--wait', '--service-type=notify', '--unit=' + unit,
          '--property=NotifyAccess=main', '--uid=messagebus', '--gid=messagebus',
          '--property=WorkingDirectory=/run/osbus-p08/work', '--property=KillMode=control-group',
          '--property=TimeoutStartSec=15', '--property=TimeoutStopSec=3', '--property=TasksMax=128',
          '--property=MemoryMax=256M', '--property=Restart=no']
        for key, value in self.manifest['startup']['environment'].items():
            command += ['--setenv=' + key + '=' + value]
        command += [str(self.release / 'bin/os_bus'), mode]
        self.report['commands'].append({'argv': command, 'spawn': True})
        channel = Console(command, EVIDENCE / (mode + '.log'), os.urandom(16).hex()) if mode == 'start_iex' else Channel(command, EVIDENCE / (mode + '.log'))
        self.channels.append(channel)
        self.units.append(unit)
        props = self.poll(lambda: (p if (p := self.properties(unit)).get('ActiveState') == 'active' else None), 15)
        assert props['Type'] == 'notify' and props['NotifyAccess'] == 'main' and int(props['ActiveEnterTimestampMonotonic']) > 0, 'genuine notify readiness'
        expected = {'User': 'messagebus', 'Group': 'messagebus', 'KillMode': 'control-group', 'Restart': 'no',
                    'NRestarts': '0', 'TasksMax': '128', 'MemoryMax': '268435456', 'WorkingDirectory': str(BASE / 'work')}
        for key, value in expected.items():
            assert props[key] == value, ('manager property drift', key, props)
        assert props['TimeoutStartUSec'] == '15s' and props['TimeoutStopUSec'] == '3s', 'manager timeout drift'
        pid = int(props['MainPID'])
        root = Path('/proc') / str(pid)
        status = root.joinpath('status').read_text()
        identities = {key: [int(x) for x in re.search('^' + key + r':([^\n]+)', status, re.M)[1].split()] for key in ['Uid', 'Gid']}
        assert identities == {'Uid': [4] * 4, 'Gid': [4] * 4}, 'actual BEAM UID/GID'
        groups = [int(x) for x in re.search(r'^Groups:([^\n]+)', status, re.M)[1].split()]
        assert sorted(set(groups + [4])) == [4], 'actual daemon supplementary groups'
        argv = root.joinpath('cmdline').read_bytes().split(b'\0')[:-1]
        argv = [value.decode() for value in argv]
        assert str(self.release / 'releases') in ' '.join(argv) and not set(['-name', '-sname']).intersection(argv), 'packaged nondistributed argv'
        assert root.joinpath('exe').resolve() == (self.release / ('erts-' + self.manifest['package']['manifest']['metadata']['erts']) / 'bin/beam.smp').resolve(), 'actual packaged BEAM executable'
        group = root.joinpath('cgroup').read_text().strip().split('::', 1)[1]
        assert group == props['ControlGroup'], 'manager/kernel cgroup mismatch'
        owned_cgroup(unit, group)
        environment = dict(item.split('=', 1) for item in root.joinpath('environ').read_bytes().decode().split('\0') if '=' in item)
        for key, value in self.manifest['startup']['environment'].items():
            if key != 'PATH':
                assert environment.get(key) == value, ('actual captured startup environment', key)
        iex_initialization = verify_iex_initialization(environment, pwd.getpwnam('messagebus').pw_dir, BASE / 'work')
        unset = set(self.manifest['startup']['unset_environment']) - {'RELEASE_COOKIE', 'RELEASE_NODE'}
        assert not unset.intersection(environment), 'unexpected startup override'
        assert environment.get('RELEASE_NODE') == 'os_bus', 'unchanged launcher node variable'
        assert environment.get('RELEASE_COOKIE') == (self.release / 'releases/COOKIE').read_text().strip(), 'unchanged launcher cookie binding'
        expected_path = ':'.join([str(self.release / ('erts-' + self.manifest['package']['manifest']['metadata']['erts']) / 'bin'),
                                  str(self.release / 'bin'), self.manifest['startup']['environment']['PATH']])
        assert environment.get('PATH') == expected_path, 'unchanged launcher utility PATH'
        sockets = set(external(pid)['fd_targets'])
        for protocol in ('tcp', 'tcp6'):
            for line in Path('/proc/net/' + protocol).read_text().splitlines()[1:]:
                fields = line.split()
                assert not (fields[3] == '0A' and 'socket:[' + fields[9] + ']' in sockets), 'unexpected BEAM TCP/epmd listener'
        receipt = {'pid': pid, 'properties': props, 'uid_gid': identities, 'groups': groups, 'argv': argv,
                   'exe': str(root.joinpath('exe').resolve()), 'cgroup': group,
                   'environment': {key: environment.get(key) for key in self.manifest['startup']['environment']},
                   'starttime': root.joinpath('stat').read_text().split(') ', 1)[1].split()[19],
                   'wrapper_pid': channel.process.pid, 'iex_initialization': iex_initialization}
        receipt['environment'].update({key: environment[key] for key in ('HOME', 'IEX_HOME') if key in environment})
        self.identities[unit] = receipt
        if isinstance(channel, Console):
            channel.bind_pid(pid)
        self.report['modes'][mode] = receipt
        return unit, channel, receipt

    def public(self, mode):
        rows = []
        for user in ['root', 'foundationA', 'foundationB']:
            result = self.command(['runuser', '-u', user, '--', 'python3', '-c', PUBLIC_CODE, str(FIXTURES), str(BASE / 'socket/bus')], timeout=10)
            observed = json.loads(result.stdout)
            record = self.manifest['accounts']['user_records'][user]
            assert all(observed[key] == record[key] for key in ('uid', 'gid', 'groups')), 'public actor actual kernel identity'
            rows.append(observed)
        properties = {}
        for name in ['Interfaces', 'Features']:
            result = self.command(['busctl', '--address=unix:path=' + str(BASE / 'socket/bus'), 'get-property',
              'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus', name], timeout=3)
            properties[name] = result.stdout.strip()
        result = {'caller_checks': rows, 'properties': properties}
        self.report['modes'][mode]['public'] = result
        return result

    def policy_probe(self, backend, socket_path):
        row = self.report['rows']['policy-' + backend]
        row['executed'] = True
        evidence = EVIDENCE / ('policy-' + backend)
        try:
            result = packaged_policy_probe.run_probe(socket_path, evidence, FIXTURES, backend)
            self.report.setdefault('policy_probes', {})[backend] = result
            packaged_policy_probe.validate_complete(result['rows'], result['counts'])
            assert result['backend'] == backend and result['status'] == 'passed', 'policy probe incomplete'
            row.update(status='passed', reason='all14 independent policy rows passed')
            return result
        except BaseException as failure:
            row.update(status='failed', reason=repr(failure))
            if (evidence / 'policy-probe.json').is_file():
                self.report.setdefault('policy_probes', {})[backend] = json.loads((evidence / 'policy-probe.json').read_text())
            raise

    def reference_probe(self):
        row = self.report['rows']['policy-reference']
        row['executed'] = True
        prior = self.properties(REFERENCE_UNIT)
        assert prior.get('MainPID', '0') == '0' and prior.get('ActiveState', 'inactive') not in ('active', 'activating'), 'preexisting private reference unit'
        directory = BASE / 'reference'
        assert not directory.exists(), 'preserve preexisting private reference directory'
        directory.mkdir(mode=0o755)
        os.chown(directory, 4, 4)
        socket_path = directory / 'bus'
        xml = reference_policy_xml((BASE / 'config/bus.conf').read_bytes())
        config = BASE / 'config/reference.conf'
        assert not config.exists(), 'preserve preexisting reference configuration'
        config.write_bytes(xml)
        config.chmod(0o644)
        binary = Path(shutil.which('dbus-daemon')).resolve()
        reference = self.report['reference'] = {'config_sha256': digest(config),
          'candidate_config_sha256': digest(BASE / 'config/bus.conf'),
          'only_configuration_delta': 'sole listen path', 'socket': str(socket_path),
          'unit': REFERENCE_UNIT, 'version': self.command([str(binary), '--version'], timeout=3).stdout,
          'cleanup': {'status': 'blocked', 'reason': 'not reached'}}
        identity = None
        try:
            self.command(['systemd-run', '--service-type=exec', '--unit=' + REFERENCE_UNIT,
              '--uid=messagebus', '--gid=messagebus', '--property=KillMode=control-group',
              '--property=TimeoutStopSec=3', '--property=Restart=no',
              str(binary), '--config-file=' + str(config), '--nofork', '--nopidfile', '--nosyslog'], timeout=8)
            props = self.poll(lambda: (p if (p := self.properties(REFERENCE_UNIT)).get('ActiveState') == 'active' and socket_path.exists() else None), 8)
            pid = int(props['MainPID'])
            proc = Path('/proc') / str(pid)
            assert pid > 0 and proc.joinpath('exe').resolve() == binary, 'actual private reference executable'
            assert props['ControlGroup'] == REFERENCE_GROUP, 'actual private reference cgroup'
            assert proc.joinpath('cgroup').read_text().strip().split('::', 1)[1] == REFERENCE_GROUP, 'reference manager/kernel cgroup mismatch'
            assert props['User'] == props['Group'] == 'messagebus' and props['KillMode'] == 'control-group' and props['NRestarts'] == '0', 'reference manager identity/lifecycle'
            status = proc.joinpath('status').read_text()
            for key in ('Uid', 'Gid'):
                assert [int(x) for x in re.search('^' + key + r':([^\n]+)', status, re.M)[1].split()] == [4] * 4, 'actual reference UID/GID'
            assert stat.S_ISSOCK(socket_path.stat().st_mode), 'reference endpoint must be a socket'
            identity = {'pid': pid, 'starttime': proc.joinpath('stat').read_text().split(') ', 1)[1].split()[19],
                        'exe': str(binary), 'properties': props, 'argv': proc.joinpath('cmdline').read_bytes().decode().split('\0')[:-1]}
            assert '--config-file=' + str(config) in identity['argv'], 'explicit private reference config'
            reference['identity'] = identity
            self.policy_probe('reference', socket_path)
            assert config.read_bytes() == xml, 'reference policy changed during probe'
        except BaseException as failure:
            row.update(status='failed', reason=repr(failure))
            raise
        finally:
            try:
                self.command(['systemctl', 'stop', REFERENCE_UNIT], timeout=8)
                def clean():
                    props = self.properties(REFERENCE_UNIT)
                    assert props.get('ControlGroup', '') in ('', REFERENCE_GROUP), 'reference cleanup group replaced'
                    group = Path('/sys/fs/cgroup') / REFERENCE_GROUP.lstrip('/')
                    members = group.joinpath('cgroup.procs').read_text().split() if group.exists() else []
                    gone = None
                    if identity is not None:
                        try:
                            birth = Path('/proc', str(identity['pid']), 'stat').read_text().split(') ', 1)[1].split()[19]
                            gone = birth != identity['starttime']
                        except FileNotFoundError:
                            gone = True
                    result = {'properties': props, 'main_gone': gone, 'cgroup_pids': members,
                              'socket_removed': not socket_path.exists()}
                    return result if not members and props.get('MainPID', '0') == '0' and not socket_path.exists() else None
                reference['cleanup'] = self.poll(clean, 5)
                if identity is not None:
                    verify_reference_cleanup(reference['cleanup'])
                journal = self.command(['journalctl', '-u', REFERENCE_UNIT, '--no-pager', '-o', 'short-monotonic'], timeout=3, check=False)
                (EVIDENCE / 'policy-reference-journal.log').write_text(journal.stdout + journal.stderr)
            except BaseException as failure:
                reference['cleanup_error'] = repr(failure)
                row.update(status='failed', reason=repr(failure))
                raise

    def stopped(self, unit):
        receipt = self.identities[unit]
        captured_group = owned_cgroup(unit, receipt['cgroup'])
        group = Path('/sys/fs/cgroup') / captured_group.lstrip('/')
        def clean():
            pid_path = Path('/proc') / str(receipt['pid'])
            gone = not pid_path.exists() or pid_path.joinpath('stat').read_text().split(') ', 1)[1].split()[19] != receipt['starttime']
            members = group.joinpath('cgroup.procs').read_text().split() if group.exists() else []
            props = self.properties(unit)
            assert props.get('ControlGroup', '') in ('', captured_group), 'manager cgroup replaced during stop'
            return {'main_gone': gone, 'cgroup': captured_group, 'cgroup_pids': members, 'properties': props,
                    'socket_removed': not (BASE / 'socket/bus').exists()} if gone and not members and not (BASE / 'socket/bus').exists() and props.get('MainPID', '0') == '0' else None
        return self.poll(clean, 5)

    def shutdown(self, unit, channel, console=False):
        if not console:
            self.command(['systemctl', 'stop', unit], timeout=8)
        result = channel.stop(grace=5)
        result['unit'] = unit
        self.report['cleanup'].append(result)
        # The systemd service outlives its wrapper if stdout remains inherited.
        # Always inspect our exact owned cgroup, independently of wrapper status.
        result['manager_cleanup'] = self.stopped(unit)
        manager = result['manager_cleanup']
        assert manager['cgroup'] == owned_cgroup(unit, self.identities[unit]['cgroup']), 'wrong cleanup cgroup'
        assert manager['main_gone'] is True and manager['socket_removed'] is True and manager['cgroup_pids'] == [], 'service cleanup incomplete'
        assert manager['properties'].get('MainPID') == '0', 'manager retains main PID'
        assert result['returncode'] == 0 and result['method'] == ('console-System.stop' if console else 'eof'), ('not graceful shutdown', result)
        assert not {'protocol_error', 'shutdown_error', 'tail_error'}.intersection(result), 'console shutdown/protocol/tail failure'
        if console:
            assert result.get('tail_eof') is True and result.get('service_cgroup_cleanup_required') is True, 'incomplete console/service cleanup receipt'
        return result

    def actor(self, user, mode):
        command = ['runuser', '-u', user, '--', 'python3', str(FIXTURES / 'actor.py'), str(BASE / 'socket/bus'), mode]
        if mode == 'healthy':
            command = ['runuser', '-u', user, '--', 'python3', str(FIXTURES / 'packaged_diagnostic_actor.py'),
                       str(BASE / 'socket/bus'), self.diagnostics.nonce]
        self.report['commands'].append({'argv': command, 'spawn': True})
        actor = (DiagnosticActor(command, EVIDENCE / (mode + '.log'), self.diagnostics)
                 if mode == 'healthy' else Actor(command, EVIDENCE / (mode + '.log')))
        self.channels.append(actor)
        response = actor.read()
        assert response['ok'], 'actor startup failed'
        ready = response['result']
        assert ready['uid'] == (1101 if mode == 'worker' else 1100), 'actual actor UID'
        self.report['actors'].append(ready)
        return actor

    def exclusion(self, kind):
        if isinstance(self.health_lock, HealthGate):
            return self.health_lock.section(kind, self.report['operation_count'])
        # Existing pure receipt tests supply their own clock-controlled lock.
        return self.health_lock

    def health_probe(self, observer, regular=True):
        index = self.health['count'] if regular else None
        due = (self.health['started'] + index * WORKLOAD['health_interval_ms'] / 1000
               if regular else time.monotonic())
        requested = time.monotonic()
        with self.exclusion('health-regular' if regular else 'health-post-kill'):
            started = time.monotonic()
            sample = observer.request(op='health')
            finished = time.monotonic()
            diagnostic_request_id = (observer.request_id
                if hasattr(self, 'diagnostics') and hasattr(observer, 'request_id') else None)
        latency = max((finished - due) * 1000, finite(sample['latency_ms']))
        receipt = {'index': index, 'due': due, 'requested': requested,
          'started': started, 'finished': finished, 'dispatch_lag_ms': (started - due) * 1000,
          'actual_ms': (finished - started) * 1000, 'latency_ms': latency, 'actor': sample}
        if diagnostic_request_id is not None:
            receipt.update(diagnostic_nonce=self.diagnostics.nonce, diagnostic_request_id=diagnostic_request_id)
        if regular:
            self.health['observations'].append(receipt)
            self.health['count'] += 1
            self.health['max_ms'] = max(self.health['max_ms'], latency)
        assert latency <= WORKLOAD['healthy_probe_ms'], 'independent end-to-end health deadline'
        return receipt

    def start_health(self, observer):
        self.health['started'] = time.monotonic()
        self.health_probe(observer)
        def probe():
            while True:
                due = self.health['started'] + self.health['count'] * WORKLOAD['health_interval_ms'] / 1000
                if self.stop.is_set():
                    if 'finished' not in self.health or due > self.health['finished'] + 1e-9:
                        return
                elif self.stop.wait(max(0, due - time.monotonic())):
                    continue
                try:
                    self.health_probe(observer)
                except BaseException as error:
                    self.health['errors'].append(repr(error))
                    return
        self.thread = threading.Thread(target=probe, name='packaged-healthy-peer')
        self.thread.start()

    def snapshot(self, console, pid, operation='snapshot', record=True):
        with self.exclusion('snapshot:' + operation):
            state = console.request(operation)
            state['external'] = external(pid)
            state['elapsed_seconds'] = time.monotonic() - self.started
            state['operation_count'] = self.report['operation_count']
        try:
            verify_sample(state, self.report.get('baseline'))
            verify_runtime(state, self.manifest)
        except BaseException as error:
            self.report['rows']['whole-accounting'] = {'status': 'failed', 'executed': True, 'reason': repr(error)}
            raise
        assert not self.health['errors'], ('health errors', self.health['errors'])
        if record:
            index = self.report['operation_count']
            if index and (not self.report['sampled_operations'] or self.report['sampled_operations'][-1] != index):
                self.report['sampled_operations'].append(index)
            self.report['samples'].append(state)
            self.save()
        return state

    def barrier(self, worker):
        completed = worker.request(op='barrier')
        assert completed == {'completed': self.report['operation_count']}, 'exact actual worker operation index'
        self.report['worker_barriers'].append(completed['completed'])

    def operations(self, worker, observer, console, pid, count=None, deadline=None):
        assert (count is None) != (deadline is None), 'one operation stopping condition'
        counts = {kind: 0 for kind in WORKLOAD['operations']}
        order = list(WORKLOAD['operations'])
        random.Random(WORKLOAD['seed']).shuffle(order)
        while (sum(counts.values()) < count if count is not None else time.monotonic() < deadline):
            result = worker.request(op='operation')
            expected = order[self.report['operation_count'] % len(order)]
            assert result['kind'] == expected, ('unchanged seeded operation order', expected, result)
            if result['kind'] == 'abrupt_kill':
                self.report['rows']['peer-kill'] = {'status': 'blocked', 'executed': True, 'reason': 'not reached'}
                with self.exclusion('kill'):
                    killed = console.request('kill', name=result['victim'])
                    assert killed['monitor'] == 'DOWN:killed', 'real Peer monitored kill'
                    after = killed['snapshot']
                    after['external'] = external(pid)
                    assert worker.request(op='killed') == {'closed': True}, 'worker failed to observe native EOF'
                verify_sample(after, self.report.get('baseline'))
                verify_runtime(after, self.manifest)
                assert killed['before']['authorities'] == after['authorities'], 'kill replaced authority'
                assert all(peer['name'] != result['victim'] for peer in after['peers']), 'victim retained'
                self.report.setdefault('kills', []).append({'operation_index': self.report['operation_count'] + 1,
                  'victim': result['victim'], 'peer': killed['peer'], 'monitor': killed['monitor'],
                  'before': killed['before'], 'after': after})
                self.report['kills'][-1]['healthy_after'] = self.health_probe(observer, regular=False)
                self.report['rows']['peer-kill'] = {'status': 'passed', 'executed': True}
            counts[result['kind']] += 1
            self.report['operation_count'] += 1
            # The inspector contains its one absolute3000ms quiescence deadline.
            self.snapshot(console, pid, 'quiescent', record=False)
            if self.report['operation_count'] % 100 == 0:
                self.snapshot(console, pid)
            assert not self.health['errors'], 'health worker failed'
        self.barrier(worker)
        return counts

    def workload(self, console, pid):
        worker = self.actor('foundationB', 'worker')
        observer = self.actor('foundationA', 'healthy')
        self.start_health(observer)
        self.report['rows']['whole-accounting']['executed'] = True
        # Initialize inspector/IEx helper costs before immutable warmup/baseline.
        self.snapshot(console, pid, 'metrics', record=False)
        self.report['warmup_started'] = time.monotonic()
        self.report['warmup_counts'] = self.operations(worker, observer, console, pid, count=100)
        baseline = self.snapshot(console, pid, 'metrics')
        self.report['baseline'] = baseline
        self.report['rows']['whole-accounting'] = {'status': 'passed', 'executed': True}
        self.report['rows']['three-batches']['executed'] = True
        for index in range(1, 4):
            started = time.monotonic()
            counts = self.operations(worker, observer, console, pid, count=1000)
            state = self.snapshot(console, pid, 'metrics')
            verify_settled(state, baseline)
            operation_counts(counts, 1000)
            self.report['batches'].append({'number': index, 'operations': sum(counts.values()), 'counts': counts,
              'status': 'passed', 'started': started, 'verified_at': time.monotonic(), 'final': state})
            self.save()
        self.report['rows']['three-batches'] = {'status': 'passed', 'executed': True}
        # Only this clock qualifies the additional sustained phase.
        started = time.monotonic()
        self.report['rows']['sustained']['executed'] = True
        counts = self.operations(worker, observer, console, pid, deadline=started + self.manifest['duration_seconds'])
        self.report['sustained'] = {'started': started, 'finished': time.monotonic(), 'counts': counts, 'operations': sum(counts.values())}
        final = self.snapshot(console, pid, 'metrics')
        verify_settled(final, baseline)
        self.report['final_sample_operation'] = self.report['operation_count']
        self.report['rows']['sustained'] = {'status': 'passed' if self.manifest['mode'] == 'soak' else 'blocked',
          'executed': True, 'reason': 'verified600s continuation' if self.manifest['mode'] == 'soak' else '10s preflight is nonqualifying for600s RES-06'}
        self.health['finished'] = time.monotonic()
        self.stop.set()
        self.thread.join(timeout=15)
        assert not self.thread.is_alive(), 'health thread did not stop'
        for actor in [worker, observer]:
            result = actor.stop()
            self.report['cleanup'].append(result)
            assert result['method'] == 'eof' and result['returncode'] == 0, 'actor emergency cleanup'
        zero = self.snapshot(console, pid, 'metrics', record=False)
        assert zero['peers'] == [] and zero['names'] == ['org.freedesktop.DBus'] and not zero['names_by_peer'] and not zero['matches_by_peer'], 'final zero-Peer ownership cleanup'
        assert zero['usage']['global']['connections'] == zero['matches'] == zero['pending'] == zero['capabilities'] == 0, 'final zero resource credits'
        assert zero['external']['fds'] <= self.report['empty_baseline']['external']['fds'], 'final zero-Peer native FD growth'
        assert zero['atoms'] <= baseline['atoms'] + WORKLOAD['ceilings']['atom_post_quiescence_growth'], 'final atom ceiling'
        self.report['final_zero'] = zero
        validate_completion(self.report)
        self.report['RES-06'] = {'status': 'passed' if qualifies_res06(self.report) else 'blocked',
          'mode': 'packaged-local-console-soak', 'uninstrumented_start600s': 'unqualified'}

    def run(self):
        error = None
        normal = None
        try:
            normal = self.normal_bus()
            self.report['normal_bus_before'] = normal
            self.install()
            self.reference_probe()
            self.report['rows']['startup-equivalence']['executed'] = True
            unit, plain, receipt = self.launch('start')
            public = self.public('start')
            self.policy_probe('start', BASE / 'socket/bus')
            self.shutdown(unit, plain)
            unit, console, receipt = self.launch('start_iex')
            assert self.public('start_iex') == public, 'same-config startup public behavior differs'
            self.policy_probe('start_iex', BASE / 'socket/bus')
            verify_policy_probes(self.report['policy_probes'])
            with self.exclusion('initialize'):
                verify_iex_initialization(receipt['environment'], pwd.getpwnam('messagebus').pw_dir, BASE / 'work')
                ready = console.request('snapshot', bootstrap=(str(FIXTURES / 'packaged_inspection.exs'), self.manifest['fixtures']['packaged_inspection.exs']['sha256']))
                ready['external'] = external(receipt['pid'])
                verify_runtime(ready, self.manifest)
            self.report['instrumented_after_normal_boot'] = ready
            self.report['empty_baseline'] = self.snapshot(console, receipt['pid'], 'metrics', record=False)
            self.report['rows']['startup-equivalence'] = {'status': 'passed', 'executed': True,
              'equivalent': ['config/XML', 'managerpolicy', 'kernelUID/GID', 'publicAPI/ownership/match/pending', 'Interfaces', 'Features', 'machine-id'],
              'volatile': ['PID', 'starttime', 'GUID', 'bus-ID', 'unique names'],
              'plain_authority_internals': 'unobserved; not claimed by console equivalence'}
            self.workload(console, receipt['pid'])
            self.report['rows']['cleanup']['executed'] = True
            self.shutdown(unit, console, console=True)
            assert inventory(self.release) == self.report['inventory_before'], 'package mutated after run'
            assert self.normal_bus() == normal, 'guest normal bus changed'
            self.report['normal_bus_after'] = normal
            self.report['inventory_after'] = inventory(self.release)
            self.report['fixture_hashes_after'] = {name: digest(FIXTURES / name) for name in self.manifest['fixtures']}
            assert all(value == self.manifest['fixtures'][name]['sha256'] for name, value in self.report['fixture_hashes_after'].items()), 'fixture mutated after run'
            self.report['rows']['cleanup'] = {'status': 'passed', 'executed': True}
            required = [row for name, row in self.report['rows'].items() if name != 'sustained' or self.manifest['mode'] == 'soak']
            assert all(row['executed'] and row['status'] == 'passed' for row in required), 'required rows not passed'
            self.report['result'] = 'passed_packaged_soak' if self.manifest['mode'] == 'soak' else 'passed_packaged_preflight'
        except BaseException as failure:
            error = failure
            self.report.update(result='failed', error=repr(failure))
            current = next((row for row in self.report['rows'].values() if row['executed'] and row['status'] == 'blocked' and row.get('reason') == 'not reached'), None)
            if current is not None:
                current.update(status='failed', reason=repr(failure))
        finally:
            self.stop.set()
            if self.thread is not None:
                self.thread.join(timeout=15)
                if self.thread.is_alive():
                    self.report.update(result='failed', cleanup_error='health thread remains alive')
            # Contain only our actors/wrappers and private units; preserve exact
            # emergency outcomes instead of treating termination as graceful EOF.
            for channel in reversed(self.channels):
                if channel.process.poll() is None:
                    try:
                        if isinstance(channel, Console):
                            result = channel.stop(grace=3)
                        elif isinstance(channel, Actor):
                            result = channel.stop(grace=3)
                        else:
                            for unit in self.units:
                                self.command(['systemctl', 'stop', unit], timeout=6, check=False)
                            result = channel.stop(grace=3)
                        result['exception_cleanup'] = True
                        self.report['cleanup'].append(result)
                    except BaseException as failure:
                        self.report.setdefault('cleanup_errors', []).append(repr(failure))
            for unit in self.units:
                try:
                    if self.properties(unit).get('MainPID', '0') != '0':
                        self.command(['systemctl', 'stop', unit], timeout=6, check=False)
                    if unit in self.identities:
                        self.report.setdefault('final_manager_cleanup', {})[unit] = self.stopped(unit)
                except BaseException as failure:
                    self.report.setdefault('cleanup_errors', []).append(repr(failure))
            if normal is not None:
                try:
                    assert self.normal_bus() == normal, 'guest normal bus changed during cleanup'
                except BaseException as failure:
                    self.report.setdefault('cleanup_errors', []).append(repr(failure))
            if self.report.get('cleanup_errors'):
                self.report['result'] = 'failed'
            self.save()
        if error is not None:
            raise error
        assert self.report['result'].startswith('passed_packaged_'), self.report.get('cleanup_errors')
        print(json.dumps({'result': self.report['result'], 'counts': self.report['counts'],
                          'RES-06': self.report['RES-06'], 'manifest_sha256': self.report['manifest_sha256']}))


def main(frozen_package, packaged_capture):
    Guest(frozen_package, packaged_capture).run()


if __name__ == '__main__':
    assert len(sys.argv) == 3, 'usage: packaged_qualify.py FROZEN_PACKAGE PACKAGED_CAPTURE'
    main(Path(sys.argv[1]), Path(sys.argv[2]))
