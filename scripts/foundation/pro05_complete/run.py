"""Guest-only PRO05 adapter for the existing independent actor/channel harness.

Importing this module has no effects. Runtime entry requires the disposable VM
marker, fixed private endpoint, pinned current artifact and inherited helpers.
Source tests use injected channels; they never start this adapter on the host.
"""
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

from wire_replay import bounded, decode_frames, verify_trace
from vectors import wire_string

HERE = Path(__file__).resolve().parent
BUS = 'org.freedesktop.DBus'
OWNER = 'org.foundation.Observer'
ROOT = Path('/run/osbus-security/pro05-complete')
MATCH = "type='signal',arg0path='/probe'"
BACKENDS = ('reference', 'gao_bus')
MEMORY_MAX = 268_435_456
ATOM_GROWTH_MAX = 16


def pin(path):
    data = path.read_bytes()
    return dict(bytes=len(data), mode=stat.S_IMODE(path.stat().st_mode),
                sha256=hashlib.sha256(data).hexdigest())


def kernel(status, identity):
    rows = {row.split(':', 1)[0]: row.split(':', 1)[1].split()
            for row in status.splitlines() if ':' in row}
    assert int(rows['Pid'][0]) == identity['pid']
    assert rows['Uid'] == [str(identity['uid'])] * 4
    assert rows['Gid'] == [str(identity['gid'])] * 4


def identity(pid, uid):
    accepted = dict(pid=pid, uid=uid, gid=uid)
    raw = Path('/proc', str(pid), 'status').read_text()
    kernel(raw, accepted)
    return accepted, raw


def process_sample(accepted):
    """PRO03 incarnation/FD sampler, retaining additional raw memory endpoints."""
    root = Path('/proc', str(accepted['pid']))
    errors, links = [], {}
    before_stat = after_stat = status = ''
    fields = None
    rss_bytes = None
    try:
        before_stat = (root / 'stat').read_text()
        fields = before_stat[before_stat.rfind(')') + 2:].split()
        status = (root / 'status').read_text()
        kernel(status, accepted)
        for entry in (root / 'fd').iterdir():
            try:
                links[entry.name] = os.readlink(entry)
            except FileNotFoundError:
                errors.append(dict(fd=entry.name, reason='enoent', observation='incomplete'))
        after_stat = (root / 'stat').read_text()
        after = after_stat[after_stat.rfind(')') + 2:].split()
        assert fields[19] == after[19], 'process incarnation changed during sample'
        rss = next(row for row in status.splitlines() if row.startswith('VmRSS:'))
        assert rss.split()[2] == 'kB'
        rss_bytes = int(rss.split()[1]) * 1024
    except FileNotFoundError:
        errors.append(dict(reason='process_retired', observation='incomplete'))
    return dict(identity=copy.deepcopy(accepted), complete=not errors, errors=errors,
                starttime_ticks=int(fields[19]) if fields else None, fd_targets=links,
                fd_count=len(links), rss_bytes=rss_bytes,
                cpu_ticks=dict(user=int(fields[11]), system=int(fields[12])) if fields else None,
                proc_stat=before_stat, proc_stat_after=after_stat, proc_status=status)


def check_guest(evidence):
    assert not sys.flags.optimize and os.geteuid() == 0
    marker = Path('/etc/osbus-security-guest')
    info = marker.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0
    assert marker.read_text() == 'isolated-vm\n'
    assert evidence == ROOT and evidence.is_dir()
    info = evidence.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0
    assert stat.S_IMODE(info.st_mode) == 0o755
    assert not (evidence / 'qualification.json').exists()


def check_inputs(candidate, repository):
    bindings = json.loads((HERE / 'bindings.json').read_text())
    assert pin(HERE / 'cleanup.py')['sha256'] == bindings['cleanup_sha256']
    artifact = candidate / 'artifact.json'
    assert pin(artifact)['sha256'] == bindings['artifact_sha256']
    manifest = json.loads(artifact.read_text())
    assert manifest['not_a_release'] is True and manifest['sources'] and manifest['files']
    assert len(manifest['sources']) == bindings['production_sources']
    assert len(manifest['files']) == bindings['artifact_files']
    assert manifest['origin_pin']['sha256'] == bindings['runtime_manifest_sha256']
    assert {str(path.relative_to(candidate)) for path in (candidate / 'lib').rglob('*')
            if path.is_file()} == set(manifest['files'])
    for name, expected in manifest['files'].items():
        path = candidate / name
        assert not path.is_symlink() and path.is_relative_to(candidate)
        observed = pin(path)
        assert observed['sha256'] == expected['sha256'] and observed['bytes'] == expected['bytes']
        assert observed['mode'] == expected['mode'] & ~0o222
    for name, expected in bindings['helpers'].items():
        path = repository / name
        assert not path.is_symlink() and path.is_relative_to(repository)
        observed = pin(path)
        assert observed['sha256'] == expected['sha256'] and observed['bytes'] == expected['bytes']
        assert observed['mode'] == expected['mode'] & ~0o222
    return bindings, manifest


def load_support(repository):
    original = repository / 'scripts/foundation/vm_security'

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    search_path = list(sys.path)
    try:
        sys.path.insert(0, str(original))
        legacy = load('pro05_inherited_channel', original / 'run.py')
    finally:
        sys.path[:] = search_path
    cleanup = load('pro05_inherited_cleanup', HERE / 'cleanup.py')
    return original, legacy, cleanup.stop_channel


def query_wire(member, serial, signature='', body=()):
    """The inherited ordinary call omits an empty body-signature field."""
    assert signature in ('', 's') and len(body) == len(signature)
    fields = [(1, 'o', '/org/freedesktop/DBus'), (2, 's', BUS),
              (3, 's', member), (6, 's', BUS)]
    if signature:
        fields.append((8, 'g', signature))
    header = bytearray()
    for code, kind, value in fields:
        header.extend(bytes(-len(header) % 8))
        header.extend(bytes([code, 1])+kind.encode()+b'\0')
        header.extend(bytes([len(value)])+value.encode()+b'\0' if kind == 'g' else wire_string(value))
    payload = b''.join(wire_string(value) for value in body)
    fixed = bytes([ord('l'), 1, 0, 1])+len(payload).to_bytes(4, 'little')
    fixed += serial.to_bytes(4, 'little')+len(header).to_bytes(4, 'little')
    return fixed+header+bytes(-len(header) % 8)+payload


def checked_reply(response, member, serial, signature='', body=(), destination=None):
    """Bind public identity queries to their actual request and raw reply."""
    frames = decode_frames(verify_trace(response, [query_wire(member, serial, signature, body)], 3000))
    assert len(frames) == 1
    result = response['result']
    assert frames[0]['message'] == result and result['type'] == 2
    assert result['sender'] == BUS and result['reply_serial'] == serial
    expected_signature = {'ListNames':'as', 'GetNameOwner':'s', 'GetId':'s',
                          'GetConnectionUnixUser':'u', 'GetConnectionUnixProcessID':'u',
                          'NameHasOwner':'b'}[member]
    assert frames[0]['fields'].get(8) == expected_signature
    if destination is not None:
        assert frames[0]['fields'].get(6) == destination
    return result


def settled_projection(value):
    return dict(authority=value['authority'], resources={name: dict(
        identity=value['resources'][name]['identity'],
        starttime_ticks=value['resources'][name]['starttime_ticks'],
        fd_targets=value['resources'][name]['fd_targets']) for name in ('daemon', 'observer')})


def resource_bounds(resources, baseline=None):
    """Fixed sampled ceilings from the accepted finite native workload."""
    for role in ('daemon', 'observer'):
        sample = resources[role]
        assert sample['complete'] is True and sample['errors'] == []
        assert type(sample['rss_bytes']) is int and 0 < sample['rss_bytes'] <= MEMORY_MAX
    native = resources.get('native')
    if native is not None:
        assert native['complete'] is True
        assert type(native['vm']['memory']['total']) is int
        assert 0 < native['vm']['memory']['total'] <= MEMORY_MAX
        assert type(native['vm']['atom_count']) is int and native['vm']['atom_count'] > 0
        if baseline is not None:
            assert native['vm']['identity'] == baseline['native']['vm']['identity']
            assert native['vm']['atom_count']-baseline['native']['vm']['atom_count'] <= ATOM_GROWTH_MAX


def natural_retirement(value):
    assert value['method'] == 'eof' and value['returncode'] == 0
    before = value['before_containment']
    assert before['pid_absent'] is before['actor_pid_absent'] is before['group_absent'] is True
    assert before['timed_out'] is False and before['errors'] == []


def configuration_record(backend, path, raw):
    """Retain the exact guest configuration used by this private backend."""
    assert backend in BACKENDS and type(raw) is bytes and raw
    filename = 'policy.exs' if backend == 'gao_bus' else 'reference.conf'
    assert path == ROOT / backend / filename
    return dict(backend=backend, profile='core', path=str(path), bytes=raw.decode('utf-8'),
                sha256=hashlib.sha256(raw).hexdigest(), endpoint=str(ROOT / backend / 'bus'),
                system_mode=True, external_only=True, isolated=True)


def finalize_backend(record):
    """Measure only after observations and natural teardown; fail before counting."""
    from contract import expected_invariant, measure_backend, validate_backend
    try:
        assert record['status'] == 'observed_pending_teardown'
        assert record['shutdown_errors'] == [] and record['endpoint_removed'] is True
        bounded(record['shutdown_ms'], 5000)
        record['invariant_measurement'] = measure_backend(record)
        # PRO-05/complete-requirement source-bound invariant measurement.
        assert record['invariant_measurement'] == expected_invariant()
        record['status'] = 'passed_pending_independent_review'
        validate_backend(record)
    except Exception as error:
        record.update(status='failed', failure=repr(error))
        raise


class Driver:
    """One private backend; controller.py owns the finite scenario ordering."""
    def __init__(self, backend, candidate, original, legacy, cleanup, directory,
                 reference_executable, deadline, persist):
        assert backend in BACKENDS
        self.backend, self.candidate, self.original = backend, candidate, original
        self.legacy, self.cleanup, self.directory = legacy, cleanup, directory
        self.endpoint = directory / 'bus'
        self.reference_executable = reference_executable
        self.deadline, self._persist = deadline, persist
        self.workers, self.retired = [], set()
        self.daemon = self.reference = self.reference_log = None
        self.observer = self.observer_worker = self.baseline = None
        self.record = dict(backend=backend, profile='core', status='running', commands=[],
                           actors=[], receipts=[], daemon_events=[], snapshots=[], settles=[],
                           retirements=[], scenario_events=[], shutdown_errors=[])

    def persist(self, event=None):
        # Keep every receipt in memory, flush at completed groups/failure and in
        # main's finally. Whole-report serialization must not consume a source
        # or DOWN/restore deadline as evidence grows across 32 prefix cycles.
        if event is not None:
            self.record['scenario_events'].append(copy.deepcopy(event))
            if event['event'] in ('group-complete', 'failure'):
                self._persist()

    def remaining(self, limit=None):
        value = min(self.deadline, limit if limit is not None else self.deadline) - time.monotonic()
        assert value > 0, 'PRO05 caller deadline'
        return value

    def request(self, worker, command=None, remaining_ms=None, **options):
        command = dict(command or {}, **options)
        began = time.monotonic()
        budget = 1000 if command['op'] == 'observe' else 3000
        if remaining_ms is not None:
            assert type(remaining_ms) in (int, float) and math.isfinite(remaining_ms) and remaining_ms > 0
            budget = min(budget, remaining_ms)
        limit = min(self.deadline, began + budget / 1000)
        command = dict(command, deadline_monotonic=limit)
        self.remaining(limit)
        worker['channel'].begin(**command)
        response = worker['channel'].read(timeout=self.remaining(limit))
        self.record['receipts'].append(dict(identity=copy.deepcopy(worker.get('identity')),
            request=command, response=copy.deepcopy(response), elapsed_ms=(time.monotonic()-began)*1000))
        self.persist()
        assert time.monotonic() < limit, 'PRO05 request exceeded fixed caller deadline'
        assert response['ok'] is True, response
        return response

    def call(self, worker, member, signature='', body=(), remaining_ms=None):
        worker['serial'] += 1
        response = self.request(worker, remaining_ms=remaining_ms, op='call', member=member,
                                signature=signature, body=body)
        result = response['result']
        assert result['sender'] == BUS and result['reply_serial'] == worker['serial']
        return response

    def public_call(self, member, signature='', body=(), limit=None):
        response = self.call(self.observer_worker, member, signature, body,
                             remaining_ms=self.remaining(limit)*1000)
        result = checked_reply(response, member, self.observer_worker['serial'], signature, body,
                               self.observer['unique'])
        return result, response

    def start_source(self, group, index):
        return self.start_actor(1101, f'{group}-{index}')

    def start_actor(self, uid, phase):
        user = {1100:'foundationA', 1101:'foundationB'}[uid]
        argv = ['runuser', '-u', user, '--', 'python3', str(HERE / 'actor_overlay.py'),
                str(self.original), str(self.endpoint)]
        self.record['commands'].append(argv)
        worker = dict(channel=self.legacy.Actor(argv, self.directory / f'actor-{len(self.workers)}.log'),
                      identity=None, serial=0)
        self.workers.append(worker)
        announced = worker['channel'].read(timeout=self.remaining(time.monotonic()+1))
        accepted, raw = identity(announced['pid'], uid)
        assert announced == accepted
        worker.update(identity=accepted, proc_status=raw, phase=phase)
        response = self.request(worker, op='register')
        value = response['result']
        worker.update(unique=value['unique'], bus_id=value['bus_id'], serial=2, registration=response)
        assert value['buffered_hex'] == '' and value['pending_messages'] == 0
        self.record['actors'].append({key: copy.deepcopy(value) for key, value in worker.items() if key != 'channel'})
        self.persist()
        return worker

    def native(self, command, remaining_ms=1500):
        assert self.backend == 'gao_bus'
        budget = min(1500, math.floor(min(remaining_ms, self.remaining()*1000)))
        assert budget > 0, 'PRO05 fixture caller budget exhausted'
        limit = min(self.deadline, time.monotonic()+budget/1000)
        command = dict(command, remaining_ms=budget)
        self.daemon.process.stdin.write((json.dumps(command)+'\n').encode())
        self.daemon.process.stdin.flush()
        event = self.daemon.read(timeout=self.remaining(limit))
        self.record['daemon_events'].append(copy.deepcopy(event))
        self.persist()
        assert time.monotonic() < limit, 'PRO05 fixture control deadline'
        return event

    def _snapshot(self, source, limit):
        observer = self.observer
        public = {}
        for key, member, arguments in (
                ('names','ListNames',()), ('owner','GetNameOwner',(OWNER,)),
                ('uid','GetConnectionUnixUser',(observer['unique'],)),
                ('pid','GetConnectionUnixProcessID',(observer['unique'],)), ('bus_id','GetId',())):
            result, _ = self.public_call(member, 's' if arguments else '', arguments, limit)
            public[key], = result['body']
        assert public['owner'] == observer['unique'] and public['bus_id'] == observer['bus_id']
        assert public['uid'] == observer['identity']['uid'] and public['pid'] == observer['identity']['pid']
        public['owner'] = OWNER  # Sentinel label; its raw resolution receipt is retained above.
        source_public = None
        if source is not None:
            uid, _ = self.public_call('GetConnectionUnixUser', 's', [source['unique']], limit)
            pid, _ = self.public_call('GetConnectionUnixProcessID', 's', [source['unique']], limit)
            assert uid['body'] == [source['identity']['uid']] and pid['body'] == [source['identity']['pid']]
            source_public = dict(identity=copy.deepcopy(source['identity']), unique=source['unique'],
                                 bus_id=source['bus_id'], uid=uid['body'][0], pid=pid['body'][0])
        names = sorted(public.pop('names'))
        public.update(identity=copy.deepcopy(observer['identity']), unique=observer['unique'])
        resources = dict(daemon=process_sample(self.record['daemon']['identity']),
                         observer=process_sample(observer['identity']))
        assert all(value['complete'] is True and value['errors'] == [] for value in resources.values())
        if self.backend == 'gao_bus':
            command = dict(op='sample', observer=observer['unique'])
            if source is not None:
                command['source'] = source['unique']
            native = self.native(command, self.remaining(limit)*1000)
            assert native['event'] == 'sample' and native['complete'] is True and native['errors'] == []
            resources['native'] = native['resources']
            core = native['authority']
        else:
            # Reference has public observations and OS process metrics only.
            core = dict(identity=copy.deepcopy(self.record['daemon']['identity']),
                        starttime_ticks=resources['daemon']['starttime_ticks'])
        info = self.endpoint.lstat()
        assert stat.S_ISSOCK(info.st_mode)
        value = dict(authority=dict(observer=public, source=source_public, names=names, core=core,
            endpoint=dict(device=info.st_dev, inode=info.st_ino)), resources=resources)
        self.record['snapshots'].append(copy.deepcopy(value))
        self.persist()
        self.remaining(limit)
        resource_bounds(resources, self.baseline['resources'] if self.baseline is not None else None)
        return value

    def snapshot(self, source, remaining_ms=None):
        began = time.monotonic()
        remaining_ms = 1500 if remaining_ms is None else remaining_ms
        assert 0 < remaining_ms <= 1500
        limit = min(self.deadline, began+remaining_ms/1000)
        previous = None
        samples = []
        expected = settled_projection(self.baseline) if source is None and self.baseline is not None else None
        try:
            for _ in range(128):
                value = self._snapshot(source, limit)
                samples.append(value)
                projection = settled_projection(value)
                if projection == previous and (expected is None or projection == expected):
                    if self.baseline is None and source is None:
                        self.baseline = copy.deepcopy(value)
                    return value
                previous = projection
            raise AssertionError('PRO05128-read settle bound')
        finally:
            self.record['settles'].append(dict(samples=len(samples), elapsed_ms=(time.monotonic()-began)*1000,
                budget_ms=remaining_ms, expected=expected))
            self.persist()

    def watch(self, source):
        if self.backend == 'gao_bus':
            event = self.native(dict(op='watch', name=source['unique'], observer=self.observer['unique']))
            assert event['event'] == 'watched' and event['name'] == source['unique']
            options = event['peer_options']
            assert options['frame_options']['max_bytes'] == 1_048_576
            assert options['xml_limits'] is None and options['frame_timeout_ms'] == 5000
            assert options['auth_limits']['timeout_ms'] == 1500
            assert options['auth_limits']['idle_timeout_ms'] == 500
            return dict(kind='beam-monitor', source_identity=copy.deepcopy(source['identity']),
                        name=source['unique'], peer=event['peer'], reference=event['reference'], watch_event=event)
        result, receipt = self.public_call('NameHasOwner', 's', [source['unique']])
        assert result['body'] == [True]
        return dict(kind='public-name', source_identity=copy.deepcopy(source['identity']),
                    name=source['unique'], watch_receipt=receipt)

    def await_down(self, source, watch, remaining_ms=None):
        began = time.monotonic()
        remaining_ms = 1500 if remaining_ms is None else remaining_ms
        assert 0 < remaining_ms <= 1500
        limit = min(self.deadline, began+remaining_ms/1000)
        if self.backend == 'gao_bus':
            event = self.native(dict(op='await_down', name=source['unique'], observer=self.observer['unique']),
                                self.remaining(limit)*1000)
            assert event['event'] == 'down'
            return dict(kind='beam-monitor', source_identity=copy.deepcopy(source['identity']),
                        name=source['unique'], peer=event['peer'], reference=event['reference'],
                        reason=event['reason'], native_down=event, elapsed_ms=(time.monotonic()-began)*1000)
        attempts = []
        for _ in range(128):
            result, receipt = self.public_call('NameHasOwner', 's', [source['unique']], limit)
            attempts.append(receipt)
            if result['body'] == [False]:
                return dict(kind='public-name', source_identity=copy.deepcopy(source['identity']),
                    name=source['unique'], has_owner=False, public_reply=receipt,
                    attempts=attempts, elapsed_ms=(time.monotonic()-began)*1000)
            assert result['body'] == [True]
        raise AssertionError('PRO05 reference disappearance128-read bound')

    def observe(self, source_name=None):
        serial = self.observer_worker['serial']+1
        response = self.request(self.observer_worker, op='observe', serial=serial, owner=OWNER, source_name=source_name)
        self.observer_worker['serial'] = serial+1
        return dict(response=response, serial=serial)

    def retire(self, source):
        outcome = self.cleanup(source['channel'], source['identity'])
        self.retired.add(id(source))
        self.record['retirements'].append(copy.deepcopy(outcome))
        self.persist()
        natural_retirement(outcome)
        return outcome

    def close_source(self, source):
        return self.request(source, op='close')

    def start(self):
        assert self.directory == ROOT / self.backend and not self.directory.exists()
        self.directory.mkdir(mode=0o755)
        assert not os.path.lexists(self.endpoint)
        if self.backend == 'gao_bus':
            policy = self.directory / 'policy.exs'
            policy.write_bytes((HERE / 'policy.exs').read_bytes())
            policy.chmod(0o600)
            argv = ['elixir', '--erl', '+S 2:2']
            for path in sorted((self.candidate / 'lib').glob('*/ebin')):
                argv += ['-pa', str(path)]
            argv += [str(HERE / 'daemon.exs'), str(self.endpoint), str(policy)]
            self.record['commands'].append(argv)
            self.daemon = self.legacy.Channel(argv, self.directory / 'daemon.log', 'FIXTURE ')
            ready = self.daemon.read(timeout=self.remaining(time.monotonic()+10))
            assert ready['event'] == 'ready' and int(ready['pid']) == self.daemon.process.pid
            assert ready['configuration']['profile'] == 'system'
            assert ready['configuration']['config_file'] is None
            assert ready['configuration']['inherited_listener'] is False
            assert ready['configuration']['auth_limits'] == dict(timeout_ms=1500, idle_timeout_ms=500)
            assert ready['configuration']['resource_limits']['peer']['frame_bytes'] == 1_048_576
            self.record['ready'] = ready
            pid = self.daemon.process.pid
            backend_version = ready['otp'] + ' / Elixir ' + ready['elixir']
        else:
            assert self.reference_executable.is_absolute() and str(self.reference_executable).startswith('/nix/store/')
            version_argv = [str(self.reference_executable), '--version']
            self.record['commands'].append(version_argv)
            version = subprocess.run(version_argv, stdin=subprocess.DEVNULL, capture_output=True,
                                     text=True, timeout=self.remaining(time.monotonic()+1))
            self.record['reference_version'] = dict(argv=version_argv, returncode=version.returncode,
                stdout=version.stdout, stderr=version.stderr, executable=pin(self.reference_executable))
            assert version.returncode == 0
            backend_version = version.stdout
            policy = self.directory / 'reference.conf'
            policy.write_bytes((HERE / 'reference.conf').read_bytes())
            argv = [str(self.reference_executable), '--nofork', '--nopidfile', '--config-file='+str(policy)]
            self.record['commands'].append(argv)
            self.reference_log = (self.directory / 'daemon.log').open('xb')
            self.reference = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=self.reference_log,
                stderr=subprocess.STDOUT, start_new_session=True)
            limit = min(self.deadline, time.monotonic()+10)
            while not self.endpoint.exists():
                self.remaining(limit)
                assert self.reference.poll() is None, 'reference startup exited'
            pid = self.reference.pid
        accepted, raw = identity(pid, 0)
        assert type(backend_version) is str and backend_version.strip()
        self.record['daemon'] = dict(identity=accepted, proc_status=raw,
                                     version=backend_version, argv=argv)
        self.record['configuration'] = configuration_record(self.backend, policy, policy.read_bytes())
        info = self.endpoint.lstat()
        assert stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
        self.socket_identity = dict(device=info.st_dev, inode=info.st_ino)
        self.observer_worker = self.start_actor(1100, 'observer')
        self.observer = {key: copy.deepcopy(self.observer_worker[key]) for key in ('identity', 'unique', 'bus_id')}
        self.observer['owner'] = OWNER
        owned = self.call(self.observer_worker, 'RequestName', 'su', [OWNER, 0])
        assert owned['result']['type'] == 2 and owned['result']['body'] == [1]
        acquired = self.request(self.observer_worker, op='poll', timeout=0.05)['result']
        assert len(acquired) == 1 and acquired[0]['type'] == 4
        assert acquired[0]['sender'] == BUS and acquired[0]['member'] == 'NameAcquired' and acquired[0]['body'] == [OWNER]
        matched = self.call(self.observer_worker, 'AddMatch', 's', [MATCH])
        assert matched['result']['type'] == 2 and matched['result']['body'] == []
        assert self.request(self.observer_worker, op='poll', timeout=0.05)['result'] == []
        self.record['observer'] = copy.deepcopy(self.observer)
        self.persist()

    def shutdown(self):
        began = time.monotonic()
        for worker in self.workers:
            if id(worker) in self.retired:
                continue
            try:
                self.retire(worker)
            except Exception as error:
                self.record['shutdown_errors'].append(repr(error))
        try:
            if self.daemon is not None:
                accepted = self.record.get('daemon', {}).get('identity',
                    dict(pid=self.daemon.process.pid, uid=0, gid=0))
                try:
                    self.daemon.process.stdin.write(b'{"op":"quit"}\n')
                    self.daemon.process.stdin.flush()
                    event = self.daemon.read(timeout=self.remaining(time.monotonic()+2))
                    self.record['daemon_events'].append(event)
                    assert event == dict(event='stopped', normal=True, watches=0)
                finally:
                    self.record['daemon_retirement'] = self.cleanup(self.daemon, accepted)
                natural_retirement(self.record['daemon_retirement'])
            elif self.reference is not None:
                stop_started = time.monotonic()
                self.reference.send_signal(signal.SIGTERM)
                code = self.reference.wait(timeout=5)
                try:
                    os.killpg(self.reference.pid, 0)
                    absent = False
                except ProcessLookupError:
                    absent = True
                self.record['daemon_retirement'] = dict(method='sigterm', returncode=code,
                    pid_absent=not Path('/proc', str(self.reference.pid)).exists(), group_absent=absent,
                    forced=False, elapsed_ms=(time.monotonic()-stop_started)*1000)
                assert code == 0 and absent and self.record['daemon_retirement']['pid_absent']
            if os.path.lexists(self.endpoint) and self.backend == 'reference':
                info = self.endpoint.lstat()
                assert stat.S_ISSOCK(info.st_mode)
                assert dict(device=info.st_dev, inode=info.st_ino) == self.socket_identity
                self.endpoint.unlink()
            self.record['endpoint_removed'] = not os.path.lexists(self.endpoint)
            assert self.record['endpoint_removed'] and (time.monotonic()-began)*1000 <= 5000
        except Exception as error:
            self.record['shutdown_errors'].append(repr(error))
        finally:
            self.record['shutdown_ms'] = (time.monotonic()-began)*1000
            if self.reference_log is not None:
                self.reference_log.close()
            self.persist()


def main(candidate, repository, evidence, selection, reference_executable):
    if sys.flags.optimize:
        raise RuntimeError('PRO05 requires enabled assertions')
    assert selection == 'complete_core', 'network requires its own observed profile'
    check_guest(evidence)
    bindings, artifact = check_inputs(candidate, repository)
    original, legacy, cleanup = load_support(repository)
    from controller import run_cases
    from contract import BOUNDS, SCENARIO, SELECTED, source_sha, validate_complete
    report = dict(version=1, fixture='PRO05-complete-core-source3', scenario=SCENARIO, profile='core',
        selected=SELECTED, backends=[], bindings=bindings, artifact=artifact,
        candidate_artifact_sha256=bindings['artifact_sha256'], candidate_source_sha256=source_sha(artifact),
        fixture_pins={path.name:pin(path) for path in sorted(HERE.iterdir()) if path.is_file()},
        bounds=copy.deepcopy(BOUNDS), result='running', accepted_index_mutation=False,
        runtime_qualification=False, requirement_qualification=False,
        product_qualified=False, readiness='L0')

    def persist():
        passed = sum(row.get('status') == 'passed_pending_independent_review' for row in report['backends'])
        failed = sum(row.get('status') == 'failed' for row in report['backends'])
        report['counts'] = dict(selected=2, executed=passed+failed, passed=passed,
                               failed=failed, blocked=2-passed-failed, skipped=0)
        target = evidence / 'qualification.json'
        temporary = target.with_suffix('.json.tmp')
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False)+'\n')
        temporary.replace(target)

    started = time.monotonic()
    deadline = started+240
    persist()
    for backend in BACKENDS:
        driver = Driver(backend, candidate, original, legacy, cleanup, evidence / backend,
                        reference_executable, deadline, persist)
        report['backends'].append(driver.record)
        try:
            driver.start()
            scenario = run_cases(driver)
            scenario.pop('events')  # Exact copies already retained in scenario_events.
            driver.record['scenario'] = scenario
            driver.record['status'] = 'observed_pending_teardown'
        except Exception as error:
            driver.record.update(status='failed', failure=repr(error))
            report.update(result='failed', failure=repr(error))
            raise
        finally:
            driver.shutdown()
            if driver.record['shutdown_errors'] or not driver.record.get('endpoint_removed'):
                driver.record['status'] = 'failed'
            persist()
        try:
            finalize_backend(driver.record)
        except Exception as error:
            report.update(result='failed', failure=repr(error))
            persist()
            raise
        persist()
    report.update(authority_elapsed_ms=(time.monotonic()-started)*1000,
                  result='passed_complete_core_PRO05_runtime_pending_independent_review')
    try:
        validate_complete(report)
    except Exception as error:
        report.update(result='failed', failure=repr(error))
        persist()
        raise
    persist()
    print(json.dumps(dict(counts=report['counts'], product_qualified=False, readiness='L0')))


if __name__ == '__main__':
    assert len(sys.argv) == 6
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5]))
