"""Guest-only bounded security qualification using frozen candidate artifacts."""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import shutil
import stat
import struct
import subprocess
import sys
import time

from actor import packet

BUS = 'org.freedesktop.DBus'
DENIED = BUS + '.Error.AccessDenied'
WORKLOAD = json.loads(Path(__file__).with_name('workload.json').read_text())
SELECTED = WORKLOAD['selected']


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_check(report, requirement, action, healthy, persist):
    report['outcomes'][requirement] = {'status': 'running'}
    persist()
    try:
        details = action()
        healthy()
        report['outcomes'][requirement] = {'status': 'passed', 'evidence': details}
    except Exception as error:
        report['outcomes'][requirement].update(status='failed', reason=repr(error))
        report['result'] = 'failed'
        persist()
        raise
    persist()


def complete(report):
    assert report['selected'] and len(set(report['selected'])) == len(report['selected']), 'zero/duplicate selection'
    assert set(report['outcomes']) == set(report['selected']), 'incomplete outcome selection'
    assert all(row['status'] == 'passed' for row in report['outcomes'].values()), 'unfinished/failed required outcomes'


def verify_ingress_cleanup(prepared, result):
    before = prepared['snapshot']['usage']
    retained = result['retained_ingress']['usage']
    assert retained['reservations'] == before['reservations'] == 1
    for metric in ['ingress_messages', 'ingress_bytes', 'ingress_fds']:
        assert retained['global'][metric] == before['global'][metric], ('work credit lost on source death', metric)
    assert result['consumer_release'] == 'ok', 'queued work consumer did not retire its token'
    after = result['after']['usage']
    assert after['reservations'] == 0
    assert all(after['global'][metric] == 0 for metric in ['ingress_messages', 'ingress_bytes', 'ingress_fds'])


def await_resource_baseline(before, measure, timeout_ms):
    started = time.monotonic()
    deadline = started + timeout_ms / 1000
    peers = sorted(before['snapshot']['peers'], key=lambda peer: peer['peer'])
    samples = []
    while len(samples) < 128 and time.monotonic() < deadline:
        after = measure()
        samples.append(after)
        observed = time.monotonic()
        if observed > deadline:
            break
        if (after['snapshot']['usage'] == before['snapshot']['usage'] and
                sorted(after['snapshot']['peers'], key=lambda peer: peer['peer']) == peers):
            return dict(after=after, samples=samples, attempts=len(samples),
                        elapsed_ms=(observed - started) * 1000)
    raise AssertionError('resource baseline not reached', dict(
        timeout_ms=timeout_ms, elapsed_ms=(time.monotonic() - started) * 1000,
        attempts=len(samples), terminal=samples[-1] if samples else None))


class Channel:
    def __init__(self, command, log, prefix=''):
        self.command = command
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT, bufsize=0, start_new_session=True)
        self.log, self.prefix = log, prefix
        self.buffer = b''

    def read(self, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            assert time.monotonic() < deadline, ('channel deadline', self.command)
            while b'\n' not in self.buffer:
                assert time.monotonic() < deadline, ('channel deadline', self.command)
                assert select.select([self.process.stdout], [], [], max(deadline - time.monotonic(), 0))[0], ('channel deadline', self.command)
                piece = os.read(self.process.stdout.fileno(), 65536)
                assert piece, ('process exited', self.command, self.process.poll())
                self.buffer += piece
                assert len(self.buffer) <= 4_194_304, 'fixture output line too large'
            raw, self.buffer = self.buffer.split(b'\n', 1)
            line = raw.decode() + '\n'
            with self.log.open('a') as output:
                output.write(line)
            if line.startswith(self.prefix):
                return json.loads(line[len(self.prefix):])

    def write(self, line):
        self.process.stdin.write((line + '\n').encode())
        self.process.stdin.flush()
        return self.read()

    def stop(self, grace=5):
        method = 'eof'
        self.process.stdin.close()
        try:
            self.process.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            method = 'terminate'
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                method = 'kill'
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=3)
        # A runner may exit before descendants; contain only our new process group.
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.set_blocking(self.process.stdout.fileno(), False)
        tail = self.buffer
        while True:
            try:
                piece = os.read(self.process.stdout.fileno(), 65536)
            except BlockingIOError:
                break
            if not piece:
                break
            tail += piece
        if tail:
            with self.log.open('ab') as output:
                output.write(tail)
        self.process.stdout.close()
        return dict(command=self.command, pid=self.process.pid,
                    returncode=self.process.returncode, method=method)


class Actor(Channel):
    def begin(self, **command):
        self.process.stdin.write((json.dumps(command) + '\n').encode())
        self.process.stdin.flush()

    def finish(self):
        response = self.read()
        assert response['ok'], response
        return response['result']

    def call(self, member, signature='', body=(), **options):
        return self.request(op='call', member=member, signature=signature, body=body, **options)

    def request(self, **command):
        response = self.write(json.dumps(command))
        assert response['ok'], response
        return response['result']


def main(candidate, fixtures, evidence):
    assert os.geteuid() == 0 and Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert str(evidence) == '/run/osbus-security'
    directory = evidence.stat()
    assert directory.st_uid == 0 and stat.S_IMODE(directory.st_mode) == 0o755
    manifest = json.loads((candidate / 'candidate.json').read_text())
    assert manifest['version'] == 1 and manifest['not_a_release']
    for name, expected in manifest['files'].items():
        assert sha(candidate / name) == expected, ('candidate artifact changed', name)
    paths = sorted((candidate / 'lib').glob('*/ebin'))
    command = ['elixir', '--erl', '+S 2:2']
    for path in paths:
        command += ['-pa', str(path)]
    policy = evidence / 'policy.exs'
    shutil.copyfile(fixtures / 'policy.exs', policy)
    socket = str(evidence / 'bus')
    daemon_command = command + [str(fixtures / 'daemon.exs'), socket, str(policy)]
    report = {
        'manifest_version': WORKLOAD['version'], 'profile': 'system', 'fixture': 'disposable-vm-security',
        'workload': WORKLOAD,
        'candidate_manifest_sha256': sha(candidate / 'candidate.json'), 'candidate': manifest,
        'fixture_sha256': {path.name: sha(path) for path in sorted(fixtures.iterdir()) if path.is_file()},
        'tools': {tool: str(Path(shutil.which(tool)).resolve())
                  for tool in ['elixir', 'erl', 'python3', 'runuser', 'gdbus', 'busctl']},
        'configuration': policy.read_text(), 'config_sha256': sha(policy),
        'selected': SELECTED, 'outcomes': {key: {'status': 'blocked', 'reason': 'not_executed'} for key in SELECTED},
        'commands': [daemon_command], 'actors': [], 'snapshots': [],
        'limitations': {
            'SEC-06': 'Real closed-socket adapter and Peer admission failure; other adapter/platform failure modes remain separate',
            'SEC-07': 'Real paced absolute expiry plus bounded malformed/auth probes; sustained resource qualification is separate',
            'SEC-12': 'Wire eavesdropping/monitor denial only; no web/cluster payload channel is loaded',
            'credentials_api': 'UNSUPPORTED: P09 public credential-query APIs; root-only inspection is fixture evidence',
            'reference_policy': 'NOT RUN: equivalent reference XML differential gate belongs to P09',
            'release': 'NOT RUN: final packaged P11 headless startup chain',
            'SEC-03': 'Selected malformed/noncanonical/out-of-range probes and valid DATA/bare-AUTH flow; not exhaustive identity corpus',
            'SEC-14': 'Selected RequestName wrong-signature case; broader method schema/body/path/interface matrix is separate',
            'SEC-15': 'Two complete malformed RequestName body frames; broader PRO codec corpus is separate',
            'SEC-17': 'Named/queued/matched peer, explicit capability and ingress reservation cleanup; broader FD/egress ownership is separate',
            'FAIL-02': 'Actual supervised start-peer ceiling failure; the distinct kernel controlling-process-transfer error branch is not injected',
            'RES-03': 'Fixed 96-operation malformed/auth/policy burst with concurrent probe and FD/RSS/atom metrics; broader soak and egress/pending/FD gates remain blocked',
        },
    }

    def persist():
        statuses = [row['status'] for row in report['outcomes'].values()]
        report['counts'] = dict(selected=len(SELECTED), executed=sum(s in ['passed', 'failed'] for s in statuses),
                                passed=statuses.count('passed'), failed=statuses.count('failed'),
                                blocked=statuses.count('blocked') + statuses.count('running'), skipped=0)
        temporary = evidence / 'qualification.json.tmp'
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        temporary.replace(evidence / 'qualification.json')

    persist()
    daemon = None
    actors = []
    try:
        daemon = Channel(daemon_command, evidence / 'daemon.log', 'FIXTURE ')
        report['daemon'] = daemon.read()
        assert report['daemon']['event'] == 'ready'
        assert int(report['daemon']['pid']) == daemon.process.pid
        assert report['daemon']['identity']['uid'] == 0
        assert stat.S_IMODE(Path(socket).stat().st_mode) == 0o666
        report['runtime_configuration'] = report['daemon']['configuration']

        def snapshot(operation='snapshot'):
            result = daemon.write(operation)
            report['snapshots'].append(result)
            persist()
            return result

        def actor(user):
            launch = ['runuser', '-u', user, '--', 'python3', str(fixtures / 'actor.py'), socket]
            report['commands'].append(launch)
            worker = Actor(launch, evidence / f'actor-{len(actors)}-{user}.log')
            identities = worker.read()
            expected_uid = {'root': 0, 'foundationA': 1100, 'foundationB': 1101}[user]
            assert identities['uid'] == expected_uid
            status = Path(f"/proc/{identities['pid']}/status").read_text()
            for key, value in [('Uid:', expected_uid), ('Gid:', identities['gid'])]:
                assert [int(item) for item in next(line for line in status.splitlines() if line.startswith(key)).split()[1:]] == [value] * 4
            identities['proc_status'] = status
            report['actors'].append(identities)
            actors.append(worker)
            persist()
            return worker, identities

        observer, observer_identity = actor('foundationA')
        observer_name = observer.request(op='register', flow='fragmented')['body'][0]
        assert observer.call('RequestName', 'su', ['org.foundation.Observer', 0])['body'] == [1]
        observer.call('GetId')
        original_router = snapshot()['router']

        def healthy():
            result = observer.call('GetNameOwner', 's', ['org.foundation.Observer'])
            assert result['type'] == 2 and result['body'] == [observer_name]
            assert observer.call('GetId')['type'] == 2
            assert snapshot()['router'] == original_router

        def check(requirement, action):
            return run_check(report, requirement, action, healthy, persist)

        def concurrent(worker, command, duration):
            worker.begin(**command)
            deadline = time.monotonic() + duration
            probes = []
            while True:
                assert time.monotonic() < deadline, 'concurrent workload deadline'
                started = time.monotonic()
                assert observer.call('GetNameOwner', 's', ['org.foundation.Observer'])['body'] == [observer_name]
                assert observer.call('GetId')['type'] == 2
                elapsed = (time.monotonic() - started) * 1000
                assert elapsed <= WORKLOAD['healthy_probe_ms'], ('healthy probe deadline', elapsed)
                probes.append(elapsed)
                if b'\n' in worker.buffer or select.select([worker.process.stdout], [], [], 0.1)[0]:
                    return dict(workload=worker.finish(), probes_ms=probes)

        def external_metrics():
            result = snapshot('metrics')
            process = Path(f'/proc/{daemon.process.pid}')
            status = (process / 'status').read_text()
            rss = next(line for line in status.splitlines() if line.startswith('VmRSS:'))
            result['external'] = dict(fd_count=len(list((process / 'fd').iterdir())),
                                      rss_bytes=int(rss.split()[1]) * 1024, proc_status=status)
            return result

        root, root_identity = actor('root')
        root.request(op='register', flow='data')
        service, service_identity = actor('foundationB')
        service_name = service.request(op='register', flow='pipeline')['body'][0]
        receiver, receiver_identity = actor('foundationB')
        receiver_name = receiver.request(op='register')['body'][0]

        def external_clients():
            peers = snapshot()['peers']
            for identity in [observer_identity, root_identity, service_identity, receiver_identity]:
                matching = [peer for peer in peers if peer['credentials']['pid'] == identity['pid']]
                assert matching and all(peer['credentials'][key] == identity[key] for peer in matching for key in ['pid', 'uid', 'gid'])
            tools = []
            for user in ['root', 'foundationA', 'foundationB']:
                for tool, arguments in [
                    ('gdbus', ['call', '--address', 'unix:path=' + socket, '--dest', BUS,
                               '--object-path', '/org/freedesktop/DBus', '--method', BUS + '.GetId']),
                    ('busctl', ['--address=unix:path=' + socket, 'call', BUS,
                                '/org/freedesktop/DBus', BUS, 'GetId']),
                ]:
                    launch = ['runuser', '-u', user, '--', tool] + arguments
                    result = subprocess.run(launch, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
                    tools.append(dict(command=launch, status=result.returncode, output=result.stdout))
                    assert result.returncode == 0 and result.stdout.strip(), tools[-1]
            return dict(tools=tools, credentials=peers)

        check('SEC-01', external_clients)

        def raw_requests(requests):
            results = []
            for wire, expected, closed in requests:
                result = observer.request(op='raw', hex=wire.hex(), until='close' if closed else 'line')
                response = bytes.fromhex(result['response_hex'])
                assert expected in response and (not closed or result['closed']), result
                results.append(dict(sent_hex=wire.hex(), **result))
                healthy()
            return results

        check('SEC-02', lambda: raw_requests([(b'\0AUTH EXTERNAL ' + str(uid).encode().hex().encode() + b'\r\n', b'REJECTED', False) for uid in [0, 1101]]))
        check('SEC-03', lambda: raw_requests([(b'\0AUTH EXTERNAL ' + value + b'\r\n', b'REJECTED', False) for value in [b'zz', b'3030', b'2d31', b'34323934393637323936']]))
        check('SEC-04', lambda: raw_requests([(b'\0' + text, b'', True) for text in [b'BEGIN\r\n', b'AUTH ANONYMOUS\r\nBEGIN\r\n', b'AUTH EXTERNAL\r\nCANCEL\r\nBEGIN\r\n']]))
        check('SEC-05', lambda: raw_requests([(b'\0AUTH ANONYMOUS\r\n', b'REJECTED', False), (b'\0NEGOTIATE_UNIX_FD\r\n', b'ERROR', False)]))

        def credential_failure():
            result = snapshot('credential_failure')
            assert result['adapter_error'] and result['termination'] == 'normal'
            assert result['credentials_before'] == 'nil'
            assert result['before']['usage'] == result['after']['usage']
            assert result['before']['names'] == result['after']['names']
            assert not any(peer['peer'] == result['peer'] for peer in result['after']['peers'])
            return result

        check('SEC-06', credential_failure)
        def authentication_bounds():
            raw = raw_requests([(b'\0AUTH ' + b'x' * 4097, b'', True),
                                (b'\0AUTH EXT', b'', True),
                                (b'\0' + b'AUTH EXTERNAL 30\r\n' * 9, b'REJECTED', True)])
            worker, _identity = actor('foundationA')
            result = concurrent(worker, dict(op='trickle', interval_ms=WORKLOAD['auth']['trickle_interval_ms'],
                                             close_max_ms=WORKLOAD['auth']['close_max_ms']), 4)
            elapsed = result['workload']['elapsed_ms']
            assert WORKLOAD['auth']['close_min_ms'] <= elapsed <= WORKLOAD['auth']['close_max_ms']
            sent = result['workload']['sent_ms']
            assert len(sent) >= 6 and all(second - first < WORKLOAD['auth']['idle_ms'] for first, second in zip(sent, sent[1:]))
            return dict(raw=raw, paced_auth=result)

        check('SEC-07', authentication_bounds)

        def denied_names():
            for worker in [observer, root, service]:
                assert worker.call('RequestName', 'su', ['org.foundation.Forbidden', 0])['error'] == DENIED
            assert observer.call('NameHasOwner', 's', ['org.foundation.Forbidden'])['body'] == [False]
            assert 'org.foundation.Forbidden' not in snapshot()['names']
            return 'root, ordinary and service identities denied without ownership'

        check('SEC-08', denied_names)
        for name in ['org.foundation.Service.Protected', 'org.foundation.Service.Alias']:
            assert service.call('RequestName', 'su', [name, 0])['body'] == [1]
        service.call('GetId')
        service.request(op='poll')

        def denied_aliases():
            results = []
            for destination in ['org.foundation.Service.Protected', 'org.foundation.Service.Alias', service_name]:
                result = observer.call('Read', destination=destination, path='/private', interface='org.foundation.Secret')
                assert result['error'] == DENIED
                assert service.request(op='poll') == []
                results.append(dict(destination=destination, reply=result))
            return results

        check('SEC-09', denied_aliases)
        receiver.call('GetId')
        receiver.request(op='poll')

        def denied_receiving():
            options = dict(destination=receiver_name, path='/private', interface='org.foundation.ReceiveDenied')
            assert observer.call('Read', **options)['error'] == DENIED
            observer.request(op='send', member='Changed', message_type=4, **options)
            observer.request(op='send', member=None, message_type=2, reply_serial=91,
                             destination=receiver_name, interface=None, path=None, signature='s', body=['private payload'])
            observer.call('GetId')
            assert receiver.request(op='poll') == []
            return 'call, signal and method return denied before delivery'

        check('SEC-10', denied_receiving)

        def denied_control():
            snapshot('deny_admission')
            denied, _identity = actor('foundationB')
            response = denied.write(json.dumps(dict(op='register')))
            assert not response['ok'], response
            snapshot('restore_policy')
            replies = []
            for worker in [root, observer]:
                for member, signature, body in [('ReloadConfig', '', []), ('UpdateActivationEnvironment', 'a{ss}', [[['FOUNDATION', 'denied']]]), ('StartServiceByName', 'su', ['org.foundation.Service.Activate', 0])]:
                    result = worker.call(member, signature, body)
                    assert result['error'] == DENIED
                    replies.append(result)
            return replies

        check('SEC-11', denied_control)

        def denied_monitoring():
            assert observer.call('AddMatch', 's', ["eavesdrop='true'"])['error'] == DENIED
            assert observer.call('BecomeMonitor', 'asu', [[], 0], interface=BUS + '.Monitoring')['error'] == DENIED
            peer = next(peer for peer in snapshot()['peers'] if peer['name'] == observer_name)
            assert not peer['match_rules']
            return 'no eavesdrop match or monitor privilege installed'

        check('SEC-12', denied_monitoring)

        def absent_policy():
            missing = command + [str(fixtures / 'daemon.exs'), str(evidence / 'missing'), 'missing']
            result = subprocess.run(missing, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10)
            report['commands'].append(missing)
            (evidence / 'missing-policy.log').write_text(result.stdout)
            assert result.returncode != 0 and 'missing_policy' in result.stdout
            snapshot('stop_policy')
            assert observer.call('RequestName', 'su', ['org.foundation.AfterPolicyDeath', 0])['error'] == DENIED
            state = snapshot()
            assert state['router'] == original_router
            assert 'org.foundation.Observer' in state['names'] and 'org.foundation.AfterPolicyDeath' not in state['names']
            snapshot('restart_policy')
            return 'missing startup rejected; real stopped evaluator denied; valid supervisor restart restored observer'

        check('SEC-13', absent_policy)

        def malformed_method():
            result = observer.call('RequestName', 's', ['org.foundation.Forbidden'])
            assert result['error'] == BUS + '.Error.InvalidArgs'
            assert observer.call('NameHasOwner', 's', ['org.foundation.Forbidden'])['body'] == [False]
            return result

        check('SEC-14', malformed_method)

        def malformed_frames():
            results = []
            name = 'org.foundation.Service.Malformed'
            valid = packet(2, 'RequestName', 'su', [name, 0])
            body_size, header_size = struct.unpack_from('<I', valid, 4)[0], struct.unpack_from('<I', valid, 12)[0]
            body_at = 16 + header_size + -header_size % 8
            truncated = bytearray(valid[:-4])
            struct.pack_into('<I', truncated, 4, body_size - 4)
            bad_string = bytearray(valid)
            bad_string[body_at + 4 + len(name)] = 255
            for frame in [truncated, bad_string]:
                worker, _identity = actor('foundationB')
                unique = worker.request(op='register')['body'][0]
                worker.call('GetId')
                worker.request(op='poll')
                result = worker.request(op='terminal', hex=frame.hex())
                assert result['closed']
                assert observer.call('NameHasOwner', 's', [name])['body'] == [False]
                assert observer.call('NameHasOwner', 's', [unique])['body'] == [False]
                results.append(dict(sent_hex=frame.hex(), **result))
                healthy()
            return results

        check('SEC-15', malformed_frames)

        def registration_boundaries():
            before_hello, _identity = actor('foundationB')
            before_hello.request(op='authenticate')
            denied = before_hello.call('RequestName', 'su', ['org.foundation.Service.BeforeHello', 0])
            assert denied['error'] == DENIED
            assert before_hello.request(op='wait_closed')['closed']
            assert observer.call('NameHasOwner', 's', ['org.foundation.Service.BeforeHello'])['body'] == [False]
            duplicate = service.call('Hello')
            assert duplicate['type'] == 3
            assert observer.call('GetNameOwner', 's', [service_name])['body'] == [service_name]
            sequence, _identity = actor('foundationB')
            replies = sequence.request(op='registration_sequence', name='org.foundation.Service.Sequence')
            assert [reply['reply_serial'] for reply in replies] == [1, 2, 3]
            assert replies[0]['type'] == 2 and replies[0]['body'][0].startswith(':')
            assert replies[1]['type'] == 2 and replies[1]['body'] == [1]
            assert replies[2]['type'] == 3
            assert observer.call('GetNameOwner', 's', ['org.foundation.Service.Sequence'])['body'] == replies[0]['body']
            receiver.call('GetId')
            receiver.request(op='poll')
            service.request(op='send', member='Changed', message_type=4, destination=receiver_name,
                            path='/public', interface='org.foundation.Allowed', sender=observer_name,
                            signature='s', body=['forged sender probe'])
            service.call('GetId')
            delivered = receiver.request(op='poll')
            assert len(delivered) == 1 and delivered[0]['sender'] == service_name
            assert delivered[0]['body'] == ['forged sender probe']
            return dict(pre_hello=denied, duplicate_hello=duplicate, coalesced_sequence=replies,
                        forged_sender_requested=observer_name, delivered=delivered)

        check('SEC-16', registration_boundaries)

        def peer_cleanup():
            victim, _identity = actor('foundationB')
            unique = victim.request(op='register')['body'][0]
            owned = 'org.foundation.Service.Cleanup'
            queued = 'org.foundation.Service.Alias'
            assert victim.call('RequestName', 'su', [owned, 0])['body'] == [1]
            assert victim.call('RequestName', 'su', [queued, 0])['body'] == [2]
            assert receiver.call('RequestName', 'su', [owned, 0])['body'] == [2]
            assert victim.call('AddMatch', 's', ["type='signal',interface='org.foundation.Cleanup'"])['body'] == []
            victim.call('GetId')
            victim.request(op='poll')
            prepared = snapshot('prepare_cleanup ' + unique)
            record = next(peer for peer in prepared['snapshot']['peers'] if peer['name'] == unique)
            assert record['match_rules'] and record['capabilities'] == 1
            assert prepared['snapshot']['usage']['reservations'] == 1
            before_queues = prepared['snapshot']['queues']
            assert next(row for row in before_queues if row['name'] == queued)['queue'][0]['unique'] == unique
            assert next(row for row in before_queues if row['name'] == owned)['unique'] == unique
            result = snapshot('kill_peer ' + unique)
            assert result['termination'] == 'killed' and not result['match_rules'] and result['capabilities'] == 0
            verify_ingress_cleanup(prepared, result)
            assert victim.request(op='wait_closed')['closed']
            after = result['repeated_cleanup']
            assert after['usage']['reservations'] == 0
            assert after['usage']['global']['connections'] == prepared['snapshot']['usage']['global']['connections'] - 1
            assert after['usage']['global']['ingress_messages'] == 0 and after['usage']['global']['ingress_bytes'] == 0
            assert unique not in after['names'] and not any(peer['peer'] == prepared['peer'] for peer in after['peers'])
            assert not any(item['unique'] == unique for row in after['queues'] for item in row['queue'])
            assert observer.call('GetNameOwner', 's', [owned])['body'] == [receiver_name]
            assert observer.call('GetNameOwner', 's', [queued])['body'] == [service_name]
            assert result['after']['usage'] == after['usage']
            assert result['after']['queues'] == after['queues']
            return dict(prepared=prepared, killed=result)

        check('SEC-17', peer_cleanup)
        check('FAIL-01', lambda: dict(procedure='SEC-17', evidence=report['outcomes']['SEC-17']['evidence']))

        def incumbent_listener():
            before = Path(socket).lstat()
            launch = command + [str(fixtures / 'daemon.exs'), socket, str(policy)]
            result = subprocess.run(launch, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
            report['commands'].append(launch)
            (evidence / 'incumbent-listener.log').write_text(result.stdout)
            after = Path(socket).lstat()
            assert result.returncode != 0
            assert (before.st_ino, before.st_uid, before.st_mode) == (after.st_ino, after.st_uid, after.st_mode)
            return dict(command=launch, exit_status=result.returncode, output=result.stdout,
                        inode=after.st_ino, uid=after.st_uid, mode=stat.S_IMODE(after.st_mode))

        check('SYS-02', incumbent_listener)

        def startup_failure():
            before = external_metrics()
            full = snapshot('fill_peer_supervisor')
            assert full['active'] == full['limit'] == WORKLOAD['supervisor_max_children']
            try:
                result = observer.request(op='raw', hex=b'\0AUTH EXTERNAL 31313030\r\n'.hex(), until='close')
                assert result['closed'] and result['response_hex'] == ''
                assert observer.call('GetId')['type'] == 2
            finally:
                restored = snapshot('clear_peer_supervisor')
            assert restored['active'] == full['before']
            after = external_metrics()
            assert before['snapshot']['usage'] == after['snapshot']['usage']
            assert before['external']['fd_count'] == after['external']['fd_count']
            return dict(before=before, full=full, rejected=result, restored=restored, after=after)

        check('FAIL-02', startup_failure)

        def bounded_burst():
            external_metrics()  # Warm the measurement path before freezing its baseline.
            before = external_metrics()
            worker, _identity = actor('foundationA')
            result = concurrent(worker, dict(op='burst', **WORKLOAD['burst']), WORKLOAD['burst']['duration_max_seconds'] + 3)
            assert result['workload']['counts'] == {kind: WORKLOAD['burst']['per_kind'] for kind in WORKLOAD['burst']['kinds']}
            quiescence = await_resource_baseline(before, external_metrics, WORKLOAD['metrics']['quiescence_ms'])
            after = quiescence['after']
            assert before['snapshot']['usage'] == after['snapshot']['usage']
            assert after['decision_keys'] == before['decision_keys'] == 7
            assert after['decision_counts']['own']['deny'] - before['decision_counts']['own']['deny'] == WORKLOAD['burst']['per_kind']
            assert after['policy_queue'] == after['router_queue'] == 0
            assert after['external']['fd_count'] - before['external']['fd_count'] <= WORKLOAD['metrics']['fd_growth_max']
            assert after['external']['rss_bytes'] <= WORKLOAD['metrics']['rss_max_bytes']
            assert after['atom_count'] - before['atom_count'] <= WORKLOAD['metrics']['atom_growth_max']
            return dict(before=before, concurrent=result, after=after, quiescence=quiescence)

        check('RES-03', bounded_burst)
        complete(report)
        report['result'] = 'passed_selected_scope'
        persist()
        print(json.dumps({'counts': report['counts'], 'result': report['result'],
                          'candidate_manifest_sha256': report['candidate_manifest_sha256'],
                          'evidence': str(evidence), 'limitations': report['limitations']}, sort_keys=True))
    finally:
        report['shutdown'] = []
        shutdown_errors = []
        for worker in actors + ([daemon] if daemon is not None else []):
            try:
                report['shutdown'].append(worker.stop())
            except Exception as error:
                shutdown_errors.append(repr(error))
        report['shutdown_errors'] = shutdown_errors
        persist()
        assert not shutdown_errors, shutdown_errors


if __name__ == '__main__':
    main(*(Path(argument) for argument in sys.argv[1:]))
