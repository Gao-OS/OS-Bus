"""Standard XML policy probe: caller owns the explicitly supplied private bus."""
import json
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import sys
import time

from channel import Actor
from packaged_policy_actor import ALLOWED, DENIED, OBSERVER, PROTECTED

ROWS = ['call-nil-denied', 'call-interface-denied', 'call-allowed',
        'signal-interface-denied', 'signal-allowed'] + [
    owner + '-' + kind + '-' + request
    for owner in ('ordinary', 'observer')
    for kind in ('return', 'error')
    for request in ('requested', 'unsolicited')
] + ['protected-destination-denied']
BASE = Path('/run/osbus-p08')
DISK_EVIDENCE = Path('/var/lib/osbus-p08-evidence')
PROBE_SECONDS = 60


def remaining(deadline):
    seconds = deadline - time.monotonic()
    assert seconds > 0, 'policy probe deadline'
    return seconds


def private_path(path):
    path = Path(path)
    assert path.is_absolute() and '..' not in path.parts, 'private absolute path required'
    assert path.resolve().is_relative_to(BASE), 'explicit private path required'
    return path


def validate_evidence_destination(path, link_target, resolved, root_uid):
    path, resolved = Path(path), Path(resolved)
    assert path.is_absolute() and '..' not in path.parts
    assert path.is_relative_to(BASE/'evidence'), 'fixed evidence alias required'
    assert str(link_target) == str(DISK_EVIDENCE) and root_uid == 0, 'owned disk evidence required'
    assert resolved.is_absolute() and '..' not in resolved.parts
    assert resolved.is_relative_to(DISK_EVIDENCE), 'evidence symlink escaped disk subtree'
    return path


def evidence_path(path):
    alias = BASE/'evidence'
    assert alias.is_symlink(), 'fixed disk-backed evidence symlink required'
    assert not DISK_EVIDENCE.is_symlink() and DISK_EVIDENCE.resolve() == DISK_EVIDENCE
    info = DISK_EVIDENCE.stat()
    assert stat.S_ISDIR(info.st_mode), 'disk evidence directory required'
    return validate_evidence_destination(path, os.readlink(alias), Path(path).resolve(), info.st_uid)


def validate_identity(record, uid):
    assert isinstance(record, dict)
    assert type(record['pid']) is int and record['pid'] > 0
    assert record['uid'] == record['broker_uid'] == uid
    assert type(record['broker_pid']) is int and record['broker_pid'] == record['pid']
    assert record['gid'] == 100 and record['groups'] == [100]
    assert isinstance(record['name'], str) and re.fullmatch(r':[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+', record['name'])


def check_delivery(messages, expected, kind, serial, sender, destination, interface, reply_serial=None):
    if kind in (2, 3):
        assert not any(item['type'] == 3 and item['fields'].get('5') == reply_serial and
            item['fields'].get('7') == 'org.freedesktop.DBus' and
            item['fields'].get('4') == 'org.freedesktop.DBus.Error.NoReply'
            for item in messages), 'requested reply timed out before policy decision'
    # Bind even negative decisions to this exact source serial; wrong envelope
    # data cannot turn an observed delivery into a successful no-delivery row.
    matching = [item for item in messages if item['serial'] == serial and
                item['fields'].get('7') != 'org.freedesktop.DBus']
    assert len(matching) == int(expected), ('policy delivery count', expected, matching)
    for message in matching:
        fields = message['fields']
        assert message['type'] == kind and fields.get('6') == destination and fields.get('7') == sender
        assert message['body_hex'] == '' and fields.get('8', '') == ''
        if kind in (1, 4):
            assert fields.get('1') == '/foundation' and fields.get('3') == 'Probe'
            assert fields.get('2') == interface
        else:
            assert fields.get('5') == reply_serial
            if kind == 3:
                assert fields.get('4') == 'org.foundation.Expected'


def check_access_denied(messages, serial, caller):
    replies = [item for item in messages if item['fields'].get('5') == serial]
    assert len(replies) == 1, ('denied call lacks matching broker error', replies)
    error = replies[0]
    assert error['type'] == 3 and error['fields'].get('7') == 'org.freedesktop.DBus'
    assert error['fields'].get('6') == caller
    assert error['fields'].get('4') == 'org.freedesktop.DBus.Error.AccessDenied', error


def observe_reply(request, target, prior_messages, reply, source_name, target_name, expected):
    command = dict(op='observe', negative=not expected)
    if expected:
        command['expect_serial'] = reply['serial']
        if any(item['serial'] == reply['serial'] and
               item['fields'].get('7') != 'org.freedesktop.DBus' for item in prior_messages):
            command['prior_serial'] = reply['serial']
    received = request(target, **command)
    assert received['barriers'] == 2, 'both reply observation barriers required'
    # A fast reply may precede the caller's send barrier. Keep both raw receipts
    # and count every frame, including duplicates and early negative deliveries.
    check_delivery(prior_messages + received['messages'], expected, reply['kind'],
                   reply['serial'], source_name, target_name, None, reply['reply_serial'])
    return dict(received=received, prior_received=prior_messages)


def accounting(rows):
    statuses = [row['status'] for row in rows]
    assert set(statuses) <= {'passed', 'failed', 'blocked', 'skipped'}
    return dict(selected=len(ROWS), executed=statuses.count('passed')+statuses.count('failed'),
                passed=statuses.count('passed'), failed=statuses.count('failed'),
                blocked=statuses.count('blocked'), skipped=statuses.count('skipped'))


def validate_complete(rows, counts):
    assert [row['id'] for row in rows] == ROWS, 'required policy rows omitted/duplicated'
    assert counts == dict(selected=14, executed=14, passed=14, failed=0, blocked=0, skipped=0), counts
    assert counts == accounting(rows)


def probe(socket_path, evidence_dir, *, fixture_binding=None):
    started = time.monotonic()
    deadline = started + PROBE_SECONDS
    assert Path('/etc/osbus-security-guest').is_file() and os.getuid() == 0, 'root disposable VM required'
    socket_path, evidence_dir = private_path(socket_path), evidence_path(evidence_dir)
    assert stat.S_ISSOCK(socket_path.stat().st_mode), 'private socket required'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    assert not (evidence_dir/'policy-probe.json').exists(), 'fresh probe evidence required'
    assert not any((evidence_dir/(user+'.raw')).exists() for user in ['foundationA', 'foundationB'])
    actors, identities, shutdown = [], {}, []
    rows = [{'id': name, 'status': 'blocked', 'reason': 'not executed'} for name in ROWS]
    result = dict(socket=str(socket_path), rows=rows, identities=identities, shutdown=shutdown,
                  budget_seconds=PROBE_SECONDS, graceful_shutdown_in_budget=True,
                  emergency_shutdown_seconds_per_wrapper=6)
    if fixture_binding is not None:
        result['fixture_binding'] = fixture_binding
        result.update(fixture_binding)
    active = None
    def request(actor, **command):
        remaining(deadline)
        actor.begin(**command)
        envelope = actor.read(timeout=min(remaining(deadline), 5))
        assert envelope['ok'] is True, envelope
        remaining(deadline)
        return envelope['result']
    try:
        for user, uid in [('foundationA', 1100), ('foundationB', 1101)]:
            account = pwd.getpwnam(user)
            assert account.pw_uid == uid and account.pw_gid == 100
            command = ['runuser', '-u', user, '--', 'python3', '-B',
                       str(Path(__file__).with_name('packaged_policy_actor.py')), str(socket_path)]
            actor = Actor(command, evidence_dir/(user+'.raw'))
            actors.append(actor)
            envelope = actor.read(timeout=min(remaining(deadline), 5))
            assert envelope['ok'] is True, envelope
            identity = envelope['result']
            validate_identity(identity, uid)
            status = dict(line.split(':', 1) for line in Path('/proc', str(identity['pid']), 'status').read_text().splitlines() if ':' in line)
            assert [int(value) for value in status['Uid'].split()] == [uid]*4
            assert [int(value) for value in status['Gid'].split()] == [100]*4
            assert [int(value) for value in status['Groups'].split()] == [100]
            identities[user] = identity
        source, target = actors
        source_name, target_name = identities['foundationA']['name'], identities['foundationB']['name']
        assert source_name != target_name

        def transfer(sender, recipient, kind, interface, expected, reply_serial=None):
            sent = request(sender, op='send', kind=kind, destination=target_name if recipient is target else source_name,
                                  interface=interface, reply_serial=reply_serial)
            received = request(recipient, op='observe', negative=not expected,
                               **({'expect_serial': sent['serial']} if expected else {}))
            if kind in (1, 2) and not expected:
                check_access_denied(sent['messages'], sent['serial'], source_name if sender is source else target_name)
            check_delivery(received['messages'], expected, kind, sent['serial'],
                           source_name if sender is source else target_name,
                           target_name if recipient is target else source_name, interface, reply_serial)
            assert received['barriers'] == 2
            return {'sent': sent, 'received': received, 'reply_serial': reply_serial}

        for index, (kind, interface, expected) in enumerate([
                (1, None, False), (1, DENIED, False), (1, ALLOWED, True),
                (4, DENIED, False), (4, ALLOWED, True)]):
            active = index
            rows[index] = dict(id=ROWS[index], status='failed')
            evidence = transfer(source, target, kind, interface, expected)
            rows[index] = dict(id=ROWS[index], status='passed', **evidence)
        index = 5
        for observer in [False, True]:
            if observer:
                result['observer_ownership'] = request(source, op='own', name=OBSERVER)
            for kind in [2, 3]:
                for requested in [True, False]:
                    active = index
                    rows[index] = dict(id=ROWS[index], status='failed')
                    if requested:
                        assert request(source, op='arm_reply', kind=kind) == {'armed': kind}
                        invocation = transfer(target, source, 1, ALLOWED, True)
                        reply_serial = invocation['sent']['serial']
                        replies = invocation['received']['responses']
                        assert len(replies) == 1 and replies[0]['kind'] == kind
                        assert replies[0]['reply_serial'] == reply_serial and replies[0]['destination'] == target_name
                        latency_ms = (replies[0]['sent_at']-invocation['sent']['sent_at'])*1000
                        assert 0 <= latency_ms < 100, ('frozen reply timeout exceeded', latency_ms)
                        observation = observe_reply(request, target, invocation['sent']['messages'],
                                                    replies[0], source_name, target_name,
                                                    not(observer and kind == 2))
                        if observer and kind == 2:
                            check_access_denied(invocation['received']['messages'], replies[0]['serial'], source_name)
                        evidence = {'sent': replies[0], **observation, 'reply_serial': reply_serial,
                                    'reply_latency_ms': latency_ms}
                    else:
                        invocation, reply_serial = None, 1000000 + index
                        evidence = transfer(source, target, kind, None, not(observer and kind == 2), reply_serial)
                    rows[index] = dict(id=ROWS[index], status='passed', requested=requested,
                                       invocation=invocation, **evidence)
                    index += 1
        active = 13
        rows[13] = dict(id=ROWS[13], status='failed')
        result['protected_ownership'] = request(target, op='own', name=PROTECTED)
        evidence = transfer(source, target, 1, ALLOWED, False)
        rows[13] = dict(id=ROWS[13], status='passed', **evidence)
    except Exception as error:
        result['error'] = repr(error)
        if active is not None and rows[active]['status'] == 'failed':
            rows[active]['reason'] = repr(error)
    finally:
        for actor in reversed(actors):
            try:
                stop_started = time.monotonic()
                stopped = actor.stop(grace=min(1, max(deadline-time.monotonic(), 0)))
                stopped['wall_seconds'] = time.monotonic()-stop_started
                shutdown.append(stopped)
                assert stopped['method'] == 'eof' and stopped['returncode'] == 0, stopped
            except Exception as error:
                result['cleanup_error'] = repr(error)
        if time.monotonic() >= deadline:
            result['cleanup_error'] = 'policy probe deadline includes graceful shutdown'
        result['wall_seconds'] = time.monotonic()-started
        result['counts'] = accounting(rows)
        result['status'] = 'failed' if result.get('error') or result.get('cleanup_error') else 'passed'
        (evidence_dir/'policy-probe.json').write_text(json.dumps(result, indent=2)+'\n')
    validate_complete(rows, result['counts'])
    assert result['status'] == 'passed', result
    return result


def run_probe(socket_path, evidence_path, fixture_dir, backend_label):
    """Parent integration API with explicit fixture and backend source binding."""
    started = time.monotonic()
    fixture_dir = Path(fixture_dir).resolve()
    assert fixture_dir == Path(__file__).resolve().parent, 'loaded fixture directory mismatch'
    assert isinstance(backend_label, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', backend_label)
    names = ['packaged_wire_policy.xml', 'packaged_wire_policy_test.exs',
             'packaged_policy_actor.py', 'packaged_policy_probe.py', 'test_packaged_policy_probe.py',
             'transport.py', 'channel.py']
    inputs = {name: hashlib.sha256((fixture_dir/name).read_bytes()).hexdigest() for name in names}
    result = probe(socket_path, evidence_path, fixture_binding=dict(
        backend=backend_label, backend_label=backend_label, fixture_dir=str(fixture_dir), fixture_sha256=inputs))
    drift = inputs != {name: hashlib.sha256((fixture_dir/name).read_bytes()).hexdigest() for name in names}
    result['wrapper_wall_seconds'] = time.monotonic()-started
    if drift or result['wrapper_wall_seconds'] >= PROBE_SECONDS:
        result.update(status='failed', error='fixture drift or total policy wrapper deadline')
    (Path(evidence_path)/'policy-probe.json').write_text(json.dumps(result, indent=2)+'\n')
    assert result['status'] == 'passed', result
    return result


if __name__ == '__main__':
    assert len(sys.argv) in (3, 5)
    print(json.dumps(probe(sys.argv[1], sys.argv[2]) if len(sys.argv) == 3 else run_probe(*sys.argv[1:])))
