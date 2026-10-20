"""Offline GetId evidence regressions; no sockets, actors or daemon execution."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

from actor import (BEGIN, OBSERVER, auth_command, role, send_signature,
                   validate_barrier, validate_cases)
from run import frame, validate_events

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'apps/gao_bus/test/fixtures'))
from peer_get_id_split_boundaries_actor import GET_ID, GET_ID_SUCCESSOR, HELLO


def string(value):
    raw = value.encode()
    return (struct.pack('<I', len(raw)) + raw + b'\0').hex()


def receipt(kind, serial, destination, body, signature='s', extra=None):
    fields = {6: destination, 7: 'org.freedesktop.DBus', 8: signature}
    if kind != 4:
        fields[5] = serial
    fields.update(extra or {})
    signatures = {1: 'o', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 's', 8: 'g', 9: 'u'}
    # Exercise actual wire ordering independent of JSON's sorted dictionary keys.
    ordered = [(key, signatures[key], fields[key])
               for key in (6, 5, 7, 8, 1, 2, 3, 4, 9) if key in fields]
    raw = frame(kind, serial + 100, ordered, bytes.fromhex(body), flags=1)
    return dict(type=kind, serial=serial + 100, fields=fields, body=body, wire_hex=raw.hex())


def acquired(name, destination):
    return receipt(4, 0, destination, string(name), extra={
        1: '/org/freedesktop/DBus', 2: 'org.freedesktop.DBus', 3: 'NameAcquired'})


def sample(identity, trace, started):
    return dict(connection=copy.deepcopy(identity), live=True, success=True, sole_writer=True,
                duplicated_connection=False, error=None, units='transmit allocation accounting',
                allocation=0, ioctl=21521, kernel='offline', send_trace=send_signature(trace),
                started=started, finished=started + .01)


def send(log, name, data, started):
    log.append(dict(direction='send', role=name, hex=data.hex(), monotonic=started,
                    completed=started + .001, outcome='sent'))


def receive(log, name, data, started, auth=False):
    parts = [bytes([byte]) for byte in data] if auth else [data[:16], data[16:]]
    log.extend(dict(direction='receive', role=name, hex=part.hex(), requested=len(part),
                    monotonic=started + index * .001, completed=started + index * .001 + .0001,
                    flags=0, controls=[]) for index, part in enumerate(parts))


def evidence():
    # Synthetic validator identities only; runtime identities come from the kernel.
    uid, pid, observer, bus_id = 1234, 123, ':1.0', string('a' * 32)
    auth, ok = auth_command(uid), b'OK ' + b'b' * 32 + b'\r\n'
    steps = [dict(phase=phase, allocation=value) for phase, value in [
        ('before_send', 0), ('unread', 9), ('partial_read', 9), ('complete_read', 0)]]
    events = [dict(event='identity', pid=pid, uid=uid, euid=uid, gid=100, egid=100, starttime_ticks=789),
              dict(event='kernel_control', passed=True, seconds=.1, ioctl=21521, kernel='offline',
                   payload_sha256='abc', received_sha256='abc', steps=steps)]
    wire = []

    def connect(name, number):
        identity = dict(pid=pid, starttime_ticks=789, fd=7, inode=456 + number)
        events.append(dict(event='connection', role=name, connection=identity,
                           peer_credentials=[999, uid, 100], endpoint='/offline/bus'))
        events.append(dict(event='authenticated', role=name, auth=ok.hex()))
        return identity

    def observer_receives(rows, started):
        for index, row in enumerate(rows):
            receive(wire, 'observer', bytes.fromhex(row['wire_hex']), started + index * .01)

    def health(started, serial, source=None):
        rows = [receipt(2, serial, observer, string(observer)), receipt(2, serial + 1, observer, bus_id)]
        observer_receives(rows, started + .005)
        result = dict(started=started, finished=started + .05, observer=observer,
                      owned=OBSERVER, bus_id=bus_id, receipts=rows)
        if source is not None:
            owner = receipt(2, serial + 2, observer, string(source))
            result.update(source=source, source_owner=owner, source_owner_serial=serial + 2)
            observer_receives([owner], started + .03)
        return result

    connect('observer', 0)
    send(wire, 'observer', auth, 0)
    receive(wire, 'observer', ok, .01, auth=True)
    send(wire, 'observer', BEGIN + HELLO + GET_ID, .1)
    registration = [receipt(2, 1, observer, string(observer)), acquired(observer, observer),
                    receipt(2, 2, observer, bus_id)]
    ownership = [receipt(2, 3, observer, struct.pack('<I', 1).hex(), 'u'), acquired(OBSERVER, observer)]
    observer_receives(registration, .2)
    observer_receives(ownership, .3)
    events.append(dict(event='ready', observer=observer, owned=OBSERVER, bus_id=bus_id,
                       auth=auth.hex(), ok=ok.hex(), begin=BEGIN.hex(), hello=HELLO.hex(),
                       get_id=GET_ID.hex(), get_id_successor=GET_ID_SUCCESSOR.hex(),
                       hello_sha256=hashlib.sha256(HELLO).hexdigest(),
                       get_id_sha256=hashlib.sha256(GET_ID).hexdigest(),
                       registration=registration, ownership=ownership))
    for split in range(1, 128):
        name, source, base, serial = role(split), ':1.' + str(split), split * 2, 10 + split * 20
        identity = connect(name, split)
        trace = []
        send(trace, name, auth, base)
        receive(trace, name, ok, base + .01, auth=True)
        send(trace, name, BEGIN + HELLO, base + .1)
        registered = [receipt(2, 1, source, string(source)), acquired(source, source)]
        for index, row in enumerate(registered):
            receive(trace, name, bytes.fromhex(row['wire_hex']), base + .2 + index * .01)
        send(trace, name, GET_ID[:split], base + .3)
        prefix = list(trace)
        barrier = dict(started=base + .31, finished=base + .42,
                       first=sample(identity, prefix, base + .32), second=sample(identity, prefix, base + .4),
                       health=health(base + .34, serial, source))
        send(trace, name, GET_ID[split:] + GET_ID_SUCCESSOR, base + .5)
        replies = [receipt(2, 2, source, bus_id), receipt(2, 3, source, bus_id)]
        for index, row in enumerate(replies):
            receive(trace, name, bytes.fromhex(row['wire_hex']), base + .6 + index * .01)
        wire.extend(trace)
        owner = receipt(2, serial + 3, observer, string(source))
        user = receipt(2, serial + 4, observer, struct.pack('<I', uid).hex(), 'u')
        process = receipt(2, serial + 5, observer, struct.pack('<I', pid).hex(), 'u')
        observer_receives([owner, user, process], base + .65)
        after = health(base + .7, serial + 6)
        gone = receipt(3, serial + 8, observer, string('gone'), extra={
            4: 'org.freedesktop.DBus.Error.NameHasNoOwner'})
        observer_receives([gone], base + .8)
        events.append(dict(event='case', split=split, result='PASS', source=source, connection=identity,
                           registration=registered, receipts=replies, prefix_trace=prefix, barrier=barrier,
                           owner=owner, owner_serial=serial + 3, uid=user, uid_serial=serial + 4,
                           pid=process, pid_serial=serial + 5, after_close_health=after,
                           ownership_disappearance=[gone], disappearance_serials=[serial + 8],
                           ownership_disappearance_seconds=.1, source_pending=False, received_fds=0,
                           internal_accounting='UNSUPPORTED', source_parser_buffer='UNSUPPORTED'))
    final = health(300, 3000)
    wire.sort(key=lambda row: row['monotonic'])
    events.extend(dict(event='wire', **row) for row in wire)
    events.append(dict(event='result', result='PASS', cases=127, connections=128, observer=observer,
                       owned=OBSERVER, bus_id=bus_id, final_health=final, internal_accounting='UNSUPPORTED',
                       source_parser_buffer='UNSUPPORTED', native_frames_per_read='UNSUPPORTED'))
    return events


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.events = evidence()
        self.case = next(row for row in self.events if row['event'] == 'case')

    def rejected(self, events):
        with self.assertRaises((AssertionError, ValueError, KeyError)):
            validate_events(events)

    def test_accepts_exact_127_cases_and_json_field_order(self):
        self.assertEqual(validate_events(self.events)['cases'], 127)
        self.assertEqual(validate_events(json.loads(json.dumps(self.events, sort_keys=True)))['connections'], 128)

    def test_rejects_missing_duplicate_reordered_out_of_range_or_failed_cases(self):
        cases = [dict(split=split, result='PASS') for split in range(1, 128)]
        wrong_split, failed = copy.deepcopy(cases), copy.deepcopy(cases)
        wrong_split[0]['split'] = 0
        failed[-1]['result'] = 'FAIL'
        for wrong in (cases[:-1], cases + [cases[0]], [cases[1], cases[0]] + cases[2:],
                      [cases[0]] + cases[:-1], wrong_split, failed):
            with self.subTest(cases=wrong), self.assertRaises(AssertionError):
                validate_cases(wrong)

    def test_rejects_wrong_socket_undrained_or_changed_send_trace(self):
        for field, wrong in (('connection', dict(pid=999)), ('allocation', 1), ('live', False),
                             ('send_trace', dict(events=0))):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')['barrier']['second'][field] = wrong
            self.rejected(events)

    def test_rejects_late_barrier_and_health_outside_queue_samples(self):
        barrier = copy.deepcopy(self.case['barrier'])
        barrier['started'] += 1
        barrier['finished'] += 1
        for phase in ('first', 'second', 'health'):
            barrier[phase]['started'] += 1
            barrier[phase]['finished'] += 1
        with self.assertRaises(AssertionError):
            validate_barrier(barrier, self.case['connection'], self.case['prefix_trace'], 21521, 'offline')
        events = copy.deepcopy(self.events)
        next(row for row in events if row['event'] == 'case')['barrier']['health']['finished'] += 1
        self.rejected(events)

    def test_rejects_reordered_wrong_body_or_extra_target_reply(self):
        for mutation in ('order', 'body', 'extra'):
            events = copy.deepcopy(self.events)
            replies = next(row for row in events if row['event'] == 'case')['receipts']
            if mutation == 'order':
                replies.reverse()
            elif mutation == 'body':
                replies[0]['body'] = string('wrong-bus')
            else:
                replies.append(copy.deepcopy(replies[-1]))
            self.rejected(events)

    def test_rejects_wrong_registration_or_name_acquired(self):
        for index, field, wrong in ((0, 5, 2), (1, 3, 'wrong'), (1, 6, ':wrong')):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')['registration'][index]['fields'][field] = wrong
            self.rejected(events)

    def test_rejects_wrong_ownership_during_hold(self):
        for field, wrong in (('source', ':wrong'), ('source_owner_serial', 9999)):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')['barrier']['health'][field] = wrong
            self.rejected(events)
        events = copy.deepcopy(self.events)
        owner_receive = next(row for row in events if row['event'] == 'wire'
                             and row['role'] == 'observer' and row['direction'] == 'receive'
                             and 2.369 < row['monotonic'] < 2.371)
        owner_receive.update(monotonic=2.5, completed=2.501)
        self.rejected(events)

    def test_rejects_wrong_kernel_identity_or_credential_reply(self):
        for field in ('uid', 'pid'):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')[field]['body'] = '00000000'
            self.rejected(events)
        events = copy.deepcopy(self.events)
        [row for row in events if row['event'] == 'connection'][1]['peer_credentials'] = [999, 7, 100]
        self.rejected(events)

    def test_rejects_missing_or_corrupt_auth_registration_and_target_receives(self):
        for phase, lower, upper in (('auth', 2, 2.1), ('registration', 2.2, 2.3), ('target', 2.6, 2.7)):
            for mutation in ('missing', 'corrupt'):
                with self.subTest(phase=phase, mutation=mutation):
                    events = copy.deepcopy(self.events)
                    received = [row for row in events if row['event'] == 'wire'
                                and row['role'] == role(1) and row['direction'] == 'receive'
                                and lower <= row['monotonic'] < upper]
                    if mutation == 'missing':
                        events.remove(received[0])
                    else:
                        received[0]['hex'] = 'ff' + received[0]['hex'][2:]
                    self.rejected(events)

    def test_rejects_missing_or_corrupt_observer_receives(self):
        for mutation in ('missing', 'corrupt'):
            events = copy.deepcopy(self.events)
            received = [row for row in events if row['event'] == 'wire'
                        and row['role'] == 'observer' and row['direction'] == 'receive']
            if mutation == 'missing':
                events = [row for row in events if row not in received]
            else:
                received[-1]['hex'] = 'ff' + received[-1]['hex'][2:]
            self.rejected(events)

    def test_rejects_wrong_writes_exact_ok_and_successor(self):
        for event, field, wrong in (('wire', 'hex', 'ff'), ('authenticated', 'auth', '00'),
                                    ('ready', 'get_id_successor', GET_ID.hex())):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == event)[field] = wrong
            self.rejected(events)

    def test_rejects_pending_bytes_fds_missing_disappearance_and_stale_health(self):
        for field, wrong in (('source_pending', True), ('received_fds', 1), ('ownership_disappearance', [])):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')[field] = wrong
            self.rejected(events)
        events = copy.deepcopy(self.events)
        next(row for row in events if row['event'] == 'result')['final_health']['bus_id'] = '00'
        self.rejected(events)


if __name__ == '__main__':
    unittest.main()
