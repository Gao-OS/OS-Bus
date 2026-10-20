"""Offline evidence regressions; no sockets, actors or daemon execution."""
import copy
import hashlib
import struct
import unittest

from actor import (BEGIN, CASE_ORDER, OBSERVER, auth_command, role, send_signature,
                   validate_barrier, validate_cases, validate_ok)
from run import frame, validate_events


def receipt(kind, serial, destination, body, signature='s', **extra):
    fields = {5: serial, 6: destination, 7: 'org.freedesktop.DBus', 8: signature}
    fields.update({int(key): value for key, value in extra.items()})
    return dict(type=kind, serial=serial + 100, fields=fields, body=body)


def string(value):
    raw = value.encode()
    return (struct.pack('<I', len(raw)) + raw + b'\0').hex()


def registration(name, bus_id):
    acquired = receipt(4, 0, name, string(name))
    acquired['fields'].pop(5)
    acquired['fields'].update({1: '/org/freedesktop/DBus', 2: 'org.freedesktop.DBus', 3: 'NameAcquired'})
    return [receipt(2, 1, name, string(name)), acquired, receipt(2, 2, name, bus_id)]


def sample(identity, trace, started):
    return dict(connection=copy.deepcopy(identity), live=True, success=True, sole_writer=True,
                duplicated_connection=False, error=None, units='transmit allocation accounting',
                allocation=0, ioctl=21521, kernel='offline', send_trace=send_signature(trace),
                started=started, finished=started + 0.01)


def stamp_receipts(value):
    if isinstance(value, list):
        for item in value:
            stamp_receipts(item)
    elif isinstance(value, dict):
        if all(key in value for key in ('type', 'serial', 'fields', 'body')):
            signatures = {1: 'o', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 's', 8: 'g', 9: 'u'}
            # Deliberately preserve a wire order different from JSON's sorted keys.
            ordered = [(key, signatures[key], value['fields'][key])
                       for key in (6, 5, 7, 8, 1, 2, 3, 4, 9) if key in value['fields']]
            value['wire_hex'] = frame(value['type'], value['serial'], ordered,
                                      bytes.fromhex(value['body']), flags=1).hex()
        for item in value.values():
            if isinstance(item, (dict, list)):
                stamp_receipts(item)


def receives(name, data, began, auth=False):
    parts = [bytes([byte]) for byte in data] if auth else [data[:16], data[16:]]
    return [dict(direction='receive', role=name, hex=part.hex(), requested=len(part),
                 monotonic=began + index * .001, completed=began + index * .001 + .0001,
                 flags=0, controls=[]) for index, part in enumerate(parts)]


def evidence():
    # Synthetic validator input only; the runtime obtains UID/PID from the kernel.
    uid, pid, observer, bus_id = 1234, 123, ':1.0', string('a' * 32)
    auth, ok = auth_command(uid), b'OK ' + b'b' * 32 + b'\r\n'
    hello, get_id = b'h' * 128, b'g' * 128
    ready = dict(event='ready', observer=observer, owned=OBSERVER, bus_id=bus_id,
                 auth=auth.hex(), ok=ok.hex(), begin=BEGIN.hex(), hello=hello.hex(), get_id=get_id.hex(),
                 hello_sha256=hashlib.sha256(hello).hexdigest(), get_id_sha256=hashlib.sha256(get_id).hexdigest(),
                 registration=registration(observer, bus_id))
    owned = registration(OBSERVER, bus_id)[1]
    owned['fields'][6] = observer
    ready['ownership'] = [receipt(2, 3, observer, struct.pack('<I', 1).hex(), 'u'), owned]
    def health(started):
        return dict(started=started, finished=started + 0.05, observer=observer,
                    owned=OBSERVER, bus_id=bus_id,
                    receipts=[receipt(2, 10, observer, string(observer)), receipt(2, 11, observer, bus_id)])
    steps = [dict(phase=phase, allocation=value) for phase, value in [
        ('before_send', 0), ('unread', 9), ('partial_read', 9), ('complete_read', 0)]]
    events = [dict(event='identity', pid=pid, uid=uid, euid=uid, gid=100, egid=100, starttime_ticks=789),
              dict(event='kernel_control', passed=True, seconds=0.1, ioctl=21521, kernel='offline',
                   payload_sha256='abc', received_sha256='abc', steps=steps)]
    def connect(name, number):
        identity = dict(pid=pid, starttime_ticks=789, fd=7, inode=456 + number)
        events.append(dict(event='connection', role=name, connection=identity,
                           peer_credentials=[999, uid, 100], endpoint='/offline/bus'))
        return identity
    connect('observer', 0)
    events.append(dict(event='authenticated', role='observer', auth=ok.hex()))
    events.append(ready)
    for index, (family, split) in enumerate(CASE_ORDER, 1):
        name, source = role(family, split), ':1.' + str(index)
        identity = connect(name, index)
        expected = ([auth[:split], auth[split:], BEGIN + hello + get_id] if family == 'AUTH'
                    else [auth, BEGIN[:split], BEGIN[split:] + hello + get_id])
        trace = [dict(direction='send', role=name, hex=value.hex(), monotonic=1 + offset * .3,
                      completed=1.01 + offset * .3, outcome='sent') for offset, value in enumerate(expected)]
        prefix_count = 1 if family == 'AUTH' else 2
        prefix = trace[:prefix_count]
        began = prefix[-1]['completed']
        barrier = dict(started=began + .01, finished=began + .2,
                       first=sample(identity, prefix, began + .02),
                       second=sample(identity, prefix, began + .15), health=health(began + .05))
        events.extend(dict(event='wire', **row) for row in trace)
        events.append(dict(event='authenticated', role=name, auth=ok.hex()))
        gone = receipt(3, 25, observer, string('gone'))
        gone['fields'][4] = 'org.freedesktop.DBus.Error.NameHasNoOwner'
        events.append(dict(event='case', family=family, split=split, result='PASS', source=source,
                           connection=identity, prefix_trace=prefix, barrier=barrier,
                           receipts=registration(source, bus_id),
                           owner=receipt(2, 20, observer, string(source)), owner_serial=20,
                           uid=receipt(2, 21, observer, struct.pack('<I', uid).hex(), 'u'), uid_serial=21,
                           pid=receipt(2, 22, observer, struct.pack('<I', pid).hex(), 'u'), pid_serial=22,
                           after_close_health=health(2), ownership_disappearance=[gone],
                           disappearance_serials=[25], ownership_disappearance_seconds=.1,
                           source_pending=False, received_fds=0, internal_accounting='UNSUPPORTED',
                           source_parser_buffer='UNSUPPORTED'))
    events.append(dict(event='result', result='PASS', cases=30, auth_cases=24, begin_cases=6, connections=31,
                       observer=observer, owned=OBSERVER, bus_id=bus_id, final_health=health(3),
                       internal_accounting='UNSUPPORTED', source_parser_buffer='UNSUPPORTED',
                       native_frames_per_read='UNSUPPORTED'))
    stamp_receipts(events)
    case_rows = [row for row in events if row['event'] == 'case']
    streams = {}
    for case in case_rows:
        name = role(case['family'], case['split'])
        sends = [{key: value for key, value in row.items() if key != 'event'} for row in events
                 if row['event'] == 'wire' and row['role'] == name]
        raw_auth = receives(name, ok, 1.4 if case['family'] == 'AUTH' else 1.1, auth=True)
        rows = sends + raw_auth
        for index, row in enumerate(case['receipts']):
            rows += receives(name, bytes.fromhex(row['wire_hex']), 1.7 + index * .01)
        rows.sort(key=lambda row: row['monotonic'])
        case['prefix_trace'] = [row for row in rows if row['monotonic'] < case['barrier']['finished']]
        streams[name] = rows
    observer_rows = ready['registration'] + ready['ownership']
    for case in case_rows:
        observer_rows += (case['barrier']['health']['receipts'] + [case['owner'], case['uid'], case['pid']]
                          + case['after_close_health']['receipts'] + case['ownership_disappearance'])
    observer_rows += events[-1]['final_health']['receipts']
    observer_wire = [dict(direction='send', role='observer', hex=auth.hex(), monotonic=0,
                          completed=.001, outcome='sent')]
    observer_wire += receives('observer', ok, .01, auth=True)
    observer_wire.append(dict(direction='send', role='observer', hex=(BEGIN + hello + get_id).hex(),
                              monotonic=.1, completed=.101, outcome='sent'))
    for index, row in enumerate(observer_rows):
        observer_wire += receives('observer', bytes.fromhex(row['wire_hex']), 10 + index * .01)
    shaped, emitted = [], set()
    for row in events:
        if row['event'] == 'ready':
            shaped.extend(dict(event='wire', **item) for item in observer_wire)
        if row['event'] == 'wire':
            if row['role'] not in emitted:
                shaped.extend(dict(event='wire', **item) for item in streams[row['role']])
                emitted.add(row['role'])
        else:
            shaped.append(row)
    events = shaped
    return events


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.events = evidence()
        self.case = next(row for row in self.events if row['event'] == 'case')

    def rejected(self, events):
        with self.assertRaises((AssertionError, ValueError, KeyError)):
            validate_events(events)

    def test_accepts_exact_thirty_cases(self):
        self.assertEqual(validate_events(self.events)['cases'], 30)

    def test_requires_actual_uid_derived_auth25(self):
        self.assertEqual(auth_command(1234), b'\0AUTH EXTERNAL 31323334\r\n')
        for uid in (0, 123, 12345):
            with self.subTest(uid=uid), self.assertRaises(AssertionError):
                auth_command(uid)

    def test_rejects_missing_duplicate_reordered_wrong_family_and_failed(self):
        cases = [dict(family=family, split=split, result='PASS') for family, split in CASE_ORDER]
        validate_cases(cases)
        wrong_family = copy.deepcopy(cases)
        wrong_family[0]['family'] = 'BEGIN'
        failed = copy.deepcopy(cases)
        failed[-1]['result'] = 'FAIL'
        for wrong in (cases[:-1], cases + [cases[0]], [cases[1], cases[0]] + cases[2:],
                      [cases[0]] + cases[:-1], wrong_family, failed):
            with self.subTest(cases=wrong), self.assertRaises(AssertionError):
                validate_cases(wrong)

    def test_rejects_corrupt_wire_or_prefix_trace(self):
        for event, field, wrong in (('wire', 'hex', 'ff'), ('case', 'prefix_trace', [])):
            with self.subTest(event=event):
                events = copy.deepcopy(self.events)
                next(row for row in events if row['event'] == event)[field] = wrong
                self.rejected(events)

    def test_rejects_missing_auth_receives(self):
        events = [row for row in self.events if not (row['event'] == 'wire'
                  and row['role'] == 'source-AUTH-1' and row['direction'] == 'receive'
                  and row['monotonic'] < 1.6)]
        self.rejected(events)

    def test_rejects_corrupt_auth_and_missing_or_corrupt_registration_receives(self):
        for phase, action in (('auth', 'corrupt'), ('registration', 'missing'), ('registration', 'corrupt')):
            with self.subTest(phase=phase, action=action):
                events = copy.deepcopy(self.events)
                received = [row for row in events if row['event'] == 'wire'
                            and row['role'] == 'source-AUTH-1' and row['direction'] == 'receive'
                            and (row['monotonic'] < 1.6 if phase == 'auth' else row['monotonic'] >= 1.7)]
                if action == 'missing':
                    events.remove(received[0])
                else:
                    received[0]['hex'] = 'ff' + received[0]['hex'][2:]
                self.rejected(events)

    def test_rejects_missing_observer_receives(self):
        events = [row for row in self.events if not (row['event'] == 'wire'
                  and row['role'] == 'observer' and row['direction'] == 'receive')]
        self.rejected(events)

    def test_rejects_connection_family_collision_or_identity_mismatch(self):
        for field, wrong in (('role', 'source-BEGIN-1'), ('peer_credentials', [999, 9, 100])):
            events = copy.deepcopy(self.events)
            [row for row in events if row['event'] == 'connection'][1][field] = wrong
            self.rejected(events)
        events = copy.deepcopy(self.events)
        [row for row in events if row['event'] == 'connection'][1]['connection']['pid'] += 1
        self.rejected(events)

    def test_rejects_bad_ok_and_wrong_ok_guid(self):
        for reply in (b'OK bad\r\n', b'OK ' + b'z' * 32 + b'\r\n'):
            with self.assertRaises(AssertionError):
                validate_ok(reply)
        events = copy.deepcopy(self.events)
        [row for row in events if row['event'] == 'authenticated'][1]['auth'] = (b'OK ' + b'c' * 32 + b'\r\n').hex()
        self.rejected(events)

    def test_rejects_undrained_wrong_socket_changed_trace_or_health_order(self):
        for field, wrong in (('allocation', 1), ('live', False), ('connection', dict(pid=999)),
                             ('send_trace', dict(events=0))):
            events = copy.deepcopy(self.events)
            case = next(row for row in events if row['event'] == 'case')
            case['barrier']['second'][field] = wrong
            self.rejected(events)
        events = copy.deepcopy(self.events)
        next(row for row in events if row['event'] == 'case')['barrier']['health']['finished'] = 8
        self.rejected(events)

    def test_rejects_deadline_beyond_one_second_from_prefix(self):
        barrier = copy.deepcopy(self.case['barrier'])
        barrier['started'] += .9
        barrier['finished'] += .9
        for phase in ('first', 'second', 'health'):
            barrier[phase]['started'] += .9
            barrier[phase]['finished'] += .9
        with self.assertRaises(AssertionError):
            validate_barrier(barrier, self.case['connection'], self.case['prefix_trace'], 21521, 'offline')

    def test_rejects_wrong_uid_pid_reply_order_and_name_acquired(self):
        for field in ('uid', 'pid'):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')[field]['body'] = '00000000'
            self.rejected(events)
        for mutation in ('order', 'signal'):
            events = copy.deepcopy(self.events)
            rows = next(row for row in events if row['event'] == 'case')['receipts']
            if mutation == 'order':
                rows[0], rows[2] = rows[2], rows[0]
            else:
                rows[1]['fields'][2] = 'wrong.interface'
            self.rejected(events)

    def test_rejects_missing_disappearance_or_observer_health(self):
        for field, wrong in (('ownership_disappearance', []), ('source_pending', True), ('received_fds', 1)):
            events = copy.deepcopy(self.events)
            next(row for row in events if row['event'] == 'case')[field] = wrong
            self.rejected(events)
        events = copy.deepcopy(self.events)
        next(row for row in events if row['event'] == 'result')['final_health']['receipts'][1]['body'] = '00'
        self.rejected(events)


if __name__ == '__main__':
    unittest.main()
