"""Finite offline transcript controls, never runtime qualification evidence."""
import copy
import struct
import unittest
from unittest.mock import Mock, patch

import actor_overlay as actor
from vectors import CASES, CASE_ORDER, call, frame, receipt, wire_string
from wire_replay import (BUS, CONTROL_BYTES, decode_frames, verify_observer,
                         verify_target, verify_terminal)

SOURCE = ':1.41'
OBSERVER = ':1.7'
OWNER = 'org.foundation.Observer'
BUS_ID = '0123456789abcdef' * 2


def encoded_message(kind, serial, fields, signature, values):
    """Synthetic fixture encoder, independent of replay's decoder."""
    def value(buffer, signature, item):
        if signature == 'g':
            raw = item.encode()
            buffer.extend(bytes([len(raw)]) + raw + b'\0')
        else:
            buffer.extend(bytes((-len(buffer)) % 4))
            if signature in ('s', 'o'):
                raw = item.encode()
                buffer.extend(struct.pack('<I', len(raw)) + raw + b'\0')
            else:
                assert signature == 'u'
                buffer.extend(struct.pack('<I', item))

    headers = bytearray()
    if signature:
        fields = fields + [(8, 'g', signature)]
    for code, field_kind, item in fields:
        headers.extend(bytes((-len(headers)) % 8))
        headers.append(code)
        value(headers, 'g', field_kind)
        value(headers, field_kind, item)
    body = bytearray()
    for field_kind, item in zip(signature, values, strict=True):
        value(body, field_kind, item)
    size = len(headers)
    headers.extend(bytes((-size) % 8))
    return struct.pack('<BBBBIII', ord('l'), kind, 0, 1, len(body), serial, size) + headers + body


def ordinary_reply(serial, replied_to, text, error=None, destination=SOURCE):
    fields = [(5, 'u', replied_to), (6, 's', destination), (7, 's', BUS)]
    if error:
        fields.insert(0, (4, 's', error))
    kind = 3 if error else 2
    raw = encoded_message(kind, serial, fields, 's', [text])
    parsed = dict(type=kind, serial=serial, reply_serial=replied_to, error=error,
                  sender=BUS, interface=None, member=None, body=[text])
    return raw, parsed


def health_pair(serial, name=SOURCE):
    first, one = ordinary_reply(90, serial, name, destination=name)
    second, two = ordinary_reply(91, serial + 1, BUS_ID, destination=name)
    return first + second, [one, two]


def response(writes, raw, result, budget=3000):
    wire = [dict(direction='send', **receipt(data), sent=True, elapsed_ms=i + 1)
            for i, data in enumerate(writes)]
    if raw is not None:
        wire.append(dict(direction='receive', hex=raw.hex(), flags=0,
                         ancillary_count=0, elapsed_ms=len(wire) + 1))
    return dict(ok=True, result=result, wire=wire, elapsed_ms=10, budget_ms=budget)


def target_response(case):
    metadata = CASES[case]
    serial = metadata['serial']
    result = dict(case=case, frame=receipt(frame(case)), serial=serial,
                  source_socket_open=True, buffered_hex='', pending_messages=0)
    writes = [frame(case)]
    if metadata['oracle'] == 'close':
        result['disposition'] = 'sent-awaiting-controller'
        raw = None
    else:
        writes += [call('GetNameOwner', serial + 1, 's', wire_string(SOURCE)), call('GetId', serial + 2)]
        raw, result['source_health'] = health_pair(serial + 1)
        if metadata['oracle'] == 'invalid_args':
            result['disposition'] = 'invalid-args'
            error, result['error'] = ordinary_reply(89, serial, 'Invalid arguments', BUS + '.Error.InvalidArgs')
            raw = error + raw
        else:
            result['disposition'] = 'signal-sent'
    return response(writes, raw, result)


def observer_response(positive=False):
    raw, health = health_pair(10, OBSERVER)
    signal = None
    if positive:
        fields = [(1, 'o', '/probe'), (2, 's', 'org.foundation.Probe'),
                  (3, 's', 'Changed'), (7, 's', SOURCE)]
        raw = encoded_message(4, 3, fields, 's', ['/probe']) + raw
        signal = dict(type=4, serial=3, reply_serial=None, error=None,
                      sender=SOURCE, interface='org.foundation.Probe', member='Changed', body=['/probe'])
    value = dict(signal=signal, health=health, bus_id=BUS_ID,
                 observer_health_ms=5, buffered_hex='', pending_messages=0)
    writes = [call('GetNameOwner', 10, 's', wire_string(OWNER)), call('GetId', 11)]
    return response(writes, raw, value, 1000)


class CompactReplayTest(unittest.TestCase):
    def test_actual_mocked_actor_writes_and_receives_feed_independent_replay(self):
        for case in ('collection', 'match_string'):
            with self.subTest(case=case):
                scripted = []
                if case == 'collection':
                    scripted.append(ordinary_reply(89, 3, 'Invalid arguments', BUS + '.Error.InvalidArgs'))
                scripted.append(ordinary_reply(90, 4, SOURCE))
                scripted.append(ordinary_reply(91, 5, BUS_ID))
                raw = Mock()
                raw.fileno.return_value = 7
                raw.recvmsg.side_effect = [(data, [], 0, None) for data, _ in scripted]
                trace = []
                clock = dict(origin=10, deadline=13)

                class ScriptedClient:
                    def __init__(self, path):
                        self.socket = actor.RecordedSocket(raw, trace, clock)
                        self.buffer = b''
                        self.pending = []
                        self.serial = 2
                        self.unique = SOURCE
                        self.bus_id = BUS_ID
                        self.script = list(scripted)

                    def message(self):
                        data, parsed = self.script.pop(0)
                        self_data = self.socket.recv(len(data))
                        assert self_data == data
                        return parsed

                client = actor.client_type(ScriptedClient, trace, clock)('pure-control')
                with patch.object(actor.time, 'monotonic', return_value=10.1), \
                        patch.object(actor.select, 'select', return_value=([], [], [])):
                    result = client.command(dict(op='target', case=case))
                value = dict(ok=True, result=result, wire=trace, elapsed_ms=200, budget_ms=3000)
                verified = verify_target(case, value, SOURCE, BUS_ID)
                self.assertEqual(verified['writes'], 3)
                self.assertEqual(client.script, [])
                self.assertEqual(raw.sendall.call_count, 3)
                self.assertIs(verified['runtime_qualification'], False)

    def test_all_retained_target_shapes_replay_without_qualification(self):
        for case in CASE_ORDER:
            with self.subTest(case=case):
                result = verify_target(case, target_response(case), SOURCE, BUS_ID)
                self.assertIs(result['runtime_qualification'], False)
                self.assertEqual(result['received_messages'],
                                 0 if CASES[case]['oracle'] == 'close' else
                                 3 if CASES[case]['oracle'] == 'invalid_args' else 2)

    def test_large_input_is_bound_by_compact_actual_write_receipt(self):
        value = target_response('collection')
        self.assertEqual(value['wire'][0]['bytes'], 1_048_576)
        self.assertNotIn('hex', value['wire'][0])
        import json
        self.assertLess(len(json.dumps(value).encode()), 8192)
        verify_target('collection', value, SOURCE, BUS_ID)
        value['wire'][0]['sha256'] = '0' * 64
        value['result']['frame']['sha256'] = '0' * 64
        with self.assertRaises(AssertionError):
            verify_target('collection', value, SOURCE, BUS_ID)

    def test_wrong_or_duplicate_actual_write_is_rejected(self):
        for mutation in ('missing', 'duplicate', 'failed', 'wrong_size', 'full_hex'):
            with self.subTest(mutation=mutation):
                value = target_response('variant64')
                if mutation == 'missing':
                    value['wire'].pop(0)
                elif mutation == 'duplicate':
                    value['wire'].insert(0, copy.deepcopy(value['wire'][0]))
                elif mutation == 'failed':
                    value['wire'][0]['sent'] = False
                elif mutation == 'wrong_size':
                    value['wire'][0]['bytes'] -= 1
                else:
                    value['wire'][0]['hex'] = frame('variant64').hex()
                with self.assertRaises(AssertionError):
                    verify_target('variant64', value, SOURCE, BUS_ID)

    def test_reply_order_and_claims_must_equal_raw_stream(self):
        for mutation in ('order', 'claim', 'missing', 'extra', 'destination'):
            with self.subTest(mutation=mutation):
                value = target_response('struct32')
                serial = CASES['struct32']['serial']
                error, _ = ordinary_reply(89, serial, 'Invalid arguments', BUS + '.Error.InvalidArgs')
                health, _ = health_pair(serial + 1)
                if mutation == 'order':
                    value['wire'][-1]['hex'] = (health + error).hex()
                elif mutation == 'claim':
                    value['result']['error']['body'] = ['forged parsed result']
                elif mutation == 'missing':
                    value['wire'][-1]['hex'] = error.hex()
                elif mutation == 'extra':
                    value['wire'][-1]['hex'] += error.hex()
                else:
                    bad, _ = ordinary_reply(89, serial, 'Invalid arguments', BUS + '.Error.InvalidArgs', ':1.999')
                    value['wire'][-1]['hex'] = (bad + health).hex()
                with self.assertRaises(AssertionError):
                    verify_target('struct32', value, SOURCE, BUS_ID)

    def test_received_ancillary_or_flags_cannot_be_discarded(self):
        for key in ('flags', 'ancillary_count'):
            value = target_response('collection')
            value['wire'][-1][key] = 1
            with self.assertRaises(AssertionError):
                verify_target('collection', value, SOURCE, BUS_ID)

    def test_fixed_deadlines_and_control_ceiling_are_not_relaxed(self):
        for mutation in ('budget', 'late', 'nan', 'boolean', 'nonmonotonic', 'control'):
            with self.subTest(mutation=mutation):
                value = target_response('array32')
                if mutation == 'budget':
                    value['budget_ms'] = 4000
                elif mutation == 'late':
                    value['elapsed_ms'] = 3001
                elif mutation == 'nan':
                    value['elapsed_ms'] = float('nan')
                elif mutation == 'boolean':
                    value['wire'][0]['bytes'] = True
                elif mutation == 'nonmonotonic':
                    value['wire'][-1]['elapsed_ms'] = 0
                else:
                    value['unexpected_large_control'] = 'x' * CONTROL_BYTES
                with self.assertRaises(AssertionError):
                    verify_target('array32', value, SOURCE, BUS_ID)

    def test_terminal_token_does_not_establish_controller_proof(self):
        value = response([], b'', dict(case='prefix', authorization='observed-down-32',
            disposition='automatic-eof', source_socket_open=True, terminal_hex='',
            eof_ms=2, buffered_hex='', pending_messages=0))
        result = verify_terminal('prefix', value, 'observed-down-32')
        self.assertIs(result['controller_proof_required'], True)
        self.assertIs(result['runtime_qualification'], False)
        with self.assertRaises(AssertionError):
            verify_terminal('prefix', value, 'different-observation')
        value['wire'][0]['hex'] = '00'
        with self.assertRaises(AssertionError):
            verify_terminal('prefix', value, 'observed-down-32')

    def test_terminal_target_cannot_read_before_authorization(self):
        value = target_response('variant65')
        value['wire'].append(dict(direction='receive', hex='', flags=0,
                                  ancillary_count=0, elapsed_ms=2))
        # Empty bytes alone do not distinguish an early read. Require no
        # receive event at the send-only stage.
        with self.assertRaises(AssertionError):
            verify_target('variant65', value, SOURCE, BUS_ID)

    def test_observer_positive_then_nonmatch_has_exact_ordered_delivery(self):
        positive = observer_response(True)
        result = verify_observer(positive, OWNER, OBSERVER, BUS_ID, 10, SOURCE)
        self.assertEqual(result['received_messages'], 3)
        negative = observer_response(False)
        self.assertEqual(verify_observer(negative, OWNER, OBSERVER, BUS_ID, 10)['received_messages'], 2)
        with self.assertRaises(AssertionError):
            verify_observer(positive, OWNER, OBSERVER, BUS_ID, 10)
        with self.assertRaises(AssertionError):
            verify_observer(negative, OWNER, OBSERVER, BUS_ID, 10, SOURCE)

    def test_replay_rejects_truncated_or_trailing_wire_bytes(self):
        raw, parsed = ordinary_reply(90, 4, SOURCE)
        self.assertEqual(decode_frames(raw)[0]['message'], parsed)
        for bad in (raw[:-1], raw + b'\0'):
            with self.assertRaises(AssertionError):
                decode_frames(bad)


if __name__ == '__main__':
    unittest.main()
