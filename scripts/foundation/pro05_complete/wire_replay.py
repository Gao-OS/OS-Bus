"""Offline compact-write replay for the existing finite PRO05 inputs.

The finite reply decoder is adapted from the accepted PRO03 wire_replay.py.
This module launches nothing and produces no qualification receipts. In
particular, validating a terminal token does not prove controller DOWN/state
observations; the system runner must retain and bind those separately.
"""
import json
import math
import re
import struct

from vectors import CASES, call, frame, receipt, wire_string

BUS = 'org.freedesktop.DBus'
CONTROL_BYTES = 4_194_304
RECEIVE_BYTES = 65_536


def bounded(value, maximum):
    assert type(value) in (int, float) and math.isfinite(value)
    assert 0 <= value <= maximum


def decode_frames(raw):
    """Decode only ordinary replies/signals used by this finite fixture."""
    assert type(raw) is bytes and len(raw) <= RECEIVE_BYTES
    frames = []
    cursor = 0
    while cursor < len(raw):
        assert len(raw) - cursor >= 16
        prefix = raw[cursor:cursor + 16]
        assert prefix[0] in (ord('l'), ord('B')) and prefix[3] == 1
        assert prefix[1] in (2, 3, 4)
        endian = '<' if prefix[0] == ord('l') else '>'
        body_size, serial, header_size = struct.unpack_from(endian + 'III', prefix, 4)
        assert serial > 0 and body_size + header_size <= RECEIVE_BYTES
        body_at = cursor + 16 + header_size + (-header_size % 8)
        end = body_at + body_size
        assert end <= len(raw)
        header = raw[cursor + 16:cursor + 16 + header_size]
        assert raw[cursor + 16 + header_size:body_at] == bytes(-header_size % 8)

        def value(data, offset, kind):
            assert kind in ('g', 's', 'o', 'u', 'b', 'as')
            if kind == 'g':
                assert offset < len(data)
                size = data[offset]
                start = offset + 1
                assert start + size < len(data) and data[start + size] == 0
                return data[start:start + size].decode(), start + size + 1
            aligned = offset + (-offset % 4)
            assert data[offset:aligned] == bytes(aligned - offset)
            offset = aligned
            assert offset + 4 <= len(data)
            size = struct.unpack_from(endian + 'I', data, offset)[0]
            offset += 4
            if kind in ('u', 'b'):
                if kind == 'b':
                    assert size in (0, 1)
                return (bool(size) if kind == 'b' else size), offset
            if kind in ('s', 'o'):
                assert offset + size < len(data) and data[offset + size] == 0
                return data[offset:offset + size].decode(), offset + size + 1
            limit = offset + size
            assert limit <= len(data)
            items = []
            while offset < limit:
                item, offset = value(data, offset, 's')
                items.append(item)
            assert offset == limit
            return items, offset

        fields = {}
        field_types = {1: 'o', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 's', 8: 'g'}
        offset = 0
        while offset < len(header):
            aligned = offset + (-offset % 8)
            assert header[offset:aligned] == bytes(aligned - offset)
            offset = aligned
            assert offset < len(header)
            code = header[offset]
            assert code in field_types and code not in fields
            kind, offset = value(header, offset + 1, 'g')
            assert kind == field_types[code]
            fields[code], offset = value(header, offset, kind)
        signature = fields.get(8, '')
        kinds = re.findall(r'as|[soub]', signature)
        assert ''.join(kinds) == signature
        body = raw[body_at:end]
        values = []
        offset = 0
        for kind in kinds:
            item, offset = value(body, offset, kind)
            values.append(item)
        assert offset == len(body)
        message = dict(type=prefix[1], serial=serial, reply_serial=fields.get(5),
                       error=fields.get(4), sender=fields.get(7), interface=fields.get(2),
                       member=fields.get(3), body=values)
        if message['type'] in (2, 3):
            assert type(message['reply_serial']) is int and message['reply_serial'] > 0
            assert (message['error'] is None) == (message['type'] == 2)
            assert message['sender'] == BUS
        frames.append(dict(message=message, fields=fields))
        cursor = end
    assert cursor == len(raw)
    return frames


def verify_trace(response, expected_writes, budget_ms):
    """Bind compact successful writes, ordered receive bytes and fixed bounds."""
    assert response['ok'] is True and response['budget_ms'] == budget_ms
    bounded(response['elapsed_ms'], budget_ms)
    assert len(json.dumps(response).encode()) + 1 <= CONTROL_BYTES
    assert type(response['wire']) is list
    writes = []
    received = bytearray()
    previous = 0
    for event in response['wire']:
        bounded(event['elapsed_ms'], response['elapsed_ms'])
        assert previous <= event['elapsed_ms']
        previous = event['elapsed_ms']
        if event['direction'] == 'send':
            assert set(event) == {'direction', 'bytes', 'sha256', 'sent', 'elapsed_ms'}
            assert type(event['bytes']) is int and 0 < event['bytes'] <= 1_048_576
            assert type(event['sha256']) is str and re.fullmatch('[0-9a-f]{64}', event['sha256'])
            assert event['sent'] is True
            writes.append(dict(bytes=event['bytes'], sha256=event['sha256']))
        else:
            assert event['direction'] == 'receive'
            assert set(event) == {'direction', 'hex', 'flags', 'ancillary_count', 'elapsed_ms'}
            assert type(event['flags']) is type(event['ancillary_count']) is int
            assert event['flags'] == event['ancillary_count'] == 0
            assert type(event['hex']) is str and re.fullmatch('(?:[0-9a-f]{2})*', event['hex'])
            received.extend(bytes.fromhex(event['hex']))
            assert len(received) <= RECEIVE_BYTES
    assert writes == [receipt(data) for data in expected_writes]
    return bytes(received)


def health_writes(owner, serial):
    assert type(owner) is str and owner
    assert type(serial) is int and serial > 0
    return [call('GetNameOwner', serial, 's', wire_string(owner)), call('GetId', serial + 1)]


def verify_health(frames, source_name, bus_id, serial):
    assert len(frames) == 2
    for index, expected in enumerate(([source_name], [bus_id])):
        row = frames[index]
        message = row['message']
        assert message['type'] == 2 and message['reply_serial'] == serial + index
        assert message['sender'] == BUS and message['error'] is None
        assert message['body'] == expected
        assert row['fields'].get(6) == source_name and row['fields'].get(8) == 's'


def verify_target(case, response, source_name, bus_id):
    """Check a single actor target response; this is not a system-row oracle."""
    assert case in CASES
    metadata = CASES[case]
    value = response['result']
    assert value['case'] == case and value['frame'] == receipt(frame(case))
    assert value['serial'] == metadata['serial']
    assert value['source_socket_open'] is True
    assert value['buffered_hex'] == '' and type(value['pending_messages']) is int
    assert value['pending_messages'] == 0
    expected = [frame(case)]
    if metadata['oracle'] != 'close':
        expected += health_writes(source_name, metadata['serial'] + 1)
    raw = verify_trace(response, expected, metadata['request_ms'])
    frames = decode_frames(raw)
    if metadata['oracle'] == 'close':
        assert value['disposition'] == 'sent-awaiting-controller' and frames == []
        assert all(event['direction'] == 'send' for event in response['wire'])
    else:
        health = frames
        if metadata['oracle'] == 'invalid_args':
            assert value['disposition'] == 'invalid-args' and len(frames) == 3
            error, *health = frames
            assert error['message'] == value['error']
            assert error['message']['type'] == 3
            assert error['message']['error'] == BUS + '.Error.InvalidArgs'
            assert error['message']['reply_serial'] == metadata['serial']
            assert error['fields'].get(6) == source_name
            assert error['fields'].get(8) == 's'
            assert len(error['message']['body']) == 1 and type(error['message']['body'][0]) is str
        else:
            assert value['disposition'] == 'signal-sent'
        verify_health(health, source_name, bus_id, metadata['serial'] + 1)
        assert [row['message'] for row in health] == value['source_health']
    return dict(case=case, writes=len(expected), received_messages=len(frames),
                runtime_qualification=False)


def verify_terminal(case, response, authorization):
    assert case in CASES and CASES[case]['oracle'] == 'close'
    assert type(authorization) is str and authorization
    raw = verify_trace(response, [], CASES[case]['request_ms'])
    assert raw == b'' and len(response['wire']) == 1
    assert response['wire'][0]['direction'] == 'receive'
    value = response['result']
    assert value['case'] == case and value['authorization'] == authorization
    assert value['disposition'] == 'automatic-eof' and value['source_socket_open'] is True
    assert value['terminal_hex'] == value['buffered_hex'] == ''
    assert type(value['pending_messages']) is int and value['pending_messages'] == 0
    bounded(value['eof_ms'], response['elapsed_ms'])
    return dict(case=case, exact_eof=True, controller_proof_required=True,
                runtime_qualification=False)


def verify_observer(response, owner, observer_name, bus_id, serial, source_name=None):
    raw = verify_trace(response, health_writes(owner, serial), 1000)
    frames = decode_frames(raw)
    value = response['result']
    assert value['bus_id'] == bus_id and value['buffered_hex'] == ''
    assert type(value['pending_messages']) is int and value['pending_messages'] == 0
    bounded(value['observer_health_ms'], response['elapsed_ms'])
    health = frames
    if source_name is None:
        assert value['signal'] is None
    else:
        assert len(frames) == 3
        signal, *health = frames
        assert signal['message'] == value['signal']
        assert signal['message']['type'] == 4 and signal['message']['serial'] == 3
        assert signal['message']['sender'] == source_name
        assert signal['message']['interface'] == 'org.foundation.Probe'
        assert signal['message']['member'] == 'Changed' and signal['message']['body'] == ['/probe']
        assert signal['fields'] == {1: '/probe', 2: 'org.foundation.Probe',
                                    3: 'Changed', 7: source_name, 8: 's'}
    verify_health(health, observer_name, bus_id, serial)
    assert [row['message'] for row in health] == value['health']
    return dict(received_messages=len(frames), runtime_qualification=False)
