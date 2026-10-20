"""Recorded SEC-14 wire calls on the unchanged independent security client."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('method_matrix_independent_client', HERE.parent / 'vm_security/actor.py')
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)
BUS = original.BUS
packet = original.packet
MAX_FRAME = 1_048_599


def decode_frame(raw):
    assert type(raw) is bytes and 16 <= len(raw) <= MAX_FRAME
    assert raw[0] in (ord('l'), ord('B')) and raw[3] == 1
    endian = '<' if raw[0] == ord('l') else '>'
    body_size, serial, header_size = struct.unpack_from(endian + 'III', raw, 4)
    assert serial > 0 and body_size + header_size <= 1_048_576
    body_at = 16 + header_size + -header_size % 8
    assert len(raw) == body_at + body_size, 'incomplete/trailing frame'
    headers = raw[16:16 + header_size]
    assert raw[16 + header_size:body_at] == b'\0' * (-header_size % 8)
    fields, offset = {}, 0
    while offset < len(headers):
        aligned = offset + -offset % 8
        assert headers[offset:aligned] == b'\0' * (aligned - offset)
        offset = aligned
        assert offset <= len(headers)
        if offset == len(headers):
            break
        code = headers[offset]
        assert code in range(1, 10) and code not in fields, 'duplicate/unknown header field'
        kind, offset = original.decode_value(headers, offset + 1, 'g', endian)
        assert kind == {1: 'o', 2: 's', 3: 's', 4: 's', 5: 'u', 6: 's', 7: 's', 8: 'g', 9: 'u'}[code]
        fields[code], offset = original.decode_value(headers, offset, kind, endian)
        assert offset <= len(headers)
    payload = raw[body_at:]
    signature = fields.get(8, '')
    values, offset = [], 0
    for kind in (['v'] if signature == 'v' else original.signatures(signature)):
        if kind == 'v':
            assert offset < len(payload) and offset + payload[offset] + 2 <= len(payload), 'truncated variant signature'
            inner, offset = original.decode_value(payload, offset, 'g', endian)
            assert inner == 'as', 'Features must contain the actual string-array variant'
            assert offset + -offset % 4 + 4 <= len(payload), 'truncated variant array'
            value, offset = original.decode_value(payload, offset, inner, endian)
            values.append(dict(signature=inner, value=value))
        else:
            if kind == 'b':
                boolean_at = offset + -offset % 4
                assert boolean_at + 4 <= len(payload), 'truncated boolean'
                assert payload[offset:boolean_at] == b'\0' * (boolean_at - offset)
                assert struct.unpack_from(endian + 'I', payload, boolean_at)[0] in (0, 1), 'noncanonical boolean'
            value, offset = original.decode_value(payload, offset, kind, endian)
            values.append(value)
    assert offset == body_size, 'incomplete/trailing body'
    return dict(type=raw[1], flags=raw[2], serial=serial, reply_serial=fields.get(5),
        error=fields.get(4), sender=fields.get(7), destination=fields.get(6),
        interface=fields.get(2), path=fields.get(1), member=fields.get(3),
        signature=signature, body=values, frame_hex=raw.hex())


class Client(original.Client):
    def exact(self, size):
        value = super().exact(size)
        if self.recording is not None:
            self.recording.extend(value)
        return value

    def __init__(self, path):
        super().__init__(path)
        self.recording = None

    def message(self):
        self.recording = bytearray()
        try:
            prefix = self.exact(16)
            assert prefix[0] in (ord('l'), ord('B')) and prefix[3] == 1
            endian = '<' if prefix[0] == ord('l') else '>'
            body_size, _, header_size = struct.unpack_from(endian + 'III', prefix, 4)
            assert body_size + header_size <= 1_048_576
            self.exact(header_size + -header_size % 8)
            self.exact(body_size)
            return decode_frame(bytes(self.recording))
        finally:
            self.recording = None

    def command(self, request):
        if request['op'] != 'call':
            return super().command(request)
        self.serial += 1
        options = {key: value for key, value in request.items() if key != 'op'}
        frame = packet(self.serial, **options)
        assert len(frame) <= MAX_FRAME
        self.socket.sendall(frame)
        return dict(request_serial=self.serial, request_hex=frame.hex(), reply=self.reply(self.serial))


if __name__ == '__main__':
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert sys.argv[1] == '/run/osbus-security/method-matrix/bus'
    client = Client(sys.argv[1])
    print(json.dumps(dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid())), flush=True)
    try:
        for line in sys.stdin:
            try:
                result = client.command(json.loads(line))
                print(json.dumps(dict(ok=True, result=result)), flush=True)
            except Exception as error:
                print(json.dumps(dict(ok=False, error=repr(error))), flush=True)
    finally:
        if client.socket is not None:
            client.socket.close()
