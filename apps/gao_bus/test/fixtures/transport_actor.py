"""Independent Linux D-Bus framing/SCM_RIGHTS actor; never uses a default bus."""
import array
import json
import os
import socket
import struct
import sys
import tempfile


def u32(value):
    return struct.pack("<I", value)


def padding(offset, alignment):
    return b"\0" * (-offset % alignment)


def string(value):
    data = value.encode()
    return u32(len(data)) + data + b"\0"


def frame(kind, serial, fields, body=b"", flags=0):
    header = b""
    for code, signature, value in fields:
        header += padding(len(header), 8) + bytes([code, 1]) + signature.encode() + b"\0"
        if signature in ("s", "o"):
            header += string(value)
        elif signature == "u":
            header += u32(value)
        elif signature == "g":
            header += bytes([len(value)]) + value.encode() + b"\0"
        else:
            raise AssertionError(signature)
    return (b"l" + bytes([kind, flags, 1]) + u32(len(body)) + u32(serial)
            + u32(len(header)) + header + padding(len(header), 8) + body)


def call(member, serial, signature="", body=b"", destination="org.freedesktop.DBus", flags=0):
    return frame(1, serial, [(1, "o", "/org/freedesktop/DBus"),
                             (2, "s", "org.freedesktop.DBus"), (3, "s", member),
                             (6, "s", destination), (8, "g", signature)], body, flags)


def signal(serial, destination=None, count=1, body=None, signature="h"):
    fields = [(1, "o", "/foundation"), (2, "s", "org.foundation.Transport"),
              (3, "s", "Resource"), (8, "g", signature)]
    if destination:
        fields.append((6, "s", destination))
    if count is not None:
        fields.append((9, "u", count))
    return frame(4, serial, fields, u32(0) if body is None else body)


def read_string(data, offset=0):
    size = struct.unpack_from("<I", data, offset)[0]
    return data[offset + 4:offset + 4 + size].decode()


def close_fds(fds):
    for fd in fds:
        os.close(fd)


class Client:
    def __init__(self, path, negotiate=True):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3)
        self.sock.connect(path)
        self.sock.sendall(b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode() + b"\r\n")
        assert self.line().startswith(b"OK ")
        if negotiate:
            self.sock.sendall(b"NEGOTIATE_UNIX_FD\r\n")
            assert self.line() == b"AGREE_UNIX_FD\r\n", "FD negotiation was not accepted"
        self.sock.sendall(b"BEGIN\r\n" + call("Hello", 1))
        reply = self.reply(1)
        assert reply["type"] == 2, reply
        self.name = read_string(reply["body"])
        self.barrier(2)

    def line(self):
        result = b""
        while not result.endswith(b"\r\n"):
            byte = self.sock.recv(1)
            assert byte, result
            result += byte
        return result

    def read(self, length, fds):
        result = b""
        while len(result) < length:
            data, controls, flags, _ = self.sock.recvmsg(length - len(result), socket.CMSG_SPACE(253 * 4))
            assert data and not flags & socket.MSG_CTRUNC, (len(result), length, flags)
            result += data
            for level, kind, rights in controls:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                received = array.array("i")
                received.frombytes(rights)
                fds.extend(received)
        return result

    def receive(self):
        fds = []
        try:
            prefix = self.read(16, fds)
            assert prefix[0] == ord("l")
            body_size, serial, header_size = struct.unpack_from("<III", prefix, 4)
            assert body_size + header_size < 2**21
            tail = self.read(header_size + (-header_size % 8) + body_size, fds)
            fields, offset = {}, 0
            while offset < header_size:
                offset += -offset % 8
                code, length = tail[offset:offset + 2]
                assert length == 1
                signature = chr(tail[offset + 2])
                offset += 4
                if signature in ("s", "o"):
                    size = struct.unpack_from("<I", tail, offset)[0]
                    fields[code] = tail[offset + 4:offset + 4 + size].decode()
                    offset += 5 + size
                elif signature == "u":
                    fields[code] = struct.unpack_from("<I", tail, offset)[0]
                    offset += 4
                elif signature == "g":
                    size = tail[offset]
                    fields[code] = tail[offset + 1:offset + 1 + size].decode()
                    offset += size + 2
                else:
                    raise AssertionError(signature)
            assert fields.get(9, 0) == len(fds), (fields, fds)
            return {"type": prefix[1], "serial": serial, "fields": fields,
                    "body": tail[header_size + (-header_size % 8):], "fds": fds}
        except BaseException:
            close_fds(fds)
            raise

    def reply(self, serial):
        while True:
            message = self.receive()
            if message["fields"].get(5) == serial:
                return message
            assert not message["fds"], message

    def barrier(self, serial):
        self.sock.sendall(call("ListNames", serial))
        assert self.reply(serial)["type"] == 2

    def send_fds(self, data, fds):
        count = self.sock.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
        assert count > 0
        self.sock.sendall(data[count:])

    def close(self):
        self.sock.close()


def pipe_payload(data):
    reader, writer = os.pipe()
    os.write(writer, data)
    os.close(writer)
    return reader


def resource_message(client, expected):
    message = client.receive()
    assert message["fields"].get(3) == "Resource", message
    assert len(message["fds"]) == 1, message
    fd = message["fds"][0]
    try:
        assert os.read(fd, 128) == expected
    finally:
        os.close(fd)
    return message


def checkpoint(event, **details):
    print(json.dumps({"event": event, **details}), flush=True)
    assert sys.stdin.readline().strip() == "continue"


def run(path, mode):
    clients = []
    def connect(negotiate=True):
        client = Client(path, negotiate)
        clients.append(client)
        return client
    try:
        source = connect()
        target = connect()
        if mode == "resources":
            pipe = pipe_payload(b"PIPE")
            with tempfile.TemporaryFile() as file:
                file.write(b"FILE")
                file.seek(0)
                first, second = socket.socketpair()
                try:
                    second.sendall(b"SOCKET")
                    source.send_fds(signal(3, target.name, 3, u32(0) + u32(1) + u32(2), "hhh"),
                                    [pipe, file.fileno(), first.fileno()])
                    message = target.receive()
                    assert message["body"] == u32(0) + u32(1) + u32(2)
                    assert len(message["fds"]) == 3
                    try:
                        assert [os.read(fd, 128) for fd in message["fds"]] == [b"PIPE", b"FILE", b"SOCKET"]
                    finally:
                        close_fds(message["fds"])
                finally:
                    first.close()
                    second.close()
                    os.close(pipe)
        elif mode == "fragments":
            sample = signal(3, target.name)
            for index, split in enumerate([0, 1, 15, 16, 17, len(sample) - 5, len(sample) - 1]):
                payload = ("fragment-%d" % split).encode()
                fd = pipe_payload(payload)
                data = signal(10 + index, target.name)
                try:
                    source.sock.sendall(data[:split])
                    source.send_fds(data[split:split + 1], [fd])
                    source.sock.sendall(data[split + 1:])
                finally:
                    os.close(fd)
                resource_message(target, payload)
        elif mode == "coalesced":
            for serial in range(10, 30):
                source.sock.sendall(signal(serial * 3, target.name, None, b"", ""))
                fd = pipe_payload(str(serial).encode())
                try:
                    source.send_fds(signal(serial * 3 + 1, target.name), [fd])
                    source.sock.sendall(signal(serial * 3 + 2, target.name, None, b"", ""))
                finally:
                    os.close(fd)
                before = target.receive()
                assert before["serial"] == serial * 3 and before["fds"] == []
                resource_message(target, str(serial).encode())
                after = target.receive()
                assert after["serial"] == serial * 3 + 2 and after["fds"] == []
        elif mode == "invalid":
            invalid = [(0, "h", u32(0), 1), (2, "h", u32(0), 1),
                       (1, "h", u32(1), 1), (1, "h", u32(0), 0),
                       (1, "ah", u32(4) + u32(1), 1),
                       (1, "v", b"\x01h\0\0" + u32(1), 1),
                       (1, "(h)", u32(1), 1)]
            for index, (advertised, signature, body, real) in enumerate(invalid):
                bad = connect()
                fd = pipe_payload(b"BAD")
                try:
                    data = signal(20 + index, target.name, advertised, body, signature)
                    if real:
                        bad.send_fds(data, [fd])
                    else:
                        bad.sock.sendall(data)
                    assert bad.sock.recv(1) == b"", "malformed FD frame was accepted"
                finally:
                    os.close(fd)
                    bad.close()
                target.barrier(30 + index)
        elif mode == "fanout":
            other = connect()
            rule = "type='signal',interface='org.foundation.Transport'"
            for recipient in [target, other]:
                recipient.sock.sendall(call("AddMatch", 3, "s", string(rule)))
                assert recipient.reply(3)["type"] == 2
            fd = os.memfd_create("foundation-fanout", os.MFD_CLOEXEC)
            os.write(fd, b"FANOUT")
            try:
                source.send_fds(signal(3), [fd])
            finally:
                os.close(fd)
            source.barrier(4)
            source.close()
            for recipient in [target, other]:
                message = recipient.receive()
                assert len(message["fds"]) == 1
                received = message["fds"][0]
                try:
                    assert os.pread(received, 6, 0) == b"FANOUT"
                finally:
                    os.close(received)
        elif mode == "fanout_stall":
            other = connect()
            rule = "type='signal',interface='org.foundation.Transport'"
            for recipient in [target, other]:
                recipient.sock.sendall(call("AddMatch", 3, "s", string(rule)))
                assert recipient.reply(3)["type"] == 2
            checkpoint("ready", source=source.name, target=target.name)
            payload = bytes(range(256)) * 768
            body = u32(0) + u32(len(payload)) + payload
            fd = os.memfd_create("foundation-fanout-held", os.MFD_CLOEXEC)
            os.write(fd, b"FANOUT")
            try:
                source.send_fds(signal(3, None, 1, body, "hay"), [fd])
            finally:
                os.close(fd)
            source.barrier(4)
            message = other.receive()
            assert message["body"] == body and len(message["fds"]) == 1
            try:
                assert os.pread(message["fds"][0], 6, 0) == b"FANOUT"
            finally:
                close_fds(message["fds"])
            other.barrier(5)
            checkpoint("queued")
            target.close()
            source.barrier(7)
            other.barrier(8)
            return {"scenario": mode, "result": "PASS"}
        elif mode == "unnegotiated":
            plain = connect(False)
            fd = pipe_payload(b"DO-NOT-DELIVER")
            fields = [(1, "o", "/foundation"), (2, "s", "org.foundation.Transport"),
                      (3, "s", "Resource"), (6, "s", plain.name), (8, "g", "h"), (9, "u", 1)]
            try:
                source.send_fds(frame(1, 3, fields, u32(0)), [fd])
            finally:
                os.close(fd)
            denied = source.reply(3)
            assert denied["type"] == 3 and denied["fields"][4] == "org.freedesktop.DBus.Error.NotSupported", denied
            plain.barrier(4)
        elif mode == "glib_return":
            fd = os.memfd_create("foundation-glib", os.MFD_CLOEXEC)
            os.write(fd, b"GLIB_FD")
            fields = [(1, "o", "/com/test/ExternalFixture"), (2, "s", "com.test.ExternalFixture"),
                      (3, "s", "ReadAndReturnFD"), (6, "s", "com.test.ExternalFixture"),
                      (8, "g", "h"), (9, "u", 1)]
            try:
                source.send_fds(frame(1, 3, fields, u32(0)), [fd])
            finally:
                os.close(fd)
            reply = source.reply(3)
            assert reply["type"] == 2 and reply["fields"][8] == "hs", reply
            assert read_string(reply["body"], 4) == "GLIB_FD"
            assert len(reply["fds"]) == 1
            try:
                assert os.pread(reply["fds"][0], 7, 0) == b"GLIB_FD"
            finally:
                close_fds(reply["fds"])
        elif mode in ("slow_write", "source_exit", "recipient_exit", "backpressure"):
            checkpoint("ready", source=source.name, target=target.name)
            payload = bytes(range(256)) * 768
            descriptor = pipe_payload(b"PARTIAL-WRITE")
            body = u32(0) + u32(len(payload)) + payload
            packet = signal(3, target.name, 1, body, "hay")
            if mode == "backpressure":
                packet = packet[:1] + bytes([1, 1]) + packet[3:]  # method call, no reply expected
            try:
                source.send_fds(packet, [descriptor])
            finally:
                os.close(descriptor)
            source.barrier(4)
            if mode == "backpressure":
                descriptor = pipe_payload(b"REJECTED-QUEUE")
                packet = signal(5, target.name, 1, body, "hay")
                packet = packet[:1] + bytes([1, 0]) + packet[3:]
                try:
                    source.send_fds(packet, [descriptor])
                finally:
                    os.close(descriptor)
                denied = source.reply(5)
                assert denied["type"] == 3 and denied["fields"][4] == "org.freedesktop.DBus.Error.LimitsExceeded", denied
                source.barrier(6)
            elif mode == "source_exit":
                source.close()
            checkpoint("queued")
            if mode == "recipient_exit":
                target.close()
                source.barrier(7)
                return {"scenario": mode, "result": "PASS"}
            message = target.receive()
            assert message["body"] == body and len(message["fds"]) == 1, "partial output corrupted stream or rights"
            try:
                assert os.read(message["fds"][0], 128) == b"PARTIAL-WRITE"
            finally:
                close_fds(message["fds"])
        else:
            raise AssertionError(mode)
        target.barrier(1000)
        return {"scenario": mode, "result": "PASS"}
    finally:
        for client in clients:
            client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 3 and os.path.isabs(sys.argv[1])
    print(json.dumps(run(sys.argv[1], sys.argv[2])))
