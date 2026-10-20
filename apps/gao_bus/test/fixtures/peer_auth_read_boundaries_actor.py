"""Real Peer auth/BEGIN splits and ancillary boundaries on one private bus."""
import json
import os
import signal as os_signal
import socket
import sys

from transport_actor import Client, call, frame, read_string, signal, string, u32


def emit(event, **values):
    print(json.dumps(dict(event=event, **values)), flush=True)


def command(expected):
    assert sys.stdin.readline().strip() == expected, expected


def inventory(pid):
    directory = "/proc/" + pid + "/fd"
    return {name: os.readlink(directory + "/" + name) for name in sorted(os.listdir(directory))}


def health(client, owned, bus_id, serial):
    client.sock.sendall(call("GetNameOwner", serial, "s", string(owned)))
    assert client.reply(serial)["body"] == string(client.name)
    client.sock.sendall(call("GetId", serial + 1))
    assert client.reply(serial + 1)["body"] == bus_id


def hello_with_fd():
    return frame(1, 1, [(1, "o", "/org/freedesktop/DBus"),
                        (2, "s", "org.freedesktop.DBus"), (3, "s", "Hello"),
                        (6, "s", "org.freedesktop.DBus"), (8, "g", ""), (9, "u", 1)])


def pipe(payload):
    reader, writer = os.pipe()
    assert os.write(writer, payload) == len(payload)
    return reader, writer, os.readlink("/proc/self/fd/" + str(reader))


def reclaimed(writers):
    for writer in writers:
        try:
            os.write(writer, b"LEAK")
        except BrokenPipeError:
            continue
        raise AssertionError("transferred pipe reader survived Peer cleanup")


def run(path, mode, daemon_pid):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    assert mode in ("splits", "auth_rights", "first_frame")
    if sys.flags.optimize:
        raise RuntimeError("actor assertions must remain enabled")
    os_signal.alarm(30)
    auth = b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode() + b"\r\n"
    negotiation = b"NEGOTIATE_UNIX_FD\r\n"
    handshake = auth + negotiation + b"BEGIN\r\n"
    if mode == "splits":
        cuts = [0, 1, 2, len(auth), len(handshake) - 2, len(handshake) - 1, len(handshake)]
    elif mode == "auth_rights":
        cuts = [0, 1, len(auth) - 2, len(auth) - 1, len(handshake) - 2, len(handshake) - 1]
    else:
        cuts = [len(handshake) - 7]
    clients, writers, readers = [], [], []
    source = None
    try:
        target, healthy = Client(path), Client(path)
        clients.extend([target, healthy])
        owned = "org.foundation.AuthReadObserver"
        request = string(owned)
        healthy.sock.sendall(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        assert healthy.reply(3)["body"] == u32(1)
        healthy.sock.sendall(call("GetId", 4))
        bus_id = healthy.reply(4)["body"]
        emit("ready", target=target.name, healthy=healthy.name, owned=owned,
             handshake=handshake.hex(), cuts=cuts, mode=mode)
        command("baseline")
        baseline = inventory(daemon_pid)
        emit("baseline", fds=baseline)

        for index, cut in enumerate(cuts):
            command("next")
            source = Client.__new__(Client)
            source.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            source.sock.settimeout(3)
            source.sock.connect(path)
            prefix = handshake[:cut]
            emit("opened", index=index, cut=cut, prefix=prefix.hex())
            command("prefix")
            source.sock.sendall(prefix)
            if cut >= len(auth):
                assert source.line().startswith(b"OK ")
            if cut >= len(auth) + len(negotiation):
                assert source.line() == b"AGREE_UNIX_FD\r\n"
            emit("partial", fds=inventory(daemon_pid))
            command("finish")

            if mode == "auth_rights":
                reader, writer, identity = pipe(b"AUTH-REJECT")
                readers.append(reader)
                writers.append(writer)
                source.send_fds(handshake[cut:cut + 1], [reader])
                os.close(readers.pop())
                try:
                    assert source.sock.recv(1) == b""
                    terminal = "eof"
                except ConnectionResetError:
                    terminal = "econnreset"
                emit("done", index=index, terminal=terminal, pipe=identity, rights=1)
            else:
                payload = "binary\nLF\r\ntail"
                binary_tail = signal(2, target.name, None, string(payload), "s")
                if mode == "first_frame":
                    data = hello_with_fd()
                    reader, writer, identity = pipe(b"FIRST-HELLO")
                    readers.append(reader)
                    writers.append(writer)
                    source.sock.sendall(b"BEGIN\r\n")
                    source.send_fds(data[:1], [reader])
                    os.close(readers.pop())
                    source.sock.sendall(data[1:16])
                    emit("first_frame", prefix=data[:16].hex(), frame=data.hex(), pipe=identity)
                    command("retained")
                    assert os.write(writer, b"LIVE") == 4
                    emit("retained", fds=inventory(daemon_pid), pipe=identity)
                    command("complete")
                    source.sock.sendall(data[16:] + binary_tail)
                else:
                    source.sock.sendall(handshake[cut:] + call("Hello", 1) + binary_tail)
                    if cut < len(auth):
                        assert source.line().startswith(b"OK ")
                    if cut < len(auth) + len(negotiation):
                        assert source.line() == b"AGREE_UNIX_FD\r\n"
                reply = source.reply(1)
                assert reply["type"] == 2 and reply["fds"] == []
                source.name = read_string(reply["body"])
                observed = target.receive()
                assert observed["type"] == 4 and observed["serial"] == 2
                assert observed["fields"][7] == source.name and observed["body"] == string(payload)
                assert observed["fds"] == []
                if mode == "first_frame":
                    reader, writer, identity = pipe(b"usable\npipe")
                    readers.append(reader)
                    writers.append(writer)
                    source.send_fds(signal(3, target.name), [reader])
                    os.close(readers.pop())
                    observed = target.receive()
                    received = observed["fds"]
                    try:
                        assert observed["type"] == 4 and observed["serial"] == 3
                        assert observed["fields"][7] == source.name and observed["body"] == u32(0)
                        assert len(received) == 1
                        assert os.readlink("/proc/self/fd/" + str(received[0])) == identity
                        assert os.read(received[0], 64) == b"usable\npipe"
                    finally:
                        for fd in received:
                            os.close(fd)
                source.barrier(4)
                emit("registered", source=source.name, binary_lf=True,
                     usable_fd=(mode == "first_frame"), fds=inventory(daemon_pid))
                command("close")
                emit("done", index=index, rights=len(writers))

            source.close()
            source = None
            command("settled")
            health(healthy, owned, bus_id, 100 + 2 * index)
            target.barrier(100 + index)
            reclaimed(writers)
            count = len(writers)
            for writer in writers:
                os.close(writer)
            writers = []
            emit("settled", index=index, healthy=True, reclaimed=count, fds=inventory(daemon_pid))

        command("stop")
        for client in clients:
            client.close()
        clients = []
        emit("result", mode=mode, cases=len(cuts), result="PASS")
    finally:
        if source is not None:
            source.close()
        for client in clients:
            client.close()
        for fd in readers + writers:
            os.close(fd)


if __name__ == "__main__":
    run(*sys.argv[1:])
