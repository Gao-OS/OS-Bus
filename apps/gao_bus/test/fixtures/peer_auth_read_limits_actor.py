"""Independent real Peer auth line/cumulative byte-limit actor on a private bus."""
import json
import os
import signal as os_signal
import socket
import sys

from transport_actor import Client, call, read_string, signal, string, u32


LINE_LIMIT = 64
AUTH_LIMIT = 160


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


def error_line(size):
    assert size >= 8
    return b"ERROR " + b"x" * (size - 8) + b"\r\n"


def plan(mode, handshake):
    if mode == "line_complete_n":
        return [b"\0" + error_line(LINE_LIMIT)[:-2]], b"\r\n", True
    if mode == "line_complete_n_plus_one":
        return [b"\0" + error_line(LINE_LIMIT + 1)[:-2], b"\r"], b"\n", False
    if mode == "line_incomplete_n_plus_one":
        return [b"\0" + error_line(LINE_LIMIT + 2)[:-2]], b"x", False
    assert mode in ("cumulative_n", "cumulative_n_plus_one")
    total = AUTH_LIMIT + (mode == "cumulative_n_plus_one")
    filler = total - len(handshake)
    full = b"\0" + error_line(LINE_LIMIT) + error_line(filler - LINE_LIMIT) + handshake[1:]
    assert len(full) == total
    return [full[:-2], b"\r"], b"\n", mode == "cumulative_n"


def auth_replies(source):
    assert source.line().startswith(b"OK ")
    assert source.line() == b"AGREE_UNIX_FD\r\n"


def register(source, target, suffix):
    payload = "binary\nLF\r\ntail"
    tail = signal(2, target.name, None, string(payload), "s")
    source.sock.sendall(suffix + call("Hello", 1) + tail)
    reply = source.reply(1)
    assert reply["type"] == 2 and reply["fds"] == []
    source.name = read_string(reply["body"])
    observed = target.receive()
    assert observed["type"] == 4 and observed["serial"] == 2
    assert observed["fields"][7] == source.name and observed["body"] == string(payload)
    assert observed["fds"] == []
    source.barrier(3)
    emit("registered", source=source.name, binary_lf=True)


def run(path, mode, daemon_pid):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    if sys.flags.optimize:
        raise RuntimeError("actor assertions must remain enabled")
    os_signal.alarm(30)
    handshake = (b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode()
                 + b"\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n")
    steps, finish, accepted = plan(mode, handshake)
    clients = []
    source = None
    try:
        target, healthy = Client(path), Client(path)
        clients.extend([target, healthy])
        owned = "org.foundation.AuthReadLimitsObserver"
        request = string(owned)
        healthy.sock.sendall(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        assert healthy.reply(3)["body"] == u32(1)
        healthy.sock.sendall(call("GetId", 4))
        bus_id = healthy.reply(4)["body"]
        emit("ready", mode=mode, target=target.name, healthy=healthy.name, owned=owned,
             handshake=handshake.hex(), steps=[chunk.hex() for chunk in steps], finish=finish.hex())
        command("baseline")
        emit("baseline", fds=inventory(daemon_pid))
        command("next")
        source = Client.__new__(Client)
        source.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        source.sock.settimeout(3)
        source.sock.connect(path)
        emit("opened")
        for index, chunk in enumerate(steps):
            command("step")
            source.sock.sendall(chunk)
            if mode.startswith("cumulative_") and index == 0:
                assert source.line() == b"REJECTED EXTERNAL\r\n"
                assert source.line() == b"REJECTED EXTERNAL\r\n"
                auth_replies(source)
            health(healthy, owned, bus_id, 100 + 2 * index)
            target.barrier(100 + index)
            emit("step", index=index, bytes=chunk.hex(), healthy=True)
        command("finish")
        if mode == "line_complete_n":
            source.sock.sendall(finish)
            reply = source.line()
            assert reply == b"REJECTED EXTERNAL\r\n"
            emit("line_accepted", reply=reply.decode())
            command("register")
            source.sock.sendall(handshake[1:])
            auth_replies(source)
            register(source, target, b"")
        elif accepted:
            register(source, target, finish)
        else:
            source.sock.sendall(finish)
            try:
                assert source.sock.recv(1) == b"", "overflow emitted an accepted response"
                terminal = "eof"
            except ConnectionResetError:
                terminal = "econnreset"
        if accepted:
            command("close")
        source.close()
        source = None
        if accepted:
            emit("done", accepted=True)
        else:
            emit("done", accepted=False, terminal=terminal)
        command("settled")
        health(healthy, owned, bus_id, 200)
        target.barrier(200)
        emit("settled", healthy=True, fds=inventory(daemon_pid))
        command("stop")
        for client in clients:
            client.close()
        clients = []
        emit("result", mode=mode, result="PASS")
    finally:
        if source is not None:
            source.close()
        for client in clients:
            client.close()


if __name__ == "__main__":
    run(*sys.argv[1:])
