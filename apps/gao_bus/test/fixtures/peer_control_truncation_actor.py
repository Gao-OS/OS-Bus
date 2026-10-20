"""Registered private-bus SCM_RIGHTS sender and external daemon FD oracle."""
import errno
import json
import os
import signal as os_signal
import sys

from transport_actor import Client, call, close_fds, signal, string, u32


def emit(event, **details):
    print(json.dumps(dict(event=event, **details)), flush=True)


def command(expected):
    assert sys.stdin.readline().strip() == expected, expected


def inventory(pid):
    directory = "/proc/" + pid + "/fd"
    return {name: os.readlink(directory + "/" + name)
            for name in sorted(os.listdir(directory))}


def pipes(count):
    readers, writers = [], []
    for index in range(count):
        reader, writer = os.pipe()
        os.write(writer, ("RIGHT-" + str(index)).encode())
        readers.append(reader)
        writers.append(writer)
    return readers, writers


def reclaimed(writers):
    for writer in writers:
        try:
            os.write(writer, b"LEAK-PROBE")
        except BrokenPipeError:
            continue
        raise AssertionError("a pipe reader survived terminal Peer cleanup")


def run(path, mode, daemon_pid):
    assert path.startswith("/tmp/"), "explicit private socket required"
    assert mode in ["excess", "credentials", "pending"]
    os_signal.alarm(15)
    clients, readers, writers = [], [], []
    try:
        target = Client(path)
        clients.append(target)
        emit("warm", target=target.name)
        command("snapshot")
        emit("baseline", fds=inventory(daemon_pid))
        command("register")
        source = Client(path)
        clients.append(source)
        owned = "org.foundation.TruncationVictim"
        source.sock.sendall(call("RequestName", 3, "su", string(owned) + b"\0" * (-len(string(owned)) % 4) + u32(0)))
        assert source.reply(3)["body"] == u32(1)
        source.sock.sendall(call("AddMatch", 4, "s", string("type='signal'")))
        assert source.reply(4)["type"] == 2
        source.barrier(5)
        emit("registered", source=source.name, owned=owned, pid=os.getpid())

        if mode == "excess":
            command("positive")
            positive_readers, positive_writers = pipes(16)
            readers.extend(positive_readers)
            writers.extend(positive_writers)
            body = u32(16 * 4) + b"".join(u32(index) for index in range(16))
            source.send_fds(signal(60, target.name, 16, body, "ah"), positive_readers)
            close_fds(positive_readers)
            readers.clear()
            delivered = target.receive()
            assert delivered["serial"] == 60 and len(delivered["fds"]) == 16
            try:
                assert [os.read(fd, 32) for fd in delivered["fds"]] == [
                    ("RIGHT-" + str(index)).encode() for index in range(16)]
            finally:
                close_fds(delivered["fds"])
            reclaimed(positive_writers)
            source.barrier(6)
            target.barrier(7)
            emit("positive", delivered=16, reclaimed=16)

        if mode == "pending":
            command("fragment")
            first_readers, first_writers = pipes(1)
            readers.extend(first_readers)
            writers.extend(first_writers)
            data = signal(70, target.name, 18)
            source.send_fds(data[:8], first_readers)
            pipe_identity = os.readlink("/proc/self/fd/" + str(first_readers[0]))
            close_fds(first_readers)
            readers.clear()
            emit("fragment", pipe=pipe_identity)
            command("retained")
            emit("retained", fds=inventory(daemon_pid))
            tail = data[8:]
        else:
            tail = signal(70, target.name, 17 if mode == "excess" else 16)

        command("truncate")
        next_readers, next_writers = pipes(16 if mode == "credentials" else 17)
        readers.extend(next_readers)
        writers.extend(next_writers)
        source.send_fds(tail, next_readers)
        close_fds(next_readers)
        readers.clear()
        try:
            assert source.sock.recv(1) == b"", "offending registered Peer remained open"
            terminal = "eof"
        except ConnectionResetError as error:
            # Closing an accepted socket with an unread frame tail sends RST.
            assert error.errno == errno.ECONNRESET
            terminal = "econnreset"
        reclaimed(writers)
        target.barrier(80)
        emit("closed", reclaimed=len(writers), terminal=terminal)
        command("final")
        emit("final", fds=inventory(daemon_pid))
        command("stop")
        emit("result", result="PASS", scenario=mode)
    finally:
        close_fds(readers)
        close_fds(writers)
        for client in clients:
            client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 4
    run(*sys.argv[1:])
