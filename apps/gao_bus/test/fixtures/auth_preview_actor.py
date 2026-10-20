"""Independent raw Unix-stream/SCM_RIGHTS sender for the auth-preview API test."""
import array
import json
import os
from pathlib import Path
import socket
import sys


path, parent_pid = sys.argv[1:]
assert Path(path).name == "bus"
assert Path(path).parent.name.startswith("osbus-preview-")
assert parent_pid.isdecimal() and int(parent_pid) > 0
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(5)
reader = None


def emit(value):
    print(value, flush=True)


try:
    sock.connect(path)
    emit("READY")
    for raw in sys.stdin.buffer:
        command = raw.rstrip(b"\n")
        if command == b"partial":
            sock.sendall(b"BEG")
            emit("PARTIAL")
        elif command == b"full":
            sock.sendall(b"BEGIN\r\nl")
            emit("FULL")
        elif command == b"begin_rights":
            assert reader is None
            reader, writer = os.pipe()
            try:
                assert os.write(writer, b"auth-preview-pipe") == 17
            finally:
                os.close(writer)
            sock.sendall(b"BEGIN\r\n")
            assert sock.sendmsg(
                [b"l"],
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [reader]))],
            ) == 1
            emit("BEGIN_RIGHTS")
        elif command == b"return":
            received = array.array("i")
            try:
                data, controls, flags, _ = sock.recvmsg(8, socket.CMSG_SPACE(4))
                for level, kind, payload in controls:
                    assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                    received.frombytes(payload)
                assert data == b"returned" and flags == 0 and len(received) == 1
                assert os.read(received[0], 64) == b"auth-preview-pipe"
                assert os.read(received[0], 1) == b""
            finally:
                for fd in received:
                    os.close(fd)
            emit("PIPE_OK")
        elif command == b"tail":
            sock.sendall(b"tail")
            emit("TAIL")
        elif command == b"eof":
            sock.shutdown(socket.SHUT_WR)
            emit("EOF")
        elif command == b"snapshot":
            directory = Path("/proc") / parent_pid / "fd"
            inventory = {int(p.name): os.readlink(p) for p in directory.iterdir()}
            emit("FD_MAP\t" + str(len(inventory)) + "\t" + json.dumps(inventory, sort_keys=True))
        elif command == b"quit":
            emit("AUTH_PREVIEW_ACTOR_OK")
            break
        else:
            raise AssertionError("unexpected command: " + repr(command))
finally:
    if reader is not None:
        os.close(reader)
    sock.close()
