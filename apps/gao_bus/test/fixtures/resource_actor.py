"""Independent, generated-resource SCM_RIGHTS actor; requires a private address."""
import array
import os
import socket
import sys
import tempfile

path, mode = sys.argv[1:]
assert path.startswith('/tmp/') or '/tmp/' in path, 'private test address required'
sock = socket.socket(socket.AF_UNIX)
sock.settimeout(5)
sock.connect(path)
reader, writer = os.pipe()
os.write(writer, b'pipe-data')
os.close(writer)
regular = tempfile.TemporaryFile()
regular.write(b'file-data')
regular.seek(0)
left, right = socket.socketpair()
right.sendall(b'socket-data')
fds = [reader, regular.fileno(), left.fileno()]
try:
    if mode == 'excess':
        fds = fds * 10
    elif mode == 'control_budget':
        fds = [reader] * 253
    elif mode == 'control_truncated':
        # Wait until the accepted receiver has enabled SO_PASSCRED. Credentials
        # plus SCM_MAX_FD rights exceed its fixed rights-only control buffer.
        assert sys.stdin.buffer.read(1) == b's'
        fds = [reader] * 253
    sock.sendmsg([b'resources'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', fds))])
    if mode in ('roundtrip', 'short_write'):
        if mode == 'short_write':
            assert sys.stdin.buffer.read(1) == b'!'
        payload = b''
        received = array.array('i')
        expected_size = 65536 if mode == 'short_write' else 8
        while len(payload) < expected_size:
            data, control, flags, _ = sock.recvmsg(65536, socket.CMSG_SPACE(3 * 4))
            assert data and not flags & socket.MSG_CTRUNC
            payload += data
            for level, kind, raw in control:
                assert (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS)
                received.frombytes(raw)
        assert payload == (b'x' * 65536 if mode == 'short_write' else b'returned')
        try:
            assert len(received) == 3
            assert [os.read(fd, 32) for fd in received] == [b'pipe-data', b'file-data', b'socket-data']
        finally:
            for fd in received:
                os.close(fd)
    elif mode == 'owner_exit':
        assert sock.recv(1) == b''
    else:
        assert sock.recv(1) == b'!'
    # Keep the actor/port alive until the daemon has sampled its own FD count.
    assert sys.stdin.buffer.read(1) == b'q'
    print('RESOURCE_ACTOR_OK', flush=True)
finally:
    os.close(reader)
    regular.close()
    left.close()
    right.close()
    sock.close()
