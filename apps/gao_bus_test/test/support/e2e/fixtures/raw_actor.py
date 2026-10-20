"""Independent raw Unix client for private harness fixtures; no bus library."""
import json
import os
from pathlib import Path
import socket
import sys

directory, path, request = sys.argv[1:]
directory = Path(directory).resolve()
path = Path(path)
assert directory.parent == Path(os.environ['TMPDIR']).resolve()
assert path.is_absolute() and path.parent.resolve() == directory
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(5)
    client.connect(str(path))
    wire = bytes.fromhex(request)
    client.sendall(wire)
    reply = b''
    while not reply.endswith(b'\r\n'):
        part = client.recv(4096)
        assert part and len(reply) < 65536
        reply += part
    print(json.dumps(dict(pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
                          sent_hex=wire.hex(), received_hex=reply.hex())), flush=True)
    # Remain an active actor until the runner fails, rather than exit before it.
    client.settimeout(None)
    while client.recv(4096):
        pass
