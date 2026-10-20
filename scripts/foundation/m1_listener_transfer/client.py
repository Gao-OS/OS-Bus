"""One test-only exact-EOF operation over the immutable independent actor."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('listener_original_actor', HERE / 'inherited/security/actor.py')
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)


class TransferClient(original.Client):
    def command(self, request):
        assert request == {'op': 'transfer'}, 'transfer-only client operation'
        began = time.monotonic()
        with socket.socket(socket.AF_UNIX) as channel:
            channel.settimeout(1)
            channel.connect(self.path)
            channel.sendall(b'\x2a')
            remaining = 1 - (time.monotonic() - began)
            assert remaining > 0
            channel.settimeout(remaining)
            # A reset raises; it is never relabelled as EOF.
            assert channel.recv(1) == b'', 'incomplete accepted socket did not return EOF'
        return dict(closed=True, method='eof', sent_hex='2a', response_hex='',
                    elapsed_ms=(time.monotonic() - began) * 1000)


if __name__ == '__main__':
    assert Path('/etc/osbus-security-guest').read_text() == 'isolated-vm\n'
    assert sys.argv[1] == '/run/osbus-security/listener-transfer/transfer'
    assert os.getuid() == os.getgid() == 1101
    client = TransferClient(sys.argv[1])
    print(json.dumps(dict(pid=os.getpid(),uid=os.getuid(),gid=os.getgid())), flush=True)
    for line in sys.stdin:
        try:
            result = client.command(json.loads(line))
            print(json.dumps(dict(ok=True,result=result)), flush=True)
        except Exception as error:
            print(json.dumps(dict(ok=False,error=repr(error))), flush=True)
