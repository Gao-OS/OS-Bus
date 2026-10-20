"""Guest transient-unit runner; bounded observer, inherited sentinel witnesses."""
import json
import os
from pathlib import Path
import socket
import select
import time
import subprocess
import sys
from protocol import decode


def read_record(stdout,stderr,deadline):
    # EOF on both pipes and an exact record are required within one deadline.
    pending={stdout.fileno():True,stderr.fileno():False};raw=b''
    while pending:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('bridge output/EOF deadline')
        ready,_,_=select.select(list(pending),[],[],remaining)
        if not ready:raise TimeoutError('bridge output/EOF deadline')
        for fd in ready:
            data=os.read(fd,17-len(raw) if pending[fd] else 1)
            if not data:del pending[fd];continue
            assert pending[fd], 'unexpected bridge stderr'
            raw+=data
            assert len(raw)<=16, 'extra bridge bytes'
    decode(raw)
    return raw


def main(bridge,name,result):
    assert Path('/etc/osbus-p10-guest').read_text()=='isolated-vm\n'
    result=Path(result)
    assert result.parent.parent==Path('/run/osbus-p10')
    reader,writer=os.pipe()
    pair=socket.socketpair()
    with result.with_suffix('.sentinel').open('w+b') as sentinel:
        fds=[reader,writer,sentinel.fileno(),*(p.fileno() for p in pair)]
        for fd in fds:os.set_inheritable(fd,True)
        try:
            child=subprocess.Popen([bridge,name],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=fds)
            # The native writer contract is at most16 bytes, after exact child reap.
            deadline=time.monotonic()+16
            raw=read_record(child.stdout,child.stderr,deadline)
            code=child.wait(timeout=max(.001,deadline-time.monotonic()))
            assert code==0, 'abnormal bridge lifecycle/output'
            temporary=result.with_suffix('.tmp')
            temporary.write_text(json.dumps({'result':decode(raw),'record_hex':raw.hex(),'bridge_exit':code,
                'caller_pid':os.getpid(),'caller_uids':list(os.getresuid()),'caller_gids':list(os.getresgid()),
                'sentinel_fds':fds})+'\n')
            temporary.replace(result)
        finally:
            if 'child' in locals() and child.poll() is None:
                child.kill();child.wait(timeout=3)
            os.close(reader);os.close(writer)
            for p in pair:p.close()
if __name__=='__main__':main(*sys.argv[1:])
