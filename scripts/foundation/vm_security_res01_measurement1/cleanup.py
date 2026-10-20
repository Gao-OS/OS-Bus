"""Exact accepted guest natural-retirement helper; not a host harness."""
import os
from pathlib import Path
import subprocess
import time

def stop_channel(channel, accepted):
        before = dict(stdin_closed=False, wrapper_waited=False, wrapper_returncode=None,
                      pid_absent=False, actor_pid_absent=False, group_absent=False,
                      timed_out=False, errors=[])
        observed_start = time.monotonic()
        try:
            channel.process.stdin.close()
            before['stdin_closed'] = True
            try:
                before['wrapper_returncode'] = channel.process.wait(timeout=5)
                before['wrapper_waited'] = True
            except subprocess.TimeoutExpired:
                before['timed_out'] = True
            group_deadline = time.monotonic() + 1
            while True:
                before['pid_absent'] = not Path('/proc', str(channel.process.pid)).exists()
                before['actor_pid_absent'] = accepted is not None and not Path('/proc', str(accepted['pid'])).exists()
                try:
                    os.killpg(channel.process.pid, 0)
                except ProcessLookupError:
                    before['group_absent'] = True
                else:
                    before['group_absent'] = False
                if (before['pid_absent'] and before['actor_pid_absent'] and before['group_absent']
                        or before['timed_out'] or time.monotonic() >= group_deadline):
                    break
        except Exception as error:
            before['errors'].append(repr(error))
        finally:
            before['elapsed_ms'] = (time.monotonic() - observed_start) * 1000
            # Preserve the original final containment and raw-log draining.
            # Its EOF/exit0 label alone does not prove descendant retirement.
            result = channel.stop()
        result['before_containment'] = before
        group_deadline = time.monotonic() + 1
        while True:
            try:
                os.killpg(channel.process.pid, 0)
            except ProcessLookupError:
                result['group_absent'] = True
                break
            if time.monotonic() >= group_deadline:
                result['group_absent'] = False
                break
        result.update(identity=accepted, pid_absent=not Path('/proc', str(channel.process.pid)).exists(),
                      actor_pid_absent=accepted is not None and not Path('/proc', str(accepted['pid'])).exists())
        return result
