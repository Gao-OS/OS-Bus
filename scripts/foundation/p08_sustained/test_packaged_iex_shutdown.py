"""Orderly stop must finish real IEx application cleanup before input EOF."""
import errno
import os
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest

from packaged_console import Console


APPLICATION = r'''
defmodule OSBusShutdownBarrier do
  use Application

  def start(_type, _args), do: Supervisor.start_link([], strategy: :one_for_one)

  def stop(_state) do
    File.write!(System.fetch_env!("OSBUS_STOP_ENTERED"), "entered")
    "complete" = File.read!(System.fetch_env!("OSBUS_STOP_FIFO"))
    File.write!(System.fetch_env!("OSBUS_STOP_FINISHED"), "finished")
  end
end

:ok = :application.load({:application, :osbus_shutdown_barrier,
  [vsn: ~c"1", mod: {OSBusShutdownBarrier, []}, applications: [:kernel, :stdlib, :elixir]]})
:ok = Application.start(:osbus_shutdown_barrier)
IO.puts("BARRIER_READY")
'''


class IExShutdownTests(unittest.TestCase):
    def test_orderly_stop_keeps_input_open_through_real_application_cleanup(self):
        executable = os.environ.get('OSBUS_P08_IEX')
        self.assertIsNotNone(executable, 'BLOCKED_ENV: OSBUS_P08_IEX must name pinned IEx')
        self.assertTrue(Path(executable).is_file(), 'BLOCKED_ENV: pinned IEx unavailable')
        with tempfile.TemporaryDirectory(prefix='osbus-iex-shutdown-') as directory:
            root = Path(directory)
            entered, finished, fifo = (root / name for name in ('entered', 'finished', 'fifo'))
            os.mkfifo(fifo)
            application = root / 'application.exs'
            application.write_text(APPLICATION)
            console = Console(['env', '-u', 'DBUS_SYSTEM_BUS_ADDRESS', '-u', 'DBUS_SESSION_BUS_ADDRESS',
                'ERL_FLAGS=+S 2:2', 'ERL_CRASH_DUMP_SECONDS=0',
                'OSBUS_STOP_ENTERED=' + str(entered), 'OSBUS_STOP_FINISHED=' + str(finished),
                'OSBUS_STOP_FIFO=' + str(fifo), executable, '--dot-iex', str(root / 'absent.exs'),
                '-r', str(application)], root / 'console.raw', 'a' * 32)
            outcome = []
            def stop():
                try:
                    outcome.append(console.stop(grace=3))
                except BaseException as error:
                    outcome.append(error)
            thread = None
            try:
                deadline = time.monotonic() + 10
                while b'BARRIER_READY\n' not in console.buffer:
                    try:
                        console.receive_bytes(deadline)
                    except AssertionError as error:
                        self.fail(str(error) + ': ' + console.log.read_text())
                thread = threading.Thread(target=stop)
                thread.start()
                deadline = time.monotonic() + 2
                poll = threading.Event()
                while not entered.exists() and thread.is_alive() and time.monotonic() < deadline:
                    poll.wait(.01)
                self.assertTrue(entered.exists(), 'IEx exited before orderly application cleanup')
                self.assertFalse(console.process.stdin.closed, 'input EOF can halt IEx during cleanup')
                while True:
                    try:
                        descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
                        break
                    except OSError as error:
                        if error.errno != errno.ENXIO or time.monotonic() >= deadline:
                            raise
                        poll.wait(.01)
                try:
                    self.assertEqual(os.write(descriptor, b'complete'), 8)
                finally:
                    os.close(descriptor)
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive(), 'stop exceeded its existing bounded grace')
                self.assertEqual(finished.read_text(), 'finished')
                self.assertEqual(len(outcome), 1)
                self.assertIsInstance(outcome[0], dict)
                self.assertEqual((outcome[0]['method'], outcome[0]['returncode']), ('console-System.stop', 0))
                self.assertTrue(outcome[0]['tail_eof'])
                self.assertTrue(outcome[0]['service_cgroup_cleanup_required'])
            finally:
                if console.process.poll() is None:
                    os.killpg(console.process.pid, signal.SIGKILL)
                if thread is not None:
                    thread.join(timeout=4)
                console.process.wait(timeout=2)
                console.process.stdin.close()
                console.process.stdout.close()


if __name__ == '__main__':
    unittest.main()
