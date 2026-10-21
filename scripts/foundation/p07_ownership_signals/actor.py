"""Supplementary P07 recorder. Runtime collection needs a private bus socket.

Importing this module opens no sockets and starts no processes. Only collect()
connects; it never launches or configures a bus. Offline tests bypass that path.
"""
import argparse
import array
import hashlib
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


wire = _load("p07_wire", ROOT / "apps/gao_bus/test/fixtures/transport_actor.py")
oracle = _load("p07_oracle", HERE / "oracle.py")
SOURCE = "apps/gao_bus/test/name_reference_test.exs"
SOURCE_SHA256 = "57d95a42205808db0a0d554f23b2750e1b3b23be7a125bf99ead277da09c62c5"
MAX_TRACE_BYTES = 8 * 1024 * 1024


def comparison_source():
    data = (ROOT / SOURCE).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != SOURCE_SHA256:
        raise ValueError("original comparison source changed; review the source binding")
    sequence = re.search(r"sequence = \[(.*?)\n    \]", data.decode(), re.S).group(1)
    actions = [[kind, int(role), *([int(flags)] if flags else [])]
               for kind, role, flags in re.findall(
                   r"\{:(request|release), (\d+)(?:, (\d+))?\}", sequence)]
    if actions != oracle.ACTIONS:
        raise ValueError("original fourteen-action sequence differs")
    return {"path": SOURCE, "sha256": digest, "actions": actions}


class RecordingClient(wire.Client):
    def __init__(self, path, deadline, observer=False):
        self.deadline = deadline
        self.receive_index = 0
        self.recorded_bytes = 0
        self.calls = []
        self.receives = []
        self.bus_id = None
        # The independent constructor records Hello/ListNames receives through
        # our receive(), before its reply() filters any intervening signals.
        super().__init__(path, negotiate=False)
        self.serial = 2
        rule = oracle.WATCH_MATCH if observer else oracle.MATCH
        result = self.query("AddMatch", "s", wire.string(rule))
        if result["type"] != 2:
            raise ValueError("ordinary ownership subscription failed")

    def _timeout(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("ownership collection deadline reached")
        self.sock.settimeout(min(3.0, remaining))

    def line(self):
        data = b""
        while not data.endswith(b"\r\n"):
            self._timeout()
            byte = self.sock.recv(1)
            if not byte or len(data) >= 4096:
                raise ValueError("authentication response missing or too long")
            data += byte
        return data

    def read(self, length, fds):
        data = b""
        while len(data) < length:
            self._timeout()
            part, controls, flags, _ = self.sock.recvmsg(
                length - len(data), socket.CMSG_SPACE(253 * 4))
            for level, kind, rights in controls:
                if (level, kind) != (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    raise ValueError("unexpected ancillary data")
                received = array.array("i")
                received.frombytes(rights)
                fds.extend(received)
            if not part or flags & socket.MSG_CTRUNC:
                raise ValueError("incomplete message or ancillary data")
            data += part
        return data

    def receive(self):
        self._timeout()
        message = super().receive()
        try:
            self.receive_index += 1
            event = {"index": self.receive_index, "type": message["type"],
                     "serial": message["serial"],
                     "fields": {str(k): v for k, v in message["fields"].items()},
                     "body_hex": message["body"].hex(), "fd_count": len(message["fds"])}
            self.receives.append(event)
            self.recorded_bytes += len(json.dumps(event))
            if self.receive_index > 2048 or self.recorded_bytes > MAX_TRACE_BYTES:
                raise ValueError("ownership transcript collection bound exceeded")
            if message["fds"]:
                raise ValueError("ordinary ownership sequence received descriptors")
            return message
        finally:
            wire.close_fds(message["fds"])

    def query(self, member, signature="", body=b""):
        self.serial += 1
        packet = wire.call(member, self.serial, signature, body)
        self.calls.append({"serial": self.serial, "member": member,
                           "signature": signature, "body_hex": body.hex(),
                           "wire_hex": packet.hex()})
        self._timeout()
        self.sock.sendall(packet)
        return self.reply(self.serial)

    def take(self):
        snapshot = {"calls": self.calls, "receives": self.receives}
        self.calls, self.receives = [], []
        return snapshot

    def snapshot(self):
        result = self.query("GetId")
        if result["type"] != 2 or result["fields"].get(8) != "s":
            raise ValueError("GetId barrier did not return a bus identity")
        bus_id = wire.read_string(result["body"])
        if not re.fullmatch(r"[0-9a-f]{32}", bus_id):
            raise ValueError("GetId barrier returned an invalid identity")
        if self.bus_id is not None and self.bus_id != bus_id:
            raise ValueError("bus identity changed during collection")
        self.bus_id = bus_id
        return self.take()

    def identity(self):
        return {"unique": self.name, "pid": os.getpid(), "uid": os.getuid(),
                "gid": os.getgid(), "bus_id": self.bus_id}


def _private_socket(value):
    path = Path(value)
    if not path.is_absolute() or str(path) != os.path.abspath(path):
        raise ValueError("an explicit absolute private socket pathname is required")
    live = {"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket"}
    for key in ("DBUS_SYSTEM_BUS_ADDRESS", "DBUS_SESSION_BUS_ADDRESS"):
        for address in os.environ.get(key, "").split(";"):
            match = re.search(r"(?:^unix:|,)path=([^,]+)", address)
            if match:
                live.add(match.group(1))
    if str(path) in live or re.fullmatch(r"/run/user/\d+/bus", str(path)):
        raise ValueError("host system/session socket is forbidden")
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise ValueError("socket pathname must not contain symlinks")
    parent, endpoint = path.parent.stat(), path.stat()
    if (parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700
            or endpoint.st_uid != os.getuid() or not stat.S_ISSOCK(endpoint.st_mode)):
        raise ValueError("socket must be user-owned inside its private 0700 directory")
    return str(path)


def _write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _observer(path, deadline, channel, directory):
    # Only small acknowledgements cross the pipe. Raw bounded snapshots are
    # journaled first, so a failed controller can retain partial observations.
    client = RecordingClient.__new__(RecordingClient)
    try:
        client.__init__(path, deadline, observer=True)
        slot = 0
        while True:
            snapshot = client.snapshot()
            _write_json(Path(directory) / f"{slot:02d}.json",
                        {"identity": client.identity(), "snapshot": snapshot})
            channel.send({"ok": True, "slot": slot})
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not channel.poll(remaining):
                raise TimeoutError("observer command deadline reached")
            command = channel.recv()
            if command == "stop":
                break
            if command != "snapshot" or slot >= len(oracle.ACTIONS) + len("ABCD"):
                raise ValueError("unexpected observer command")
            slot += 1
    except Exception as error:
        _write_json(Path(directory) / "error.json",
                    {"error": f"{type(error).__name__}: {error}",
                     "partial": client.take() if hasattr(client, "calls") else {}})
        try:
            channel.send({"ok": False})
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        if hasattr(client, "sock"):
            client.close()
        channel.close()


def _observation(channel, directory, slot, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not channel.poll(remaining):
        raise TimeoutError("observer snapshot deadline reached")
    reply = channel.recv()
    if reply != {"ok": True, "slot": slot}:
        raise ValueError("observer failed; see preserved journal")
    return json.loads((Path(directory) / f"{slot:02d}.json").read_text())


def _observer_journal(directory):
    records, errors = {}, []
    for path in sorted(Path(directory).glob("*.json")):
        raw = None
        try:
            raw = path.read_bytes()
            records[path.name] = json.loads(raw)
        except (OSError, ValueError) as error:
            detail = f"{path.name}: {type(error).__name__}: {error}"
            errors.append(detail)
            records[path.name] = {"error": detail,
                                  "raw_hex": raw.hex() if raw is not None else None}
    return records, errors


def collect(path, backend, profile, output, timeout=120):
    report = {"schema": 2, "kind": "runtime", "backend": backend,
              "profile": profile, "name": oracle.NAME, "actors": {},
              "setup": {}, "registrations": [], "steps": [], "qualifies_original_gate": False,
              "status": "INCOMPLETE"}
    clients, child, channel = {}, None, None
    # Reserve the final file before making any connection. Existing evidence
    # is never replaced, including reports from unsuccessful collection.
    with Path(output).open("x", encoding="utf-8") as stream:
        with tempfile.TemporaryDirectory(prefix="osbus-p07-observer-") as directory:
            try:
                path = _private_socket(path)
                if backend not in ("candidate", "reference") or not profile or not 1 <= timeout <= 300:
                    raise ValueError("explicit backend/profile and finite timeout required")
                deadline = time.monotonic() + timeout
                report["socket"] = path
                report["source"] = comparison_source()
                report["implementation_sha256"] = {
                    str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in (Path(__file__), HERE / "oracle.py",
                              ROOT / "apps/gao_bus/test/fixtures/transport_actor.py")}
                context = multiprocessing.get_context("spawn")
                channel, observer_channel = context.Pipe()
                child = context.Process(target=_observer,
                                        args=(path, deadline, observer_channel, directory))
                child.start()
                observer_channel.close()
                observer = _observation(channel, directory, 0, deadline)
                report["actors"]["W"] = observer["identity"]
                report["setup"]["W"] = observer["snapshot"]
                # W's acknowledged AddMatch/GetId setup precedes participant
                # registration. Its own snapshots retain the unique-name
                # broadcasts without inferring order between connections.
                for role in "ABCD":
                    clients[role] = RecordingClient.__new__(RecordingClient)
                    clients[role].__init__(path, deadline)
                    report["setup"][role] = clients[role].snapshot()
                    report["actors"][role] = clients[role].identity()
                    channel.send("snapshot")
                    observed = _observation(channel, directory,
                                            len(report["registrations"]) + 1, deadline)
                    report["registrations"].append({"role": role, "observer": observed["snapshot"]})
                for index, action in enumerate(report["source"]["actions"], 1):
                    step = {"index": index, "action": action, "peers": {}}
                    report["steps"].append(step)
                    client = clients["ABCD"[action[1]]]
                    body = wire.string(oracle.NAME)
                    if action[0] == "request":
                        body += wire.padding(len(body), 4) + wire.u32(action[2])
                        client.query("RequestName", "su", body)
                    else:
                        client.query("ReleaseName", "s", body)
                    client.query("ListQueuedOwners", "s", wire.string(oracle.NAME))
                    channel.send("snapshot")
                    for role, peer in clients.items():
                        step["peers"][role] = peer.snapshot()
                    step["peers"]["W"] = _observation(
                        channel, directory, index + len(report["registrations"]), deadline)["snapshot"]
                # Collect the entire sequence even if the pristine reference
                # differs. A normative mismatch retains all raw observations.
                report["validation"] = oracle.validate(report)
                report["status"] = "RECORDED_VALID"
            except Exception as error:
                report["status"] = "FAIL"
                report["error"] = f"{type(error).__name__}: {error}"
            finally:
                if channel is not None:
                    try:
                        channel.send("stop")
                    except (BrokenPipeError, EOFError, OSError):
                        pass
                if child is not None and child.pid is not None:
                    child.join(3)
                    if child.is_alive():
                        child.terminate()
                        child.join(3)
                    if child.is_alive():
                        child.kill()
                        child.join(3)
                    report["observer_exitcode"] = child.exitcode
                    if child.exitcode != 0:
                        report["status"] = "FAIL"
                        report["cleanup_error"] = "observer did not finish normally"
                if channel is not None:
                    channel.close()
                report["partial"] = {}
                for role, client in clients.items():
                    if hasattr(client, "calls"):
                        report["partial"][role] = client.take()
                    if hasattr(client, "sock"):
                        client.close()
                report["observer_journal"], journal_errors = _observer_journal(directory)
                if journal_errors:
                    report["status"] = "FAIL"
                    report["journal_errors"] = journal_errors
                json.dump(report, stream, indent=2, sort_keys=True)
                stream.write("\n")
    return report["status"] == "RECORDED_VALID"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    record = commands.add_parser("collect", help="future authorized private-socket collection")
    record.add_argument("--socket", required=True)
    record.add_argument("--backend", required=True, choices=("candidate", "reference"))
    record.add_argument("--profile", required=True)
    record.add_argument("--output", required=True)
    record.add_argument("--timeout", type=int, default=120)
    compare = commands.add_parser("compare", help="offline comparison of complete observations")
    compare.add_argument("--reference", required=True)
    compare.add_argument("--candidate", required=True)
    compare.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "collect":
        return 0 if collect(args.socket, args.backend, args.profile, args.output, args.timeout) else 1
    result = oracle.compare(json.loads(Path(args.reference).read_text()),
                            json.loads(Path(args.candidate).read_text()))
    _write_json(args.output, result)
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
