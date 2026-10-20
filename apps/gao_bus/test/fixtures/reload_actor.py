"""Private-socket ReloadConfig oracle using the existing independent wire actor."""
import collections
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
import transport_actor as wire

BUS = "org.freedesktop.DBus"
INTERFACE = "org.foundation.Reload"
OLD_NAME = "org.foundation.Reload.Old"
NEW_NAME = "org.foundation.Reload.New"
TRANSITION_NAME = "org.foundation.Reload.Transition"
ROUNDS = 8
INVALID_RELOAD_ERRORS = {
    "candidate": {"malformed-xml": "Failed", "missing-include": "FileNotFound"},
    "reference": {"malformed-xml": "Failed", "missing-include": "FileNotFound"},
}


def policy(uid, phase):
    forbidden = "NewOnly" if phase == "old" else "OldOnly"
    forbidden_name = NEW_NAME if phase == "old" else OLD_NAME
    split_direction = "receive" if phase == "old" else "send"
    return f'''<busconfig><policy context="default">
      <allow user="*"/><allow own="*"/>
      <allow send_type="method_call"/><allow send_requested_reply="true"/>
      <allow receive_type="method_call"/><allow receive_type="signal"/>
      <allow receive_requested_reply="true"/>
      <deny send_destination="{BUS}" send_interface="{BUS}" send_member="ReloadConfig"/>
      <deny own="{forbidden_name}"/>
      <deny send_type="method_call" send_interface="{INTERFACE}" send_member="{forbidden}"/>
      <deny {split_direction}_type="method_call" {split_direction}_interface="{INTERFACE}"
            {split_direction}_member="Split"/>
    </policy><policy user="{uid}">
      <allow send_destination="{BUS}" send_interface="{BUS}" send_member="ReloadConfig"/>
    </policy></busconfig>'''


def replace(path, contents):
    temporary = path.with_suffix(".next")
    temporary.write_text(contents)
    temporary.chmod(0o644)
    temporary.replace(path)


def prepare(directory, uid, ordinary_uid):
    assert uid != ordinary_uid, "ordinary and authorized kernel UIDs must differ"
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o755)
    socket_directory = directory.parent / "socket"
    socket_directory.mkdir(exist_ok=True)
    socket_directory.chmod(0o755)
    replace(directory / "bus.conf", f'''<busconfig><type>system</type><auth>EXTERNAL</auth>
      <listen>unix:path={socket_directory / 'bus'}</listen><include>policy.conf</include></busconfig>''')
    replace(directory / "policy.conf", "<busconfig><include>rules.conf</include></busconfig>")
    replace(directory / "rules.conf", policy(uid, "old"))


def prepared_socket(directory):
    listen = ET.parse(directory / "bus.conf").getroot().findtext("listen")
    assert listen and listen.startswith("unix:path="), "private fixture requires a filesystem socket"
    return Path(listen.removeprefix("unix:path="))


class Client(wire.Client):
    def __init__(self, path, label, trace):
        self.label, self.trace, self.serial = label, trace, 10
        super().__init__(path, negotiate=False)
        trace.append({"event": "identity", "actor": label, "name": self.name,
                      "pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
                      "groups": os.getgroups()})

    def receive(self):
        message = super().receive()
        assert not message["fds"], "reload fixture must never receive rights"
        self.trace.append({"event": "receive", "actor": self.label,
                           "type": message["type"], "serial": message["serial"],
                           "fields": message["fields"], "body_hex": message["body"].hex()})
        return message

    def send(self, member, signature="", body=b"", destination=BUS, interface=BUS):
        self.serial += 1
        data = wire.frame(1, self.serial, [(1, "o", "/org/freedesktop/DBus"),
            (2, "s", interface), (3, "s", member), (6, "s", destination),
            (8, "g", signature)], body)
        self.trace.append({"event": "call", "actor": self.label, "serial": self.serial,
            "member": member, "destination": destination, "interface": interface,
            "signature": signature, "body_hex": body.hex(), "wire_hex": data.hex()})
        self.sock.sendall(data)
        return self.serial

    def query(self, member, signature="", body=b""):
        return self.reply(self.send(member, signature, body))

    def reply(self, serial):
        while True:
            message = self.receive()
            if message["fields"].get(5) == serial:
                return message
            assert_bus_signal(message)


def assert_bus_signal(message):
    assert message["type"] == 4 and message["fields"].get(2) == BUS, message


def ok(message, signature=""):
    assert message["type"] == 2 and message["fields"].get(8, "") == signature, message
    if not signature:
        assert message["body"] == b"", message
    return message


def error(message, name):
    assert message["type"] == 3 and message["fields"].get(4) == BUS + ".Error." + name, message


def number(message):
    ok(message, "u")
    assert len(message["body"]) == 4, message
    return struct.unpack("<I", message["body"])[0]


def request(client, name):
    body = wire.string(name)
    return client.query("RequestName", "su", body + wire.padding(len(body), 4) + wire.u32(0))


def release(client, name):
    assert number(client.query("ReleaseName", "s", wire.string(name))) == 1


def probe(caller, target, member, expected=None):
    """Pump both actual sockets; any delivered call is recorded and answered."""
    marker = f"{member}:{os.getpid()}:{caller.serial}"
    serial = caller.send(member, "s", wire.string(marker), target.name, INTERFACE)
    barrier = target.send("GetId")
    response, barrier_seen, delivered = None, False, False
    while response is None or not barrier_seen:
        readable, _, _ = select.select([caller.sock, target.sock], [], [], 3)
        assert readable, "no response to pending probe/barrier"
        for current in readable:
            client = caller if current is caller.sock else target
            message = client.receive()
            if client is caller and message["fields"].get(5) == serial:
                response = message
            elif client is target and message["fields"].get(5) == barrier:
                ok(message, "s")
                barrier_seen = True
            elif client is target and message["type"] == 1:
                assert message["fields"].get(2) == INTERFACE, message
                assert message["serial"] == serial and message["fields"].get(3) == member, message
                assert message["body"] == wire.string(marker), message
                delivered = True
                target.serial += 1
                data = wire.frame(2, target.serial, [(5, "u", serial),
                    (6, "s", caller.name), (8, "g", "s")], wire.string(marker))
                target.trace.append({"event": "echo", "actor": target.label,
                    "serial": target.serial, "reply_serial": serial, "wire_hex": data.hex()})
                target.sock.sendall(data)
            else:
                assert_bus_signal(message)
    allowed = response["type"] == 2
    if allowed:
        ok(response, "s")
        assert response["body"] == wire.string(marker) and delivered, response
    else:
        error(response, "AccessDenied")
        assert not delivered, "denied probe payload reached recipient"
    # The caller's response causally follows the route; this barrier also catches
    # any payload erroneously queued behind the first recipient barrier.
    ok(target.query("GetId"), "s")
    if expected is not None:
        assert allowed == expected, (member, expected, response)
    target.trace.append({"event": "probe", "member": member, "allowed": allowed,
                         "delivered": delivered, "marker": marker})


def check(caller, target, phase):
    for member in ["OldOnly", "NewOnly", "Split"]:
        probe(caller, target, member,
              member == ("OldOnly" if phase == "old" else "NewOnly"))
    for name, permitted in [(OLD_NAME, phase == "old"), (NEW_NAME, phase == "new")]:
        response = request(caller, name)
        if permitted:
            assert number(response) == 1
            owner = ok(target.query("GetNameOwner", "s", wire.string(name)), "s")
            assert wire.read_string(owner["body"]) == caller.name
            release(caller, name)
        else:
            error(response, "AccessDenied")
            error(target.query("GetNameOwner", "s", wire.string(name)), "NameHasNoOwner")
    ok(caller.query("GetId"), "s")


def worker(connection, path, role, ordinary_uid):
    clients, trace = [], []
    try:
        if role == "ordinary":
            os.setgroups([])
            os.setgid(ordinary_uid)
            os.setuid(ordinary_uid)
            assert os.getuid() == ordinary_uid
            for filename in ["bus.conf", "policy.conf", "rules.conf"]:
                file = Path(path).parent.parent / "config" / filename
                try:
                    descriptor = os.open(file, os.O_WRONLY)
                except PermissionError:
                    trace.append({"event": "trusted-file-denied", "file": filename,
                                  "uid": os.getuid(), "pid": os.getpid()})
                else:
                    os.close(descriptor)
                    raise AssertionError("ordinary actor can write trusted " + filename)
        caller = Client(path, role, trace)
        clients.append(caller)
        target = None
        if role == "traffic":
            target = Client(path, "recipient", trace)
            clients.append(target)
        connection.send({"event": "ready", "trace": trace})
        trace.clear()
        while True:
            command = connection.recv()
            if command["op"] == "stop":
                break
            if command["op"] == "ordinary":
                error(caller.query("ReloadConfig"), "AccessDenied")
                ok(caller.query("GetId"), "s")
            elif command["op"] == "check":
                check(caller, target, command["phase"])
            elif command["op"] == "concurrent":
                body = wire.string(TRANSITION_NAME)
                serial = caller.send("RequestName", "su",
                                     body + wire.padding(len(body), 4) + wire.u32(0))
                connection.send({"event": "submitted"})
                assert connection.recv() == {"op": "continue"}
                assert number(caller.reply(serial)) == 1
                # Split is denied in each complete old/new generation. The two
                # other calls may legitimately straddle a publication boundary.
                for member in ["Split", "OldOnly", "NewOnly"]:
                    probe(caller, target, member, False if member == "Split" else None)
                release(caller, TRANSITION_NAME)
                ok(caller.query("GetId"), "s")
            else:
                raise AssertionError(command)
            connection.send({"event": "complete", "trace": trace})
            trace.clear()
    except BaseException as failure:
        connection.send({"event": "failure", "error": repr(failure), "trace": trace})
    finally:
        for client in clients:
            client.close()
        connection.close()


def receive_worker(connection, trace, event="complete"):
    assert connection.poll(15), "independent actor did not finish bounded operation"
    result = connection.recv()
    trace.extend(result.get("trace", []))
    assert result["event"] == event, result


def snapshot_checkpoint(label, generation, trace):
    request = {"event": "snapshot-checkpoint", "label": label,
               "request_id": 1 + sum(item["event"] == "snapshot-checkpoint" for item in trace),
               "expected_generation": generation}
    trace.append(request)
    print(json.dumps(request), flush=True)
    deadline, data = time.monotonic() + 15, b""
    while not data.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        assert remaining > 0 and select.select([sys.stdin], [], [], remaining)[0], \
            "snapshot checkpoint acknowledgement deadline"
        chunk = os.read(sys.stdin.fileno(), 1)
        assert chunk and len(data) < 4096, "incomplete/oversized snapshot acknowledgement"
        data += chunk
    receipt = json.loads(data)
    assert set(receipt) == {"event", "label", "request_id", "generation", "term_sha256"}
    assert receipt["event"] == "snapshot-captured" and receipt["label"] == label
    assert receipt["request_id"] == request["request_id"] and receipt["generation"] == generation
    assert len(receipt["term_sha256"]) == 64 and all(c in "0123456789abcdef" for c in receipt["term_sha256"])
    request["receipt"] = receipt


def run(path, directory, ordinary_uid, backend, checkpoints=False):
    assert os.geteuid() == 0, "BLOCKED_ENV: reload wire actor requires root and a mapped ordinary UID"
    assert ordinary_uid != os.getuid(), "ordinary UID must differ from authorized UID"
    trace, processes, channels, clients = [], [], {}, []
    initial_hash = hashlib.sha256((directory / "bus.conf").read_bytes()).hexdigest()
    try:
        for role in ["ordinary", "traffic"]:
            parent, child = multiprocessing.Pipe()
            process = multiprocessing.Process(target=worker, args=(child, path, role, ordinary_uid))
            process.start()
            child.close()
            processes.append(process)
            channels[role] = parent
            receive_worker(parent, trace, "ready")
        admin = Client(path, "authorized", trace)
        observer = Client(path, "observer", trace)
        clients.extend([admin, observer])
        identities = [item for item in trace if item["event"] == "identity"]
        for identity in identities:
            assert number(observer.query("GetConnectionUnixUser", "s", wire.string(identity["name"]))) == identity["uid"]
            assert number(observer.query("GetConnectionUnixProcessID", "s", wire.string(identity["name"]))) == identity["pid"]
        bus_id = wire.read_string(ok(observer.query("GetId"), "s")["body"])

        def command(role, op, **details):
            channels[role].send({"op": op, **details})
            receive_worker(channels[role], trace)

        def checkpoint(label, generation):
            if checkpoints:
                assert backend == "candidate"
                snapshot_checkpoint(label, generation, trace)

        command("traffic", "check", phase="old")
        replace(directory / "rules.conf", policy(os.getuid(), "new"))
        command("ordinary", "ordinary")
        checkpoint("denied-before-first-success", 1)
        command("traffic", "check", phase="old")
        ok(admin.query("ReloadConfig"))
        command("traffic", "check", phase="new")
        command("ordinary", "ordinary")
        checkpoint("denied-after-first-success", 2)
        for iteration in range(ROUNDS):
            phase = "old" if iteration % 2 == 0 else "new"
            replace(directory / "rules.conf", policy(os.getuid(), phase))
            channels["traffic"].send({"op": "concurrent"})
            receive_worker(channels["traffic"], trace, "submitted")
            serial = admin.send("ReloadConfig")
            channels["traffic"].send({"op": "continue"})
            ok(admin.reply(serial))
            receive_worker(channels["traffic"], trace)
            command("traffic", "check", phase=phase)
            trace.append({"event": "publication", "iteration": iteration, "phase": phase})
            assert wire.read_string(ok(observer.query("GetId"), "s")["body"]) == bus_id
        checkpoint("last-successful-reload", ROUNDS + 2)
        final_policy = policy(os.getuid(), phase)
        rollback_errors = {}
        for invalid in ["malformed-xml", "missing-include"]:
            if invalid == "malformed-xml":
                replace(directory / "rules.conf", "<busconfig>")
            else:
                replace(directory / "rules.conf", final_policy)
                checkpoint("rules-restored-before-missing-include", ROUNDS + 2)
                replace(directory / "policy.conf", "<busconfig><include>missing.conf</include></busconfig>")
            # Both backends must match the pinned reference's exact error name
            # while retaining the complete active policy after each rejection.
            response = admin.query("ReloadConfig")
            error(response, INVALID_RELOAD_ERRORS[backend][invalid])
            rollback_errors[invalid] = response["fields"][4]
            checkpoint(invalid + "-rejected", ROUNDS + 2)
            command("traffic", "check", phase=phase)
            command("ordinary", "ordinary")
            checkpoint(invalid + "-denied", ROUNDS + 2)
            assert wire.read_string(ok(observer.query("GetId"), "s")["body"]) == bus_id
            trace.append({"event": "rollback", "invalid": invalid, "retained_phase": phase,
                          "actual_error": response["fields"][4]})
        replace(directory / "policy.conf", "<busconfig><include>rules.conf</include></busconfig>")
        checkpoint("policy-restored", ROUNDS + 2)
        replace(directory / "rules.conf", final_policy)
        checkpoint("rules-restored-final", ROUNDS + 2)
        assert hashlib.sha256((directory / "bus.conf").read_bytes()).hexdigest() == initial_hash
        expected_errors = {case: BUS + ".Error." + name
                           for case, name in INVALID_RELOAD_ERRORS["reference"].items()}
        error_name_delta = {
            case: {"expected": expected, "actual": rollback_errors.get(case)}
            for case, expected in expected_errors.items()
            if rollback_errors.get(case) != expected
        }
        summary = {"result": "PASS", "backend": backend, "identities": identities,
            "rounds": ROUNDS, "valid_reloads": ROUNDS + 1, "invalid_reloads": 2,
            "denied_reloads": 4, "expected_generation": ROUNDS + 2,
            "final_phase": phase, "bus_id": bus_id, "root_sha256": initial_hash,
            "rollback_errors": rollback_errors, "error_name_delta": error_name_delta,
            "exact_error_equivalence": rollback_errors == expected_errors,
            "exact_error_equivalence_scope": list(expected_errors),
            "installed_profile_qualified": False,
            "counts": dict(collections.Counter(item["event"] for item in trace)), "trace": trace}
        return summary
    except BaseException as failure:
        print(json.dumps({"result": "FAIL", "backend": backend,
                          "error": repr(failure), "trace": trace}), flush=True)
        raise
    finally:
        for client in clients:
            client.close()
        for channel in channels.values():
            try:
                channel.send({"op": "stop"})
            except (BrokenPipeError, EOFError, OSError):
                pass
            channel.close()
        for process in processes:
            process.join(3)
            if process.exitcode is None:
                process.terminate()
                process.join(3)
            if process.exitcode is None:
                process.kill()
                process.join(3)
            assert process.exitcode is not None, "owned actor could not be reaped"


def reference(daemon, directory, ordinary_uid):
    prepare(directory, os.getuid(), ordinary_uid)
    with (directory / "reference.stderr").open("w") as stderr:
        process = subprocess.Popen([daemon, "--config-file=" + str(directory / "bus.conf"),
            "--nofork", "--print-address"], stdout=subprocess.PIPE, stderr=stderr)
        try:
            assert select.select([process.stdout], [], [], 5)[0], "private reference startup timeout"
            address = process.stdout.readline().decode().strip()
            assert address.startswith("unix:path=" + str(prepared_socket(directory))), address
            prepared_socket(directory).chmod(0o666)
            result = run(str(prepared_socket(directory)), directory, ordinary_uid, "reference")
            result["daemon_sha256"] = hashlib.sha256(Path(daemon).read_bytes()).hexdigest()
            return result
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


PROTECTED_NAME = "org.foundation.Reload.Protected"
ALTERNATE_NAME = "org.foundation.Reload.Alternate"
ALIAS_FILES = ("bus.conf", "policy.conf", "rules.conf")


def prepare_alias(directory, root_uid, caller_uid, service_uid):
    assert os.getuid() == root_uid == 0, "alias fixture requires a root coordinator"
    assert len({root_uid, caller_uid, service_uid}) == 3, "alias fixture requires distinct UIDs"
    prepare(directory, root_uid, caller_uid)
    deny = f'''<policy user="{caller_uid}"><deny send_destination="{PROTECTED_NAME}"
      send_type="method_call" send_interface="{INTERFACE}" send_member="AliasProbe"/></policy>'''
    replace(directory / "rules.conf", policy(root_uid, "old").replace("</busconfig>", deny + "</busconfig>"))


def alias_hashes(directory):
    return {filename: hashlib.sha256((directory / filename).read_bytes()).hexdigest()
            for filename in ALIAS_FILES}


def alias_raw(message):
    return {"type": message["type"], "flags": message["flags"],
            "serial": message["serial"], "fields": dict(message["fields"]),
            "body_hex": message["body"].hex(), "wire_hex": message["wire_hex"],
            "rights": len(message["fds"]), "sender": message["fields"].get(7),
            "destination": message["fields"].get(6),
            "reply_serial": message["fields"].get(5),
            "signature": message["fields"].get(8, "")}


class AliasClient(Client):
    """Capture complete frames without changing the frozen transport decoder."""
    def __init__(self, path, label, trace):
        try:
            super().__init__(path, label, trace)
        except BaseException:
            if hasattr(self, "sock"):
                self.sock.close()
                trace.append({"event": "socket-closed", "actor": label,
                              "pid": os.getpid(), "uid": os.getuid(), "closed": True,
                              "constructor_failed": True})
            raise

    def read(self, length, fds):
        data = super().read(length, fds)
        self.frame_parts.append(data)
        return data

    def receive(self):
        self.frame_parts = []
        try:
            message = wire.Client.receive(self)
        except BaseException:
            self.trace.append({"event": "receive-failure", "actor": self.label,
                               "wire_hex": b"".join(self.frame_parts).hex()})
            raise
        data = b"".join(self.frame_parts)
        message.update(flags=data[2], wire_hex=data.hex())
        self.trace.append({"event": "receive", "actor": self.label, **alias_raw(message)})
        if message["fds"]:
            wire.close_fds(message["fds"])
            raise AssertionError("alias fixture received prohibited rights")
        assert data[3] == 1, alias_raw(message)
        return message


def alias_bus_reply(client, message, signature):
    ok(message, signature)
    assert message["fields"].get(7) == BUS, alias_raw(message)
    assert message["fields"].get(6) == client.name, alias_raw(message)
    assert not message["fds"], alias_raw(message)
    return message


def alias_text(message):
    value = wire.read_string(message["body"])
    assert message["body"] == wire.string(value), alias_raw(message)
    return value


def alias_identity(client, trace, denials=None):
    identity = next(item for item in trace if item["event"] == "identity")
    identity = dict(identity)
    identity["file_write_denials"] = denials or {}
    return identity


def alias_pump(connection, client, command, trace):
    """Keep pumping after the first fence until the actual response's final fence."""
    first = client.send("GetId")
    final, seen, requests, fences = None, {}, [], []
    deadline = time.monotonic() + 12
    while final is None or first not in seen or final not in seen:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "alias service probe/fence timeout"
        readable, _, _ = select.select([client.sock, connection], [], [], remaining)
        assert readable, "alias service probe/fence timeout"
        for current in readable:
            if current is connection:
                instruction = connection.recv()
                assert instruction == {"op": "finish-probe"}, instruction
                assert final is None, "duplicate final fence"
                # Only the root coordinator can request this fence, after it has
                # received the caller's actual wire response over the Pipe.
                final = client.send("GetId")
                trace.append({"event": "causal-final-fence", "actor": "service",
                              "serial": final, "caller_response_observed": True})
                continue
            message = client.receive()
            reply_serial = message["fields"].get(5)
            if reply_serial in (first, final) and reply_serial is not None:
                alias_bus_reply(client, message, "s")
                assert reply_serial not in seen, "duplicate fence response"
                seen[reply_serial] = alias_raw(message)
            elif message["type"] == 1:
                raw = alias_raw(message)
                requests.append(raw)
                assert message["serial"] == command["caller_serial"], raw
                assert message["fields"].get(1) == "/org/freedesktop/DBus", raw
                assert message["fields"].get(2) == INTERFACE, raw
                assert message["fields"].get(3) == "AliasProbe", raw
                assert message["fields"].get(6) == command["destination"], raw
                assert message["fields"].get(7) == command["caller_name"], raw
                assert message["fields"].get(8) == "s", raw
                assert message["body"] == wire.string(command["marker"]), raw
                client.serial += 1
                data = wire.frame(2, client.serial, [(5, "u", message["serial"]),
                    (6, "s", command["caller_name"]), (8, "g", "s")], message["body"])
                trace.append({"event": "echo", "actor": "service", "serial": client.serial,
                              "reply_serial": message["serial"], "wire_hex": data.hex()})
                client.sock.sendall(data)
            else:
                assert_bus_signal(message)
    fences.extend([seen[first], seen[final]])
    assert len({alias_text_from_raw(item) for item in fences}) == 1, fences
    return {"requests": requests, "deliveries": len(requests), "fences": fences}


def alias_text_from_raw(message):
    body = bytes.fromhex(message["body_hex"])
    value = wire.read_string(body)
    assert body == wire.string(value), message
    return value


def alias_worker(connection, path, role, uid):
    trace, client, failed = [], None, False
    try:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        assert os.getuid() == os.geteuid() == uid
        assert os.getgid() == os.getegid() == uid and os.getgroups() == []
        denials = {}
        for filename in ALIAS_FILES:
            try:
                descriptor = os.open(Path(path).parent.parent / "config" / filename, os.O_WRONLY)
            except PermissionError as failure:
                denials[filename] = failure.errno
                trace.append({"event": "trusted-file-denied", "actor": role,
                              "file": filename, "errno": failure.errno,
                              "uid": os.getuid(), "pid": os.getpid()})
            else:
                os.close(descriptor)
                raise AssertionError(role + " can write trusted " + filename)
        client = AliasClient(path, role, trace)
        ownership = {}
        if role == "service":
            for label, name in [("protected", PROTECTED_NAME), ("alternate", ALTERNATE_NAME)]:
                response = request(client, name)
                alias_bus_reply(client, response, "u")
                assert number(response) == 1, alias_raw(response)
                ownership[label + "_request"] = 1
                ownership[label + "_request_response"] = alias_raw(response)
        connection.send({"event": "ready", "identity": alias_identity(client, trace, denials),
                         "ownership": ownership, "trace": trace})
        trace.clear()
        while True:
            assert connection.poll(30), "alias worker coordinator command timeout"
            command = connection.recv()
            if command["op"] == "stop":
                break
            result = {}
            if role == "caller" and command["op"] == "probe":
                serial = client.send("AliasProbe", "s", wire.string(command["marker"]),
                                     command["destination"], INTERFACE)
                connection.send({"event": "submitted", "caller_serial": serial, "trace": trace})
                trace.clear()
                response = client.reply(serial)
                result = {"response": alias_raw(response)}
            elif role == "service" and command["op"] == "pump":
                result = alias_pump(connection, client, command, trace)
            elif role == "service" and command["op"] == "release":
                response = client.query("ReleaseName", "s", wire.string(PROTECTED_NAME))
                alias_bus_reply(client, response, "u")
                assert number(response) == 1, alias_raw(response)
                result = {"protected_release": 1, "protected_release_response": alias_raw(response)}
            else:
                raise AssertionError(command)
            connection.send({"event": "complete", **result, "trace": trace})
            trace.clear()
    except BaseException as failure:
        failed = True
        connection.send({"event": "failure", "error": repr(failure), "trace": trace})
        raise
    finally:
        try:
            if client is not None:
                client.close()
                receipt = {"event": "socket-closed", "actor": role, "name": client.name,
                           "pid": os.getpid(), "uid": os.getuid(),
                           "closed": client.sock.fileno() == -1, "failed": failed}
                connection.send(receipt)
        finally:
            connection.close()


def alias_receive(connection, trace, event="complete"):
    assert connection.poll(15), "alias worker bounded operation timeout"
    result = connection.recv()
    trace.extend(result.get("trace", []))
    assert result["event"] == event, result
    return result


def alias_cleanup(processes, channels, clients, trace):
    cleanup = {"workers": [], "root_sockets_closed": True}
    for client in clients:
        try:
            client.close()
            cleanup["root_sockets_closed"] &= client.sock.fileno() == -1
            trace.append({"event": "socket-closed", "actor": client.label,
                          "name": client.name, "pid": os.getpid(), "uid": os.getuid(),
                          "closed": client.sock.fileno() == -1})
        except BaseException as failure:
            cleanup["root_sockets_closed"] = False
            trace.append({"event": "cleanup-failure", "error": repr(failure)})
    for role, process in processes:
        channel = channels[role]
        record = {"actor": role, "pid": process.pid, "normal_stop": False,
                  "socket_closed_receipt": None, "terminate": False, "kill": False}
        try:
            channel.send({"op": "stop"})
            deadline = time.monotonic() + 3
            while channel.poll(max(0, deadline - time.monotonic())):
                item = channel.recv()
                trace.extend(item.get("trace", []))
                if item["event"] == "socket-closed":
                    trace.append(item)
                    record["socket_closed_receipt"] = item
                    record["normal_stop"] = item["closed"] and not item["failed"]
                    break
                trace.append({"event": "cleanup-worker-message", "actor": role,
                              "message": {key: value for key, value in item.items() if key != "trace"}})
                if time.monotonic() >= deadline:
                    break
        except (BrokenPipeError, EOFError, OSError) as failure:
            record["channel_error"] = repr(failure)
        finally:
            channel.close()
        process.join(3)
        if process.exitcode is None:
            record["terminate"] = True
            process.terminate()
            process.join(3)
        if process.exitcode is None:
            record["kill"] = True
            process.kill()
            process.join(3)
        record["exitcode"] = process.exitcode
        cleanup["workers"].append(record)
    return cleanup


def run_alias(path, directory, caller_uid, service_uid, backend):
    trace, processes, channels, clients = [], [], {}, []
    summary = {"result": "FAIL", "backend": backend, "scope": "destination-alias",
               "readiness": "L0", "installed_profile_qualified": False,
               "identities": [], "probes": [], "ownership": {}, "trace": trace}
    try:
        assert os.getuid() == os.geteuid() == 0, "BLOCKED_ENV: alias actor requires root"
        assert len({0, caller_uid, service_uid}) == 3, "alias actors require distinct kernel UIDs"
        assert Path(path) == prepared_socket(directory), "alias fixture socket must match prepared path"
        summary["config_hashes_before"] = alias_hashes(directory)
        # All privilege-dropped workers are forked before the coordinator opens
        # any root socket, so neither child inherits root bus authority.
        for role, uid in [("service", service_uid), ("caller", caller_uid)]:
            parent, child = multiprocessing.Pipe()
            process = multiprocessing.Process(target=alias_worker, args=(child, path, role, uid))
            process.start()
            child.close()
            processes.append((role, process))
            channels[role] = parent
        for role, process in processes:
            ready = alias_receive(channels[role], trace, "ready")
            identity = ready["identity"]
            assert identity["pid"] == process.pid
            assert identity["uid"] == identity["gid"] == (service_uid if role == "service" else caller_uid)
            assert identity["groups"] == [] and set(identity["file_write_denials"]) == set(ALIAS_FILES)
            summary["identities"].append(identity)
            summary["ownership"].update(ready["ownership"])
        observer = AliasClient(path, "observer", trace)
        clients.append(observer)
        observer_identity = dict(next(item for item in trace
                                     if item["event"] == "identity" and item["actor"] == "observer"))
        observer_identity["file_write_denials"] = {}
        summary["identities"].append(observer_identity)
        for identity in summary["identities"]:
            proof = {}
            for method, key in [("GetConnectionUnixUser", "bus_uid"),
                                ("GetConnectionUnixProcessID", "bus_pid")]:
                response = observer.query(method, "s", wire.string(identity["name"]))
                alias_bus_reply(observer, response, "u")
                identity[key] = number(response)
                proof[key] = alias_raw(response)
            identity["bus_identity_responses"] = proof
            assert identity["bus_uid"] == identity["uid"]
            assert identity["bus_pid"] == identity["pid"]
        service_name = summary["identities"][0]["name"]
        caller_name = summary["identities"][1]["name"]

        def bus_id():
            response = observer.query("GetId")
            alias_bus_reply(observer, response, "s")
            return alias_text(response)

        summary["bus_id"] = summary["bus_ids_before"] = bus_id()
        ownership = summary["ownership"]
        for label, name in [("protected", PROTECTED_NAME), ("alternate", ALTERNATE_NAME)]:
            response = observer.query("GetNameOwner", "s", wire.string(name))
            alias_bus_reply(observer, response, "s")
            ownership[label + "_owner"] = alias_text(response)
            ownership[label + "_owner_response"] = alias_raw(response)
            assert ownership[label + "_owner"] == service_name

        for phase, destinations in [
                ("protected-owned", [("protected", PROTECTED_NAME), ("unique", service_name),
                                     ("alternate", ALTERNATE_NAME)]),
                ("protected-released", [("unique", service_name), ("alternate", ALTERNATE_NAME)])]:
            if phase == "protected-released":
                channels["service"].send({"op": "release"})
                ownership.update({key: value for key, value in alias_receive(channels["service"], trace).items()
                                  if key not in ("event", "trace")})
                response = observer.query("GetNameOwner", "s", wire.string(PROTECTED_NAME))
                ownership["protected_after_response"] = alias_raw(response)
                error(response, "NameHasNoOwner")
                assert response["fields"].get(7) == BUS and response["fields"].get(6) == observer.name
                assert response["fields"].get(8) == "s"
                alias_text(response)
                ownership["protected_after_error"] = response["fields"][4]
                response = observer.query("GetNameOwner", "s", wire.string(ALTERNATE_NAME))
                alias_bus_reply(observer, response, "s")
                ownership["alternate_after_owner"] = alias_text(response)
                ownership["alternate_after_response"] = alias_raw(response)
                assert ownership["alternate_after_owner"] == service_name
                summary["config_hashes_release"] = alias_hashes(directory)
                assert summary["config_hashes_release"] == summary["config_hashes_before"]
                summary["bus_ids_release"] = bus_id()
                assert summary["bus_ids_release"] == summary["bus_id"]
            for kind, destination in destinations:
                marker = f"AliasProbe:{phase}:{kind}:{os.getpid()}:{len(summary['probes'])}"
                probe_result = {"phase": phase, "destination_kind": kind, "destination": destination,
                                "marker": marker, "allowed": None, "deliveries": None,
                                "error_name": None}
                summary["probes"].append(probe_result)
                channels["caller"].send({"op": "probe", "destination": destination, "marker": marker})
                submitted = alias_receive(channels["caller"], trace, "submitted")
                serial = submitted["caller_serial"]
                probe_result["caller_serial"] = serial
                channels["service"].send({"op": "pump", "caller_serial": serial,
                    "destination": destination, "caller_name": caller_name, "marker": marker})
                response = alias_receive(channels["caller"], trace)["response"]
                probe_result["response"] = response
                trace.append({"event": "caller-response-observed", "caller_serial": serial,
                              "phase": phase, "destination": destination})
                channels["service"].send({"op": "finish-probe"})
                pumped = alias_receive(channels["service"], trace)
                probe_result.update({key: pumped[key] for key in ("deliveries", "requests", "fences")})
                allowed = response["type"] == 2
                probe_result["allowed"] = allowed
                probe_result["error_name"] = response["fields"].get(4)
                assert response["reply_serial"] == serial and response["destination"] == caller_name
                assert response["rights"] == 0 and response["signature"] == "s"
                alias_text_from_raw(response)
                if phase == "protected-owned":
                    assert response["type"] == 3 and not allowed
                    assert response["sender"] == BUS
                    assert probe_result["error_name"] == BUS + ".Error.AccessDenied", response
                    assert pumped["deliveries"] == 0, "denied alias payload reached service"
                else:
                    assert response["type"] == 2 and allowed and response["sender"] == service_name
                    assert response["body_hex"] == wire.string(marker).hex()
                    assert pumped["deliveries"] == 1, "allowed alias requires exactly one service echo"
                assert all(alias_text_from_raw(fence) == summary["bus_id"] for fence in pumped["fences"])
                trace.append({"event": "probe", **probe_result})
        summary["config_hashes_after"] = alias_hashes(directory)
        assert summary["config_hashes_after"] == summary["config_hashes_before"]
        summary["bus_ids_after"] = bus_id()
        assert summary["bus_ids_after"] == summary["bus_id"]
        summary["result"] = "PASS"
    except BaseException as failure:
        summary["error"] = repr(failure)
    finally:
        summary["cleanup"] = alias_cleanup(processes, channels, clients, trace)
        cleanup = summary["cleanup"]
        if not cleanup["root_sockets_closed"] or len(cleanup["workers"]) != 2 or any(
                item["exitcode"] != 0 or not item["normal_stop"] or not item["socket_closed_receipt"]
                or item["terminate"] or item["kill"] for item in cleanup["workers"]):
            summary["result"] = "FAIL"
            summary.setdefault("error", "alias worker cleanup did not complete normally")
        try:
            summary["config_hashes_after"] = alias_hashes(directory)
            if summary["config_hashes_after"] != summary.get("config_hashes_before"):
                summary["result"] = "FAIL"
                summary.setdefault("error", "trusted alias XML hashes changed")
        except BaseException as failure:
            summary["result"] = "FAIL"
            summary["hash_error"] = repr(failure)
    return summary


def alias_reference(daemon, directory, caller_uid, service_uid):
    # Deliberately do not prepare or replace any XML: both backends consume the
    # same three immutable files and the same socket path prepared once.
    result, process = None, None
    daemon_cleanup = {"normal_stop": False, "terminate": False, "kill": False, "exitcode": None}
    with (directory / "alias-reference.stderr").open("w") as stderr:
        try:
            process = subprocess.Popen([daemon, "--config-file=" + str(directory / "bus.conf"),
                "--nofork", "--print-address"], stdout=subprocess.PIPE, stderr=stderr)
            address_bytes, deadline = b"", time.monotonic() + 5
            while not address_bytes.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                assert remaining > 0 and select.select([process.stdout], [], [], remaining)[0], \
                    "private alias reference startup timeout"
                chunk = os.read(process.stdout.fileno(), 1)
                assert chunk and len(address_bytes) < 4096, "private alias reference missing address"
                address_bytes += chunk
            address = address_bytes.decode().strip()
            assert address.split(",", 1)[0] == "unix:path=" + str(prepared_socket(directory)), address
            prepared_socket(directory).chmod(0o666)
            result = run_alias(str(prepared_socket(directory)), directory, caller_uid, service_uid, "reference")
            result["daemon_address"] = address
            result["daemon_sha256"] = hashlib.sha256(Path(daemon).read_bytes()).hexdigest()
        except BaseException as failure:
            if result is None:
                result = {"result": "FAIL", "backend": "reference", "scope": "destination-alias",
                          "installed_profile_qualified": False, "readiness": "L0", "trace": [], "cleanup": {}}
            result["result"], result["error"] = "FAIL", repr(failure)
        finally:
            if process is not None:
                daemon_cleanup["pid"] = process.pid
                if process.poll() is None:
                    daemon_cleanup["terminate"] = True
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        daemon_cleanup["kill"] = True
                        process.kill()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired as failure:
                            daemon_cleanup["reap_error"] = repr(failure)
                    daemon_cleanup["normal_stop"] = not daemon_cleanup["kill"] and process.returncode in (0, -15)
                daemon_cleanup["exitcode"] = process.returncode
                process.stdout.close()
            result["cleanup"]["daemon"] = daemon_cleanup
            if not daemon_cleanup["normal_stop"]:
                result["result"] = "FAIL"
                result.setdefault("error", "private alias reference daemon did not stop normally")
    return result


PROPERTIES = BUS + ".Properties"
PROPERTY_SENTINEL = "foundation-property-set-sentinel"
PROPERTY_READ_ONLY = BUS + ".Error.PropertyReadOnly"


def prepare_properties(directory, root_uid, caller_uid):
    assert os.getuid() == root_uid == 0, "properties fixture requires a root coordinator"
    prepare(directory, root_uid, caller_uid)


def properties_strings(*items):
    body = b""
    for item in items:
        body += wire.padding(len(body), 4) + wire.string(item)
    return body


def properties_variant_strings(items, prefix=b""):
    body = prefix + b"\x02as\0"
    body += wire.padding(len(body), 4)
    contents = properties_strings(*items)
    return body + wire.u32(len(contents)) + contents


def properties_features(message):
    body = message["body"]
    assert body[:4] == b"\x02as\0", alias_raw(message)
    length = struct.unpack_from("<I", body, 4)[0]
    offset, end, features = 8, 8 + length, []
    assert end == len(body), alias_raw(message)
    while offset < end:
        offset += -offset % 4
        size = struct.unpack_from("<I", body, offset)[0]
        assert offset + 5 + size <= end and body[offset + 4 + size] == 0, alias_raw(message)
        features.append(body[offset + 4:offset + 4 + size].decode())
        offset += 5 + size
    assert offset == end and body == properties_variant_strings(features), alias_raw(message)
    return features


def properties_query(client, member, signature="", body=b"", interface=BUS, result=None):
    def expired(_signum, _frame):
        raise TimeoutError("properties query exceeded its 12s deadline")

    # These isolated Linux actor processes run their queries on the main thread.
    # The timer also bounds a fragmented frame inside the frozen wire reader.
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    previous_handler = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, 12)
        serial = client.send(member, signature, body, interface=interface)
        if result is not None and member == "Set":
            result["set_request"] = dict(client.trace[-1])
        deadline = time.monotonic() + 12
        while True:
            remaining = deadline - time.monotonic()
            assert remaining > 0 and select.select([client.sock], [], [], remaining)[0], \
                "properties query exceeded its 12s deadline"
            message = client.receive()
            if message["fields"].get(5) == serial:
                return message
            assert_bus_signal(message)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)


def properties_sequence(client, trace):
    result = {"sentinel": PROPERTY_SENTINEL, "set_advertised": False,
              "set_expected_error": PROPERTY_READ_ONLY, "set_actual_error": None,
              "unchanged": False, "contract_failures": []}

    def operation(label, member, signature="", body=b"", interface=BUS, check=None):
        try:
            response = properties_query(client, member, signature, body, interface, result)
            result[label + "_response"] = alias_raw(response)
            assert response["fields"].get(7) == BUS, alias_raw(response)
            assert response["fields"].get(6) == client.name, alias_raw(response)
            if check is not None:
                check(response)
        except BaseException as failure:
            result["contract_failures"].append({"operation": label, "error": repr(failure)})

    def introspection(response):
        alias_bus_reply(client, response, "s")
        node = ET.fromstring(alias_text(response))
        method = node.find("interface[@name='org.freedesktop.DBus.Properties']/method[@name='Set']")
        assert method is not None, "Properties.Set is not advertised"
        inputs = [arg.attrib["type"] for arg in method.findall("arg")
                  if arg.attrib.get("direction", "in") == "in"]
        outputs = [arg for arg in method.findall("arg") if arg.attrib.get("direction") == "out"]
        assert inputs == ["s", "s", "v"] and not outputs, "Properties.Set must advertise ssv"
        feature = node.find("interface[@name='org.freedesktop.DBus']/property[@name='Features']")
        assert feature is not None and feature.attrib.get("type") == "as" \
            and feature.attrib.get("access") == "read", "Features must advertise read-only as"
        result["set_advertised"] = True

    def features(label, response):
        alias_bus_reply(client, response, "v")
        result[label] = properties_features(response)
        assert PROPERTY_SENTINEL not in result[label], "sentinel appeared in Features"

    def set_result(response):
        result["set_actual_error"] = response["fields"].get(4)
        assert response["fields"].get(8) == "s", alias_raw(response)
        result["set_error_body"] = alias_text(response)
        error(response, "PropertyReadOnly")

    def health(response):
        alias_bus_reply(client, response, "s")
        result["bus_id"] = alias_text(response)
        assert len(result["bus_id"]) == 32, alias_raw(response)

    operation("introspection", "Introspect", interface=BUS + ".Introspectable", check=introspection)
    get_body = properties_strings(BUS, "Features")
    operation("features_before", "Get", "ss", get_body, PROPERTIES,
              lambda response: features("features_before", response))
    operation("set", "Set", "ssv", properties_variant_strings([PROPERTY_SENTINEL], get_body),
              PROPERTIES, set_result)
    # A wrong Set error is evidence, not a reason to lose the after-read/health
    # or to replace the expected read-only contract with the observed error.
    operation("features_after", "Get", "ss", get_body, PROPERTIES,
              lambda response: features("features_after", response))
    operation("get_id", "GetId", check=health)
    if "features_before" in result and "features_after" in result:
        result["unchanged"] = result["features_before"] == result["features_after"]
    if not result["unchanged"]:
        result["contract_failures"].append({"operation": "features_after", "error": "Features changed or unavailable"})
    trace.append({"event": "properties-contract", "result": "FAIL" if result["contract_failures"] else "PASS"})
    return result


def getall_dictionary(message):
    """Decode only the physical a{sv}/variant-as contract used by this case."""
    body, offset = message["body"], 0

    def take(size, end):
        nonlocal offset
        assert 0 <= size <= end - offset, "GetAll field exceeds its container"
        value = body[offset:offset + size]
        offset += size
        return value

    def align(boundary, end):
        padding = -offset % boundary
        assert take(padding, end) == bytes(padding), "GetAll contains nonzero padding"

    def uint32(end):
        align(4, end)
        return struct.unpack("<I", take(4, end))[0]

    def string(end):
        size = uint32(end)
        value = take(size, end)
        assert take(1, end) == b"\0" and b"\0" not in value, "GetAll string has invalid NUL"
        return value.decode("utf-8")

    size = uint32(len(body))
    align(8, len(body))
    end = offset + size
    assert end <= len(body), "GetAll dictionary exceeds its body"
    properties = {}
    while offset < end:
        align(8, end)
        name = string(end)
        assert name not in properties, "GetAll contains a duplicate property"
        signature = take(take(1, end)[0], end)
        assert take(1, end) == b"\0" and signature == b"as", "GetAll variant must contain as"
        size = uint32(end)
        strings_end = offset + size
        assert strings_end <= end, "GetAll string array exceeds its dictionary"
        values = []
        while offset < strings_end:
            values.append(string(strings_end))
        assert offset == strings_end, "GetAll string array was not fully consumed"
        properties[name] = {"signature": "as", "value": values}
    assert offset == end == len(body), "GetAll dictionary was not fully consumed"
    return properties


def getall_sequence(client, trace):
    result = {"consistent": False, "unknown_interface_expected_error": BUS + ".Error.UnknownInterface",
              "unknown_interface_actual_error": None, "contract_failures": []}

    def operation(label, member, signature="", body=b"", interface=PROPERTIES, check=None):
        try:
            response = properties_query(client, member, signature, body, interface)
            result[label + "_response"] = alias_raw(response)
            assert response["fields"].get(7) == BUS, alias_raw(response)
            assert response["fields"].get(6) == client.name, alias_raw(response)
            if check is not None:
                check(response)
        except BaseException as failure:
            result["contract_failures"].append({"operation": label, "error": repr(failure)})

    def strings(label, response):
        alias_bus_reply(client, response, "v")
        result[label] = properties_features(response)

    def bus(response):
        alias_bus_reply(client, response, "a{sv}")
        result["bus_properties"] = getall_dictionary(response)
        expected = {name: {"signature": "as", "value": result.get(label)}
                    for name, label in [("Features", "features"), ("Interfaces", "interfaces")]}
        result["consistent"] = result["bus_properties"] == expected
        assert result["consistent"], "GetAll bus properties differ from this backend's Get values"

    def peer(response):
        alias_bus_reply(client, response, "a{sv}")
        result["peer_properties"] = getall_dictionary(response)
        assert result["peer_properties"] == {}, "Peer GetAll must return an empty dictionary"

    def unknown(response):
        result["unknown_interface_actual_error"] = response["fields"].get(4)
        assert response["fields"].get(8) == "s", alias_raw(response)
        result["unknown_interface_error_body"] = alias_text(response)
        error(response, "UnknownInterface")

    def health(response):
        alias_bus_reply(client, response, "s")
        result["bus_id"] = alias_text(response)
        assert len(result["bus_id"]) == 32, alias_raw(response)

    for label, name in [("features", "Features"), ("interfaces", "Interfaces")]:
        operation(label, "Get", "ss", properties_strings(BUS, name),
                  check=lambda response, label=label: strings(label, response))
    operation("bus", "GetAll", "s", wire.string(BUS), check=bus)
    operation("peer", "GetAll", "s", wire.string(BUS + ".Peer"), check=peer)
    operation("unknown_interface", "GetAll", "s", wire.string("org.foundation.UnknownInterface"), check=unknown)
    operation("get_id", "GetId", interface=BUS, check=health)
    trace.append({"event": "getall-contract", "result": "FAIL" if result["contract_failures"] else "PASS"})
    return result


API_PATHS = ("/org/freedesktop/DBus", "/", "/org", "/org/freedesktop", "/unrelated")
API_PEER = BUS + ".Peer"
API_INTROSPECT = BUS + ".Introspectable"
API_MONITOR = BUS + ".Monitoring"
API_OPERATION_COUNTS = {"ordinary": 212, "root": 22}
# Frozen common legacy surface; audit/SELinux methods are reference-only.
API_METHODS = {
    "Hello": ("", "s"), "RequestName": ("su", "u"), "ReleaseName": ("s", "u"),
    "StartServiceByName": ("su", "u"), "UpdateActivationEnvironment": ("a{ss}", ""),
    "NameHasOwner": ("s", "b"), "ListNames": ("", "as"),
    "ListActivatableNames": ("", "as"), "AddMatch": ("s", ""), "RemoveMatch": ("s", ""),
    "GetNameOwner": ("s", "s"), "ListQueuedOwners": ("s", "as"),
    "GetConnectionUnixUser": ("s", "u"), "GetConnectionUnixProcessID": ("s", "u"),
    "ReloadConfig": ("", ""), "GetId": ("", "s"), "GetConnectionCredentials": ("s", "a{sv}")}


class ApiClient(AliasClient):
    def __init__(self, path, label, trace, hello=True, deadline=None):
        self.label, self.trace, self.serial = label, trace, 0
        constructor_budget = 12 if deadline is None else min(12, deadline - time.monotonic())
        assert constructor_budget > 0, "API constructor absolute deadline exceeded"
        def expired(_signum, _frame):
            raise TimeoutError("API auth/Hello constructor deadline exceeded")
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        previous_handler = signal.signal(signal.SIGALRM, expired)
        try:
            signal.setitimer(signal.ITIMER_REAL, constructor_budget)
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(3)
            self.sock.connect(path)
            self.sock.sendall(b"\0AUTH EXTERNAL " + str(os.getuid()).encode().hex().encode() + b"\r\n")
            authenticated = self.line()
            assert authenticated.startswith(b"OK "), authenticated
            trace.append({"event": "authenticated", "actor": label, "auth_guid": authenticated[3:].strip().decode()})
            self.sock.sendall(b"BEGIN\r\n")
            if not hello:
                return
            serial = self.send("Hello")
            response = self.reply(serial)
            ok(response, "s")
            self.name = alias_text(response)
            assert response["fields"].get(7) == BUS, alias_raw(response)
            trace.append({"event": "identity", "actor": label, "name": self.name,
                          "pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(),
                          "hello_path": API_PATHS[0], "hello_interface": BUS})
        except BaseException:
            if hasattr(self, "sock"):
                self.sock.close()
                trace.append({"event": "socket-closed", "actor": label, "pid": os.getpid(),
                              "uid": os.getuid(), "closed": True, "constructor_failed": True})
            raise
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_handler)
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)

    def send(self, member, signature="", body=b"", destination=BUS, interface=BUS,
             path=API_PATHS[0], flags=0):
        self.serial += 1
        fields = [(1, "o", path), (3, "s", member), (6, "s", destination), (8, "g", signature)]
        if interface is not None:
            fields.insert(1, (2, "s", interface))
        data = wire.frame(1, self.serial, fields, body, flags=flags)
        self.trace.append({"event": "call", "actor": self.label, "serial": self.serial,
                           "member": member, "destination": destination, "interface": interface,
                           "path": path, "flags": flags, "signature": signature,
                           "body_hex": body.hex(), "wire_hex": data.hex()})
        self.sock.sendall(data)
        return self.serial


def api_query(client, row, deadline):
    remaining = min(12, deadline - time.monotonic())
    assert remaining > 0, "API absolute 90s deadline exceeded"
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    def expired(_signum, _frame):
        raise TimeoutError("API query deadline exceeded")
    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, remaining)
        client.send(row["member"], row["signature"], bytes.fromhex(row["body_hex"]),
                    interface=row["interface"], path=row["path"], flags=row.get("flags", 0))
        row["request"] = dict(client.trace[-1])
        serial = client.serial
        if row.get("flags", 0) & 1:
            barrier = client.send("GetId")
            row["barrier_request"] = dict(client.trace[-1])
            row["suppressed_replies"] = []
        else:
            barrier = None
        while True:
            message = client.receive()
            reply_serial = message["fields"].get(5)
            if reply_serial == serial:
                row["response"] = alias_raw(message)
                if barrier is None:
                    return message
                row["suppressed_replies"].append(alias_raw(message))
                continue
            if barrier is not None and reply_serial == barrier:
                row["barrier_response"] = alias_raw(message)
                alias_bus_reply(client, message, "s")
                assert not row["suppressed_replies"], "NO_REPLY_EXPECTED produced a physical reply"
                return message
            assert_bus_signal(message)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def api_xml(message, path, backend):
    node = ET.fromstring(alias_text(message))
    assert node.tag == "node", "introspection root is not a node"
    interfaces = {item.attrib["name"]: item for item in node.findall("interface")}
    assert len(interfaces) == len(node.findall("interface")), "duplicate XML interface"
    required = {BUS, API_PEER, API_INTROSPECT}
    if path == API_PATHS[0]:
        required.add(PROPERTIES)
    assert required <= set(interfaces), (path, "missing interfaces", sorted(required - set(interfaces)))
    if backend == "candidate" or path != API_PATHS[0]:
        assert set(interfaces) == required, (path, "unexpected interfaces", sorted(set(interfaces) - required))
    children = [child.attrib["name"] for child in node.findall("node")]
    assert children == {"/": ["org/freedesktop/DBus"], "/org": ["freedesktop/DBus"],
                        "/org/freedesktop": ["DBus"]}.get(path, []), (path, children)
    schemas = {BUS: API_METHODS, API_PEER: {"Ping": ("", ""), "GetMachineId": ("", "s")},
               API_INTROSPECT: {"Introspect": ("", "s")}}
    if PROPERTIES in required:
        schemas[PROPERTIES] = {"Get": ("ss", "v"), "GetAll": ("s", "a{sv}"), "Set": ("ssv", "")}
    for interface, methods in schemas.items():
        for member, (inputs, outputs) in methods.items():
            found = interfaces[interface].findall("method[@name='" + member + "']")
            assert len(found) == 1, (path, interface, member, "missing or duplicate method")
            args = found[0].findall("arg")
            assert all(arg.attrib.get("direction") in ("in", "out") for arg in args), (member, "missing direction")
            assert "".join(arg.attrib["type"] for arg in args if arg.attrib["direction"] == "in") == inputs, member
            assert "".join(arg.attrib["type"] for arg in args if arg.attrib["direction"] == "out") == outputs, member
    signals = {BUS: {"NameOwnerChanged": "sss", "NameLost": "s", "NameAcquired": "s"}}
    if PROPERTIES in required:
        signals[PROPERTIES] = {"PropertiesChanged": "sa{sv}as"}
    for interface, members in signals.items():
        for member, signature in members.items():
            found = interfaces[interface].findall("signal[@name='" + member + "']")
            assert len(found) == 1, (path, interface, member)
            assert "".join(arg.attrib["type"] for arg in found[0].findall("arg")) == signature, member
    for name in ("Features", "Interfaces"):
        found = interfaces[BUS].findall("property[@name='" + name + "']")
        assert len(found) == 1 and found[0].attrib.get("type") == "as" and found[0].attrib.get("access") == "read", name
        annotations = found[0].findall("annotation[@name='org.freedesktop.DBus.Property.EmitsChangedSignal']")
        assert len(annotations) == 1 and annotations[0].attrib.get("value") == "const", (name, "const annotation missing")
    return {"interfaces": sorted(interfaces), "children": children, "xml": alias_text(message)}


def api_rows(backend, privileged=False):
    rows = []
    def add(label, member, signature="", body=b"", interface=BUS, path=API_PATHS[0],
            expected="", check=None, flags=0):
        rows.append({"label": label, "member": member, "signature": signature,
                     "body_hex": body.hex(), "interface": interface, "path": path,
                     "expected": expected, "check": check, "flags": flags})
    wrong = lambda schema: ("s", wire.string("bad")) if not schema else ("", b"")
    if privileged:
        for member, (schema, _output) in API_METHODS.items():
            signature, body = wrong(schema)
            add("root-wrong-" + member, member, signature, body, expected="error:InvalidArgs")
        add("root-reload-offpath", "ReloadConfig", path="/unrelated")
        for signature, body, suffix in [("", b"", "wrong"), ("a{ss}", wire.u32(0) + bytes(4), "valid")]:
            add("root-environment-offpath-" + suffix, "UpdateActivationEnvironment", signature, body,
                path="/unrelated", expected="error:AccessDenied")
        add("root-monitor-wrong-signature", "BecomeMonitor", interface=API_MONITOR,
            expected="error:InvalidArgs")
        body = wire.string("org.foundation.API.AbsentService")
        body += wire.padding(len(body), 4) + wire.u32(0)
        add("root-start-absent", "StartServiceByName", "su", body, path="/unrelated",
            expected="error:" + ("NotSupported" if backend == "candidate" else "ServiceUnknown"))
        return rows
    for index, path in enumerate(API_PATHS):
        for style in ("explicit", "omitted"):
            add(f"fresh-hello-{index}-{style}", "Hello", interface=BUS if style == "explicit" else None,
                path=path, expected="s", check="freshhello")
            for member, interface, signature, check in [
                    ("Introspect", API_INTROSPECT, "s", "xml"), ("Ping", API_PEER, "", None),
                    ("GetMachineId", API_PEER, "s", "machine"), ("GetId", BUS, "s", "id"),
                    ("ListNames", BUS, "as", "names"), ("ListActivatableNames", BUS, "as", "activatable")]:
                add(f"path-{index}-{style}-{member}", member,
                    interface=interface if style == "explicit" else None, path=path, expected=signature, check=check)
        for suffix, member, interface, failure in [
                ("unknown-interface", "ListNames", "org.foundation.UnknownInterface", "UnknownInterface"),
                ("bus-unknown-member", "AbsentMember", BUS, "UnknownMethod"),
                ("peer-unknown-member", "AbsentMember", API_PEER, "UnknownMethod"),
                ("introspect-unknown-member", "AbsentMember", API_INTROSPECT, "UnknownMethod"),
                ("omitted-unknown-member", "AbsentMember", None, "UnknownMethod"),
                ("properties-unknown-member", "AbsentMember", PROPERTIES,
                 "UnknownMethod" if index == 0 else "UnknownInterface"),
                ("omitted-Get", "Get", None, "InvalidArgs" if index == 0 else "UnknownMethod")]:
            add(f"path-{index}-{suffix}", member, interface=interface, path=path, expected="error:" + failure)
        add(f"path-{index}-monitor-unknown-member", "AbsentMember", interface=API_MONITOR, path=path,
            expected="error:" + ("UnknownMethod" if index == 0 else "UnknownInterface"))
    for path_index, path in enumerate((API_PATHS[0], "/unrelated")):
        for member, (schema, _output) in API_METHODS.items():
            if member in ("ReloadConfig", "UpdateActivationEnvironment"):
                continue
            signature, body = wrong(schema)
            add(f"wrong-{path_index}-{member}", member, signature, body, path=path, expected="error:InvalidArgs")
        for member, interface in [("Ping", API_PEER), ("GetMachineId", API_PEER), ("Introspect", API_INTROSPECT)]:
            add(f"wrong-{path_index}-{member}", member, "s", wire.string("bad"), interface, path, expected="error:InvalidArgs")
    for member, interface in [("Get", PROPERTIES), ("Set", PROPERTIES), ("GetAll", PROPERTIES), ("BecomeMonitor", API_MONITOR)]:
        add("offpath-wrong-" + member, member, interface=interface, path="/unrelated", expected="error:UnknownInterface")
    for path_index, path in enumerate((API_PATHS[0], "/unrelated")):
        add(f"denied-reload-{path_index}", "ReloadConfig", path=path, expected="error:AccessDenied")
        for signature, body, suffix in [("", b"", "wrong"), ("a{ss}", wire.u32(0) + bytes(4), "valid")]:
            add(f"denied-environment-{path_index}-{suffix}", "UpdateActivationEnvironment", signature, body,
                path=path, expected="error:AccessDenied")
    for signature, body, suffix in [("", b"", "wrong"), ("asu", wire.u32(0) + wire.u32(0), "valid")]:
        add("denied-monitor-" + suffix, "BecomeMonitor", signature, body, API_MONITOR, expected="error:AccessDenied")
    name, rule = "org.foundation.API.Transient", "type='signal',interface='org.foundation.API.Probe'"
    encoded_name = wire.string(name)
    add("offpath-request-name", "RequestName", "su", encoded_name + wire.padding(len(encoded_name), 4) + wire.u32(0),
        path="/unrelated", expected="u", check="one")
    for member, signature, check in [("NameHasOwner", "b", "true"), ("GetNameOwner", "s", "owner"),
                                      ("ListQueuedOwners", "as", "owners")]:
        add("offpath-" + member, member, "s", encoded_name, path="/unrelated", expected=signature, check=check)
    for member, signature in [("GetConnectionUnixUser", "u"), ("GetConnectionUnixProcessID", "u"),
                              ("GetConnectionCredentials", "a{sv}")]:
        add("offpath-" + member, member, "s", wire.string(BUS), path="/unrelated", expected=signature)
    for member in ("AddMatch", "RemoveMatch"):
        add("offpath-" + member, member, "s", wire.string(rule), path="/unrelated")
    add("offpath-release-name", "ReleaseName", "s", encoded_name, path="/unrelated", expected="u", check="one")
    absent = wire.string("org.foundation.API.AbsentService")
    add("offpath-start-absent", "StartServiceByName", "su", absent + wire.padding(len(absent), 4) + wire.u32(0),
        path="/unrelated", expected="error:" + ("NotSupported" if backend == "candidate" else "ServiceUnknown"))
    for member, bad_args in [("Get", [("", b""), ("s", wire.string(BUS))]),
                              ("Set", [("", b""), ("ss", properties_strings(BUS, "Features"))]),
                              ("GetAll", [("", b""), ("ss", properties_strings(BUS, "Features"))])]:
        for index, (signature, body) in enumerate(bad_args):
            add(f"properties-wrong-{member}-{index}", member, signature, body, PROPERTIES, expected="error:InvalidArgs")
    def property_calls(label, target, prop, get_error, set_error, all_error=None):
        prefix = properties_strings(target, prop)
        add(label + "-Get", "Get", "ss", prefix, PROPERTIES, expected="error:" + get_error)
        add(label + "-Set", "Set", "ssv", properties_variant_strings([], prefix), PROPERTIES, expected="error:" + set_error)
        if all_error is not None:
            add(label + "-GetAll", "GetAll", "s", wire.string(target), PROPERTIES,
                expected="error:" + all_error if all_error else "a{sv}", check=None if all_error else "empty")
    property_calls("unknown-interface", "org.foundation.UnknownInterface", "Absent", "UnknownInterface", "UnknownInterface", "UnknownInterface")
    property_calls("unknown-property", BUS, "Absent", "UnknownProperty", "UnknownProperty")
    for interface in (API_PEER, API_INTROSPECT, PROPERTIES):
        property_calls("propertyless-" + interface, interface, "Absent", "UnknownProperty", "UnknownProperty", "")
    for name in ("Features", "Interfaces"):
        prefix = properties_strings(BUS, name)
        for phase in ("before", "after"):
            if phase == "after":
                for kind in ("as", "s", "u"):
                    if kind == "as":
                        body = properties_variant_strings([PROPERTY_SENTINEL], prefix)
                    else:
                        body = prefix + bytes([len(kind)]) + kind.encode() + b"\0"
                        body += wire.padding(len(body), 4) + (wire.string(PROPERTY_SENTINEL) if kind == "s" else wire.u32(17))
                    add(f"readonly-{name}-{kind}", "Set", "ssv", body, PROPERTIES, expected="error:PropertyReadOnly")
            add(f"property-{name}-{phase}", "Get", "ss", prefix, PROPERTIES, expected="v", check="property")
    for phase in ("before", "after"):
        add("property-all-" + phase, "GetAll", "s", wire.string(BUS), PROPERTIES, expected="a{sv}", check="all")
    if backend == "reference":
        property_calls("empty-interface", "", "Features", "UnknownInterface", "UnknownInterface", "UnknownInterface")
    else:
        add("empty-interface-Get", "Get", "ss", properties_strings("", "Features"), PROPERTIES, expected="v", check="empty-target-get")
        add("empty-interface-Set", "Set", "ssv", properties_variant_strings([], properties_strings("", "Features")), PROPERTIES, expected="error:PropertyReadOnly")
        add("empty-interface-GetAll", "GetAll", "s", wire.string(""), PROPERTIES, expected="a{sv}", check="all")
    for member, signature, body in [("Get", "ss", properties_strings(BUS, "Features")),
                                    ("GetAll", "s", wire.string(BUS)),
                                    ("Set", "ssv", properties_variant_strings([], properties_strings(BUS, "Features")))]:
        for style in ("explicit", "omitted"):
            add(f"offpath-properties-{member}-{style}", member, signature, body,
                PROPERTIES if style == "explicit" else None, "/unrelated",
                expected="error:" + ("UnknownInterface" if style == "explicit" else "UnknownMethod"))
    for member, interface in [("Ping", API_PEER), ("AbsentMember", BUS)]:
        add("no-reply-" + member, member, interface=interface, expected="s", check="id", flags=1)
    return rows


def api_sequence(client, trace, backend, deadline, privileged=False):
    rows = api_rows(backend, privileged)
    assert len(rows) == API_OPERATION_COUNTS["root" if privileged else "ordinary"], "API row inventory changed"
    result = {"operation_count": len(rows), "operation_labels": [row["label"] for row in rows],
              "rows": rows, "bus_ids": [], "machine_ids": [], "properties": {}, "contract_failures": []}
    machine_paths = (Path("/var/lib/dbus/machine-id"), Path("/etc/machine-id"))
    machine_path = next((path for path in machine_paths if path.is_file()), None)
    trusted_machine = machine_path.read_text().strip() if machine_path is not None else None
    result["trusted_machine"] = {"path": str(machine_path), "value": trusted_machine,
                                  "sha256": hashlib.sha256(machine_path.read_bytes()).hexdigest() if machine_path else None}
    for row in rows:
        row["result"] = "FAIL"
        fresh = None
        try:
            current = client
            if row["check"] == "freshhello":
                fresh = ApiClient(client.sock.getpeername(), "fresh-" + row["label"], trace, hello=False, deadline=deadline)
                current = fresh
            response = api_query(current, row, deadline)
            expected = row["expected"]
            if row["check"] == "freshhello":
                ok(response, "s")
                fresh.name = alias_text(response)
            assert response["fields"].get(7) == BUS and response["fields"].get(6) == current.name, alias_raw(response)
            if expected.startswith("error:"):
                error(response, expected.split(":", 1)[1])
                assert response["fields"].get(8) == "s", alias_raw(response)
                row["error_body"] = alias_text(response)
            else:
                alias_bus_reply(current, response, expected)
            check = row["check"]
            if check == "freshhello":
                row["fresh_identity"] = {"name": fresh.name, "pid": os.getpid(), "uid": os.getuid(),
                                         "gid": os.getgid(), "groups": os.getgroups()}
                barrier = {"member": "GetId", "signature": "", "body_hex": "", "interface": BUS, "path": API_PATHS[0]}
                barrier_response = api_query(fresh, barrier, deadline)
                row["hello_barrier_request"] = barrier["request"]
                row["hello_barrier_response"] = alias_raw(barrier_response)
                alias_bus_reply(fresh, barrier_response, "s")
                result["bus_ids"].append(alias_text(barrier_response))
            elif check == "xml":
                row["decoded"] = api_xml(response, row["path"], backend)
            elif check in ("id", "machine"):
                value = alias_text(response)
                assert len(value) == 32 and all(char in "0123456789abcdef" for char in value), value
                result["machine_ids" if check == "machine" else "bus_ids"].append(value)
                if check == "machine":
                    assert value == trusted_machine, (value, trusted_machine)
            elif check in ("names", "owners", "activatable"):
                values = api_string_array(response)
                row["decoded"] = values
                if check == "names":
                    assert BUS in values and client.name in values and len(values) == len(set(values)), values
                elif check == "owners":
                    assert values == [client.name], values
                elif backend == "candidate":
                    assert values == [], values
            elif check == "one":
                assert number(response) == 1, alias_raw(response)
            elif check == "true":
                assert response["body"] == wire.u32(1), alias_raw(response)
            elif check == "owner":
                assert alias_text(response) == client.name, alias_raw(response)
            elif check == "empty":
                assert getall_dictionary(response) == {}, alias_raw(response)
            elif check in ("property", "empty-target-get"):
                row["decoded"] = properties_features(response)
                assert PROPERTY_SENTINEL not in row["decoded"], row["decoded"]
                if check == "property":
                    name, phase = row["label"].split("-")[1:]
                    result["properties"][name + "_" + phase] = row["decoded"]
                else:
                    assert row["decoded"] == result["properties"].get("Features_before"), row["decoded"]
            elif check == "all":
                row["decoded"] = getall_dictionary(response)
                expected_properties = {name: {"signature": "as", "value": result["properties"].get(name + "_before")}
                                       for name in ("Features", "Interfaces")}
                assert row["decoded"] == expected_properties, row["decoded"]
            row["result"] = "PASS"
        except BaseException as failure:
            row["error"] = repr(failure)
            result["contract_failures"].append({"operation": row["label"], "error": repr(failure)})
        finally:
            if fresh is not None:
                fresh.close()
                row["fresh_socket_closed"] = fresh.sock.fileno() == -1
                trace.append({"event": "socket-closed", "actor": fresh.label,
                              "pid": os.getpid(), "uid": os.getuid(), "closed": row["fresh_socket_closed"]})
    for key in ("bus_ids", "machine_ids"):
        if result[key] and len(set(result[key])) != 1:
            result["contract_failures"].append({"operation": key, "error": "identity changed across calls"})
    if not privileged:
        for name in ("Features", "Interfaces"):
            if result["properties"].get(name + "_before") != result["properties"].get(name + "_after"):
                result["contract_failures"].append({"operation": name, "error": "property changed after rejected Set"})
        result["bus_id"] = result["bus_ids"][0] if result["bus_ids"] else None
    trace.append({"event": "api-contract", "privileged": privileged,
                  "operation_count": len(rows), "result": "FAIL" if result["contract_failures"] else "PASS"})
    return result


def api_string_array(message):
    body = message["body"]
    assert len(body) >= 4 and struct.unpack_from("<I", body)[0] == len(body) - 4, alias_raw(message)
    offset, values = 4, []
    while offset < len(body):
        offset += -offset % 4
        size = struct.unpack_from("<I", body, offset)[0]
        assert offset + size + 5 <= len(body) and body[offset + size + 4] == 0, alias_raw(message)
        values.append(body[offset + 4:offset + 4 + size].decode())
        offset += size + 5
    assert offset == len(body), alias_raw(message)
    return values


def properties_worker(connection, path, uid, scope="properties-set", backend=None, api_deadline=None):
    trace, client, failed = [], None, False
    try:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        assert os.getuid() == os.geteuid() == uid
        assert os.getgid() == os.getegid() == uid and os.getgroups() == []
        denials = {}
        for filename in ALIAS_FILES:
            try:
                descriptor = os.open(Path(path).parent.parent / "config" / filename, os.O_WRONLY)
            except PermissionError as failure:
                assert failure.errno == 13, failure
                denials[filename] = failure.errno
                trace.append({"event": "trusted-file-denied", "actor": "caller",
                              "file": filename, "errno": failure.errno, "uid": uid, "pid": os.getpid()})
            else:
                os.close(descriptor)
                raise AssertionError("properties caller can write trusted " + filename)
        client = ApiClient(path, "caller", trace, deadline=api_deadline) if scope == "api-dispatch" else AliasClient(path, "caller", trace)
        connection.send({"event": "ready", "identity": alias_identity(client, trace, denials), "trace": trace})
        trace.clear()
        exercised = False
        while True:
            assert connection.poll(95 if scope == "api-dispatch" else 30), "properties worker coordinator command timeout"
            command = connection.recv()
            if command == {"op": "stop"}:
                break
            assert command == {"op": "properties"} and not exercised, command
            exercised = True
            if scope == "api-dispatch":
                result = api_sequence(client, trace, backend, api_deadline)
                connection.send({"event": "complete", "api": result, "trace": trace})
            else:
                result = getall_sequence(client, trace) if scope == "properties-get-all" else properties_sequence(client, trace)
                connection.send({"event": "complete", "properties": result, "trace": trace})
            trace.clear()
    except BaseException as failure:
        failed = True
        connection.send({"event": "failure", "error": repr(failure), "trace": trace})
    finally:
        try:
            if client is not None:
                client.close()
                connection.send({"event": "socket-closed", "actor": "caller", "name": client.name,
                                 "pid": os.getpid(), "uid": os.getuid(),
                                 "closed": client.sock.fileno() == -1, "failed": failed})
        finally:
            connection.close()
    if failed:
        raise SystemExit(1)


def run_properties(path, directory, caller_uid, backend, scope="properties-set"):
    trace, processes, channels, clients = [], [], {}, []
    # Reserve 15s of the 90s actor bound for startup/normal socket, worker and
    # private-reference shutdown; all actual API queries share this deadline.
    api_deadline = time.monotonic() + 75 if scope == "api-dispatch" else None
    summary = {"result": "FAIL", "backend": backend, "scope": scope, "readiness": "L0",
               "installed_profile_qualified": False, "identities": [], "properties": {},
               "contract_failures": [], "trace": trace}
    try:
        assert os.getuid() == os.geteuid() == 0 and caller_uid != 0, "properties actors require root and ordinary UIDs"
        assert Path(path) == prepared_socket(directory), "properties socket must match prepared path"
        summary["config_hashes_before"] = alias_hashes(directory)
        parent, child = multiprocessing.Pipe()
        worker_args = (child, path, caller_uid, scope, backend, api_deadline) if scope == "api-dispatch" else (child, path, caller_uid, scope)
        process = multiprocessing.Process(target=properties_worker, args=worker_args)
        process.start()
        child.close()
        processes.append(("caller", process))
        channels["caller"] = parent
        ready = alias_receive(parent, trace, "ready")
        identity = ready["identity"]
        assert identity["pid"] == process.pid and identity["uid"] == identity["gid"] == caller_uid
        assert identity["groups"] == [] and identity["file_write_denials"] == dict.fromkeys(ALIAS_FILES, 13)
        summary["identities"].append(identity)
        # The ordinary worker exists before this root socket and waits for the
        # coordinator's independent kernel UID/PID proof before API requests.
        observer = ApiClient(path, "observer", trace, deadline=api_deadline) if scope == "api-dispatch" else AliasClient(path, "observer", trace)
        clients.append(observer)
        observer_identity = dict(next(item for item in trace
                                     if item["event"] == "identity" and item["actor"] == "observer"))
        observer_identity["file_write_denials"] = {}
        summary["identities"].append(observer_identity)
        for current in summary["identities"]:
            proof = {}
            for method, key in [("GetConnectionUnixUser", "bus_uid"),
                                ("GetConnectionUnixProcessID", "bus_pid")]:
                if scope == "api-dispatch":
                    row = {"member": method, "signature": "s", "body_hex": wire.string(current["name"]).hex(),
                           "interface": BUS, "path": API_PATHS[0]}
                    response = api_query(observer, row, api_deadline)
                else:
                    response = properties_query(observer, method, "s", wire.string(current["name"]))
                alias_bus_reply(observer, response, "u")
                current[key] = number(response)
                proof[key] = alias_raw(response)
            current["bus_identity_responses"] = proof
            assert current["bus_uid"] == current["uid"] and current["bus_pid"] == current["pid"]
        if scope == "api-dispatch":
            response = api_query(observer, {"member": "GetId", "signature": "", "body_hex": "",
                                           "interface": BUS, "path": API_PATHS[0]}, api_deadline)
        else:
            response = properties_query(observer, "GetId")
        alias_bus_reply(observer, response, "s")
        summary["bus_id"] = summary["bus_ids_before"] = alias_text(response)
        parent.send({"op": "properties"})
        # Each query has a 12s bound; retain the existing five-call Set bound
        # and allow six calls plus the same 5s margin for GetAll.
        sequence_timeout = max(0, api_deadline - time.monotonic()) if scope == "api-dispatch" else (77 if scope == "properties-get-all" else 65)
        assert parent.poll(sequence_timeout), "properties worker bounded sequence timeout"
        complete = alias_receive(parent, trace)
        if scope == "api-dispatch":
            summary["api"] = complete["api"]
            summary["api_root"] = api_sequence(observer, trace, backend, api_deadline, privileged=True)
            summary["contract_failures"] = list(summary["api"]["contract_failures"]) + list(summary["api_root"]["contract_failures"])
            summary["operation_count"] = summary["api"]["operation_count"] + summary["api_root"]["operation_count"]
        else:
            summary["properties"] = complete["properties"]
            summary["contract_failures"] = list(complete["properties"]["contract_failures"])
        if scope == "api-dispatch":
            response = api_query(observer, {"member": "GetId", "signature": "", "body_hex": "",
                                           "interface": BUS, "path": API_PATHS[0]}, api_deadline)
        else:
            response = properties_query(observer, "GetId")
        alias_bus_reply(observer, response, "s")
        summary["bus_ids_after"] = alias_text(response)
        worker_result = summary["api"] if scope == "api-dispatch" else summary["properties"]
        assert summary["bus_ids_after"] == summary["bus_id"] == worker_result.get("bus_id")
        summary["config_hashes_after"] = alias_hashes(directory)
        assert summary["config_hashes_after"] == summary["config_hashes_before"]
        summary["result"] = "FAIL" if summary["contract_failures"] else "PASS"
        if summary["contract_failures"]:
            summary["error"] = ("API dispatch/introspection contract failed" if scope == "api-dispatch" else
                                "Properties.GetAll contract failed" if scope == "properties-get-all"
                                else "Properties.Set read-only contract failed")
    except BaseException as failure:
        summary["error"] = repr(failure)
    finally:
        summary["cleanup"] = alias_cleanup(processes, channels, clients, trace)
        cleanup = summary["cleanup"]
        if not cleanup["root_sockets_closed"] or len(cleanup["workers"]) != 1 or any(
                item["exitcode"] != 0 or not item["normal_stop"] or not item["socket_closed_receipt"]
                or item["terminate"] or item["kill"] for item in cleanup["workers"]):
            summary["result"] = "FAIL"
            summary.setdefault("error", "properties worker cleanup did not complete normally")
        try:
            summary["config_hashes_after"] = alias_hashes(directory)
            if summary["config_hashes_after"] != summary.get("config_hashes_before"):
                summary["result"] = "FAIL"
                summary.setdefault("error", "trusted properties XML hashes changed")
        except BaseException as failure:
            summary["result"] = "FAIL"
            summary["hash_error"] = repr(failure)
    return summary


def properties_reference(daemon, directory, caller_uid, scope="properties-set"):
    # Reuse the prepared bytes and endpoint; never rewrite the three XML files.
    result, process = None, None
    daemon_cleanup = {"normal_stop": False, "terminate": False, "kill": False, "exitcode": None}
    stderr_name = ("api-reference.stderr" if scope == "api-dispatch" else
                   "getall-reference.stderr" if scope == "properties-get-all" else "properties-reference.stderr")
    with (directory / stderr_name).open("w") as stderr:
        try:
            process = subprocess.Popen([daemon, "--config-file=" + str(directory / "bus.conf"),
                "--nofork", "--print-address"], stdout=subprocess.PIPE, stderr=stderr)
            address_bytes, deadline = b"", time.monotonic() + 5
            while not address_bytes.endswith(b"\n"):
                remaining = deadline - time.monotonic()
                assert remaining > 0 and select.select([process.stdout], [], [], remaining)[0], \
                    "private properties reference startup timeout"
                chunk = os.read(process.stdout.fileno(), 1)
                assert chunk and len(address_bytes) < 4096, "private properties reference missing address"
                address_bytes += chunk
            address = address_bytes.decode().strip()
            assert address.split(",", 1)[0] == "unix:path=" + str(prepared_socket(directory)), address
            prepared_socket(directory).chmod(0o666)
            result = run_properties(str(prepared_socket(directory)), directory, caller_uid, "reference", scope)
            result["daemon_address"] = address
            result["daemon_sha256"] = hashlib.sha256(Path(daemon).read_bytes()).hexdigest()
        except BaseException as failure:
            if result is None:
                result = {"result": "FAIL", "backend": "reference", "scope": scope,
                          "installed_profile_qualified": False, "readiness": "L0", "trace": [], "cleanup": {}}
            result["result"], result["error"] = "FAIL", repr(failure)
        finally:
            if process is not None:
                daemon_cleanup["pid"] = process.pid
                if process.poll() is None:
                    daemon_cleanup["terminate"] = True
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        daemon_cleanup["kill"] = True
                        process.kill()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired as failure:
                            daemon_cleanup["reap_error"] = repr(failure)
                    daemon_cleanup["normal_stop"] = not daemon_cleanup["kill"] and process.returncode in (0, -15)
                daemon_cleanup["exitcode"] = process.returncode
                process.stdout.close()
            result["cleanup"]["daemon"] = daemon_cleanup
            if not daemon_cleanup["normal_stop"]:
                result["result"] = "FAIL"
                result.setdefault("error", "private properties reference daemon did not stop normally")
    return result


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "prepare":
        prepare(Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    elif mode == "candidate":
        assert len(sys.argv) in (5, 6) and (len(sys.argv) == 5 or sys.argv[5] == "--snapshot-checkpoints")
        print(json.dumps(run(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), mode,
                             checkpoints=len(sys.argv) == 6)), flush=True)
    elif mode == "reference":
        print(json.dumps(reference(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]))), flush=True)
    elif mode == "prepare-alias":
        prepare_alias(Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
    elif mode in ("alias-candidate", "alias-reference"):
        if mode == "alias-candidate":
            result = run_alias(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), "candidate")
        else:
            result = alias_reference(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
        print(json.dumps(result), flush=True)
        if result["result"] != "PASS":
            raise SystemExit(1)
    elif mode == "prepare-properties":
        prepare_properties(Path(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    elif mode in ("properties-candidate", "properties-reference"):
        if mode == "properties-candidate":
            result = run_properties(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), "candidate")
        else:
            result = properties_reference(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]))
        print(json.dumps(result), flush=True)
        if result["result"] != "PASS":
            raise SystemExit(1)
    elif mode in ("getall-candidate", "getall-reference"):
        if mode == "getall-candidate":
            result = run_properties(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), "candidate", "properties-get-all")
        else:
            result = properties_reference(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), "properties-get-all")
        print(json.dumps(result), flush=True)
        if result["result"] != "PASS":
            raise SystemExit(1)
    elif mode in ("api-candidate", "api-reference"):
        if mode == "api-candidate":
            result = run_properties(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), "candidate", "api-dispatch")
        else:
            result = properties_reference(sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), "api-dispatch")
        print(json.dumps(result), flush=True)
        if result["result"] != "PASS":
            raise SystemExit(1)
    else:
        raise AssertionError(mode)
