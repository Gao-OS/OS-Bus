"""Finite independent dbus-python actors for the canonical disposable VM only.

Never import or execute this module for source validation: use ast.parse.
Runtime assertions are deferred acceptance sources, not recorded results.
"""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

import workload as w

LIMIT = 16
NORMAL_RESOURCE_ROUNDS = 4
SERVICE = "osbus-foundation-fixture.service"
RELOAD = Path("/run/osbus-system/reload.conf")
DROPIN = Path("/run/systemd/system/" + SERVICE + ".d/90-vm05-failure.conf")
DENY = "org.freedesktop.DBus.Error.AccessDenied"
BOUNDS = {"fd_growth": 2, "process_growth": 0, "rss_growth_bytes": 64 * 1024 * 1024,
          "socket_queue_growth_bytes": 0, "healthy_latency_seconds": 2,
          "listener_pending_growth": 0, "recovery_seconds": 10,
          "max_connections_per_user": LIMIT, "max_incoming_bytes": 262144,
          "max_outgoing_bytes": 262144}


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def identity(bus):
    name = str(bus.get_unique_name())
    own = w.credentials(bus, name)
    w.require(own["pid"] == os.getpid() and own["uid"] == os.getuid(),
              "actor credentials do not match the actual process")
    return {"name": name, "bus_id": str(w.bus_call(bus, "GetId")), **own}


def echo(bus, token):
    result = w.call(bus, w.FIXTURE, w.FIXTURE_PATH, w.FIXTURE, "Echo", "s", (token,))
    w.require(str(result) == token, "fixture Echo response differs")
    return str(result)


def actor(mode):
    """No raw protocol, malformed input, fuzzing, or unbounded traffic."""
    import dbus
    bus = w.connect()
    connections = [bus]
    try:
        own = identity(bus)
        details = {}
        if mode == "abrupt":
            name = "org.foundation.VM05.Abrupt"
            w.require(int(w.bus_call(bus, "RequestName", "su", (name, 4))) == 1,
                      "abrupt actor did not acquire its isolated name")
            details["owned_name"] = name
        elif mode == "slow":
            w.bus_call(bus, "AddMatch", "s", (
                "type='signal',interface='com.test.ExternalFixture',member='TestSignal'",))
            details["dispatching"] = False
        elif mode == "overload":
            # Exactly sixteen live authenticated connections for this one UID.
            for _ in range(LIMIT - 1):
                connections.append(w.connect())
            w.require(len({str(peer.get_unique_name()) for peer in connections}) == LIMIT,
                      "load actor connections are not independent")
            try:
                extra = w.connect()
            except dbus.DBusException as error:
                failure = error.get_dbus_name()
                # Disconnect during Hello is how dbus-daemon enforces this cap.
                w.require(failure in ("org.freedesktop.DBus.Error.LimitsExceeded",
                                      "org.freedesktop.DBus.Error.NoReply",
                                      "org.freedesktop.DBus.Error.Disconnected"),
                          "unexpected connection admission error: " + failure)
                details.update(admitted=LIMIT, attempted=LIMIT + 1, rejected=1,
                               rejection=failure, rejection_detail=str(error))
            else:
                extra.close()
                raise RuntimeError("seventeenth same-UID connection bypassed cap16")
        elif mode == "session":
            w.require(int(w.bus_call(bus, "RequestName", "su", ("org.foundation.VM05.Session", 4))) == 1,
                      "PAM session actor did not acquire its isolated name")
        emit({"event": "ready", "identity": own, **details})
        samples, maximum = 0, 0.0
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if mode == "healthy":
                started = time.monotonic()
                w.require(str(w.bus_call(bus, "GetId")) == own["bus_id"],
                          "healthy connection crossed bus epoch")
                elapsed = time.monotonic() - started
                maximum = max(maximum, elapsed)
                samples += 1
                w.require(elapsed < BOUNDS["healthy_latency_seconds"],
                          "healthy traffic exceeded two-second latency bound")
            if mode == "session":
                # systemd owns this bounded service actor and handles SIGTERM.
                time.sleep(0.1)
                continue
            ready, _, _ = select.select([sys.stdin], [], [], 0.05)
            if not ready:
                continue
            request = sys.stdin.readline().strip()
            if request == "stop" or not request:
                return
            if request == "snapshot":
                emit({"event": "snapshot", "identity": identity(bus), "samples": samples,
                      "max_latency_seconds": maximum})
            elif request in ("allow", "deny"):
                try:
                    result = echo(bus, "vm05-policy-generation")
                except dbus.DBusException as error:
                    w.require(request == "deny" and error.get_dbus_name() == DENY,
                              "policy probe unexpected error: " + str(error))
                    emit({"event": request, "error": error.get_dbus_name()})
                else:
                    w.require(request == "allow", "reloaded policy allowed denied Echo")
                    emit({"event": request, "response": result})
            else:
                raise RuntimeError("unknown actor control request: " + request)
        raise RuntimeError("actor exceeded finite 60-second lifetime")
    finally:
        for peer in connections:
            peer.close()


class Actor:
    def __init__(self, mode, user):
        self.argv = ["runuser", "-u", user, "--", sys.executable, "-B", str(Path(__file__)), mode]
        self.process = None
        self.ready = None
        self.expected_exit = 0

    def receive(self, timeout=15):
        ready, _, _ = select.select([self.process.stdout], [], [], timeout)
        w.require(ready, "actor response deadline expired: " + repr(self.argv))
        line = self.process.stdout.readline()
        w.require(line, "actor exited before response: " + repr(self.argv))
        result = json.loads(line)
        w.require("error" not in result or result.get("event") == "deny",
                  {"actor": self.argv, "failure": result})
        return result

    def __enter__(self):
        self.process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        try:
            self.ready = self.receive()
            w.require(self.ready["event"] == "ready", "actor readiness missing")
            self.ready["argv"] = self.argv
            return self
        except BaseException as error:
            try:
                self.close()
            except Exception as cleanup:
                raise RuntimeError({"actor_error": str(error), "cleanup_error": str(cleanup)}) from error
            raise

    def request(self, value):
        w.require(self.process.poll() is None, "actor exited before control request")
        self.process.stdin.write(value + "\n")
        self.process.stdin.flush()
        result = self.receive()
        w.require(result["event"] == value, "actor control response differs")
        return result

    def close(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                try:
                    self.process.stdin.write("stop\n")
                    self.process.stdin.flush()
                    self.process.wait(timeout=3)
                except (BrokenPipeError, subprocess.TimeoutExpired):
                    os.killpg(self.process.pid, signal.SIGTERM)
                    try:
                        self.process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(self.process.pid, signal.SIGKILL)
                        self.process.wait(timeout=3)
            w.require(self.process.returncode is not None, "owned actor was not reaped")
            w.require(self.process.returncode == self.expected_exit,
                      {"actor": self.argv, "unexpected_exit": self.process.returncode})
        finally:
            self.process.stdin.close()
            self.process.stdout.close()

    def __exit__(self, kind, error, trace):
        try:
            self.close()
        except Exception as cleanup:
            if error is not None:
                raise RuntimeError({"scenario_error": str(error), "cleanup_error": str(cleanup)}) from error
            raise


def sample(pid):
    """OS-level observations only; no claim about BEAM internal mailboxes/limits."""
    group = w.command(["systemctl", "show", "dbus.service", "--property=ControlGroup", "--value"])
    w.require(group.startswith("/") and ".." not in group.split("/"), "invalid unit cgroup")
    pids = sorted(int(value) for value in
                  (Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.procs").read_text().split())
    w.require(pid in pids, "canonical MainPID disappeared from unit cgroup")
    fds, rss = 0, 0
    for member in pids:
        fds += len(list(Path(f"/proc/{member}/fd").iterdir()))
        for line in Path(f"/proc/{member}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                rss += int(line.split()[1]) * 1024
    queues, listeners = [], []
    raw = w.command(["ss", "--unix", "--all", "--numeric", "--processes", "--no-header"], timeout=3)
    for line in raw.splitlines():
        if any("pid=" + str(member) + "," in line for member in pids):
            fields = line.split()
            w.require(len(fields) >= 4, "unrecognized ss row: " + line)
            if fields[1] == "LISTEN":
                # ss reports listener backlog in connections, not bytes.
                listeners.append({"pending_connections": int(fields[2]),
                                  "backlog_connections": int(fields[3]), "row": line})
            else:
                queues.append({"receive_bytes": int(fields[2]), "send_bytes": int(fields[3]), "row": line})
    w.require(queues and listeners, "ss did not expose canonical connections and listener")
    return {"monotonic": time.monotonic(), "pid": pid, "unit_pids": pids,
            "processes": len(pids), "fds": fds, "rss_bytes": rss, "socket_queues": queues,
            "listeners": listeners,
            "listener_pending_connections": sum(row["pending_connections"] for row in listeners),
            "socket_queue_bytes": sum(row["receive_bytes"] + row["send_bytes"] for row in queues),
            "internal_beam_queues": "UNOBSERVED: external OS sampler only"}


def recover(pid, before, evidence):
    deadline = time.monotonic() + BOUNDS["recovery_seconds"]
    samples = evidence.setdefault("recovery_samples", [])
    for _ in range(100):
        current = sample(pid)
        samples.append(current)
        if (current["monotonic"] <= deadline and
                current["fds"] <= before["fds"] + BOUNDS["fd_growth"] and
                current["processes"] <= before["processes"] + BOUNDS["process_growth"] and
                current["rss_bytes"] <= before["rss_bytes"] + BOUNDS["rss_growth_bytes"] and
                current["listener_pending_connections"] <= before["listener_pending_connections"] +
                BOUNDS["listener_pending_growth"] and
                current["socket_queue_bytes"] <= before["socket_queue_bytes"] +
                BOUNDS["socket_queue_growth_bytes"]):
            return current
        if time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    raise RuntimeError("OS resource recovery exceeded recorded numeric bounds")


def normal_resources(bus, pid, operation, evidence):
    # Warm the same real services before the resource baseline.
    w.fixture_fd(bus)
    w.inhibitor(bus)
    # Exceed the fixed two-FD observation allowance with one retained baseline,
    # so a repeatable descriptor leak cannot hide inside one operation's slack.
    evidence.update(bounds=BOUNDS, rounds=NORMAL_RESOURCE_ROUNDS, before=sample(pid))
    evidence["operations"] = [operation() for _ in range(NORMAL_RESOURCE_ROUNDS)]
    evidence["after"] = recover(pid, evidence["before"], evidence)
    return evidence


def wait_unowned(bus, name):
    deadline = time.monotonic() + 5
    for _ in range(50):
        if not bool(w.bus_call(bus, "NameHasOwner", "s", (name,))):
            return
        if time.monotonic() >= deadline:
            break
        time.sleep(0.1)
    raise RuntimeError("departed actor retained bus ownership: " + name)


def policy_reload(healthy, evidence):
    import dbus
    w.require(not RELOAD.exists() and not RELOAD.is_symlink(), "reload input already exists")
    evidence["policy_before"] = healthy.request("allow")
    control = w.connect()
    try:
        RELOAD.write_text('<busconfig><policy user="foundationB"><deny '
                          'send_destination="com.test.ExternalFixture" '
                          'send_interface="com.test.ExternalFixture" send_member="Echo"/>'
                          '</policy></busconfig>\n')
        evidence["valid_sha256"] = w.hashlib.sha256(RELOAD.read_bytes()).hexdigest()
        w.bus_call(control, "ReloadConfig")
        evidence["valid"] = healthy.request("deny")
        RELOAD.write_text('<busconfig><policy user="foundationB">\n')
        try:
            w.bus_call(control, "ReloadConfig")
        except dbus.DBusException as error:
            w.require(error.get_dbus_name() == "org.freedesktop.DBus.Error.Failed",
                      "invalid reload returned unexpected error: " + str(error))
            evidence["invalid"] = {"error": error.get_dbus_name(), "detail": str(error)}
        else:
            raise RuntimeError("invalid reload was accepted")
        evidence["retained_generation"] = healthy.request("deny")
    finally:
        RELOAD.unlink(missing_ok=True)
        try:
            w.bus_call(control, "ReloadConfig")
            evidence["restored"] = healthy.request("allow")
        finally:
            control.close()


def faulty_clients(bus, pid, evidence):
    with Actor("abrupt", "foundationA") as client:
        evidence["abrupt"] = client.ready
        client.expected_exit = -signal.SIGKILL
        os.killpg(client.process.pid, signal.SIGKILL)
        client.process.wait(timeout=5)
        w.require(client.process.returncode == -signal.SIGKILL, "abrupt actor was not killed")
        wait_unowned(bus, client.ready["owned_name"])
        wait_unowned(bus, client.ready["identity"]["name"])
    with Actor("slow", "foundationA") as client:
        evidence["slow"] = client.ready
        payload = "s" * 4096
        for _ in range(32):
            w.call(bus, w.FIXTURE, w.FIXTURE_PATH, w.FIXTURE, "EmitTestSignal", "s", (payload,))
        evidence["signals"] = {"count": 32, "payload_bytes_each": len(payload),
                               "total_payload_bytes": 32 * len(payload)}
        evidence["slow_during"] = sample(pid)
    wait_unowned(bus, client.ready["identity"]["name"])


def service_failure(bus, evidence):
    import dbus
    w.require(not DROPIN.exists() and not DROPIN.is_symlink(), "failure drop-in already exists")
    previous = w.credentials(bus, w.FIXTURE)
    made_directory = not DROPIN.parent.exists()
    try:
        w.command(["systemctl", "stop", SERVICE])
        wait_unowned(bus, w.FIXTURE)
        w.require(w.command(["systemctl", "show", SERVICE, "--property=ActiveState", "--value"]) ==
                  "inactive", "installed service did not stop")
        DROPIN.parent.mkdir(exist_ok=True)
        DROPIN.write_text("[Service]\nExecStart=\nExecStart=/run/current-system/sw/bin/false\n")
        w.command(["systemctl", "daemon-reload"])
        try:
            echo(bus, "vm05-service-must-fail")
        except dbus.DBusException as error:
            w.require(error.get_dbus_name() in (
                "org.freedesktop.DBus.Error.Spawn.ChildExited", "org.freedesktop.DBus.Error.Failed",
                "org.freedesktop.systemd1.UnitFailed"), "unexpected activation failure: " + str(error))
            evidence["failure"] = {"error": error.get_dbus_name(), "detail": str(error)}
        else:
            raise RuntimeError("failed installed service unexpectedly answered")
        w.command(["systemctl", "is-failed", SERVICE])
        status = w.command(["systemctl", "show", SERVICE, "--property=ExecMainStatus", "--value"])
        w.require(status == "1", "activation did not observe the injected real exit1")
        wait_unowned(bus, w.FIXTURE)
        evidence["unit_exit_status"] = int(status)
    finally:
        DROPIN.unlink(missing_ok=True)
        if made_directory and DROPIN.parent.exists():
            DROPIN.parent.rmdir()
        w.command(["systemctl", "daemon-reload"])
        w.command(["systemctl", "reset-failed", SERVICE])
        echo(bus, "vm05-service-recovery")
        restored = w.credentials(bus, w.FIXTURE)
        w.require(restored["uid"] == previous["uid"] and restored["pid"] != previous["pid"],
                  "service recovery did not create a new process with the original UID")
        evidence["recovered"] = restored


def scenario(name, bus, owner, configuration, evidence):
    w.require(w.os.geteuid() == 0, "VM-05 orchestrator requires guest root")
    evidence.update(bounds=BOUNDS, address=w.ADDRESS, seed="fixed-vm05-v1")
    user = "foundationB" if name == "vm05-policy-reload" else "foundationA"
    with Actor("healthy", user) as healthy:
        evidence["healthy_argv"] = healthy.argv
        evidence["healthy_before"] = healthy.request("snapshot")
        evidence["before"] = sample(owner["pid"])
        if name == "vm05-policy-reload":
            policy_reload(healthy, evidence)
        elif name == "vm05-faulty-clients":
            faulty_clients(bus, owner["pid"], evidence)
        elif name == "vm05-service-failure":
            service_failure(bus, evidence)
        elif name == "vm05-bounded-overload":
            with Actor("overload", "foundationB") as client:
                evidence["load"] = client.ready
                evidence["during"] = sample(owner["pid"])
                evidence["healthy_under_load"] = healthy.request("snapshot")
                echo(bus, "vm05-other-uid-progress")
            wait_unowned(bus, client.ready["identity"]["name"])
            with Actor("healthy", "foundationB") as recovered:
                evidence["admission_recovered"] = recovered.request("snapshot")
        else:
            raise RuntimeError("unknown required scenario: " + name)
        evidence["healthy_after"] = healthy.request("snapshot")
        first, last = evidence["healthy_before"], evidence["healthy_after"]
        w.require(first["identity"] == last["identity"] and last["samples"] > first["samples"],
                  "healthy UID/PID/connection/bus identity or live progress changed")
        w.require(str(w.bus_call(bus, "GetId")) == owner["id"], "scenario restarted bus core")
        w.require(int(w.command(["systemctl", "show", "dbus.service", "--property=MainPID", "--value"])) ==
                  owner["pid"], "scenario replaced canonical process")
        evidence["after"] = recover(owner["pid"], evidence["before"], evidence)
    w.require(w.inventory() == configuration, "scenario changed complete policy/service inventory")
    return evidence


def login_session(bus, evidence):
    unit, name = "osbus-foundation-session.service", "org.foundation.VM05.Session"
    service, root = "org.freedesktop.login1", "/org/freedesktop/login1"
    w.require(w.command(["systemctl", "show", unit, "--property=MainPID", "--value"]) == "0",
              "PAM session unit was already running before this workload")
    w.require(not bool(w.bus_call(bus, "NameHasOwner", "s", (name,))),
              "PAM session actor name was already owned")
    try:
        w.command(["systemctl", "start", unit])
        pid = int(w.command(["systemctl", "show", unit, "--property=MainPID", "--value"]))
        w.require(pid > 1, "PAM session unit has no live MainPID")
        deadline = time.monotonic() + 10
        for _ in range(100):
            if bool(w.bus_call(bus, "NameHasOwner", "s", (name,))):
                break
            w.require(time.monotonic() < deadline, "PAM actor did not register on canonical bus")
            time.sleep(0.1)
        else:
            raise RuntimeError("PAM actor readiness count exhausted")
        own = w.credentials(bus, name)
        w.require(own["pid"] == pid and own["uid"] == w.pwd.getpwnam("foundationA").pw_uid,
                  "PAM session actor's kernel bus credentials differ")
        session = str(w.call(bus, service, root, service + ".Manager", "GetSessionByPID", "u", (pid,)))
        properties = w.call(bus, service, session, "org.freedesktop.DBus.Properties", "GetAll", "s",
                            (service + ".Session",))
        session_id = str(properties["Id"])
        uid, user_path = properties["User"]
        leader = int(properties["Leader"])
        w.require(int(uid) == own["uid"] and leader == pid, "logind session User/Leader differs")
        w.require(str(w.call(bus, service, root, service + ".Manager", "GetSession", "s", (session_id,))) ==
                  session, "logind session ID lookup differs")
        user = w.call(bus, service, str(user_path), "org.freedesktop.DBus.Properties", "GetAll", "s",
                      (service + ".User",))
        w.require(int(user["UID"]) == own["uid"] and str(user["Name"]) == "foundationA",
                  "logind User object differs from actual actor identity")
        evidence.update(identity=own, session_path=session, session_id=session_id,
                        leader=leader, user_path=str(user_path), user_uid=int(user["UID"]),
                        unit=unit, pam_service="login")
    finally:
        w.command(["systemctl", "stop", unit])
        wait_unowned(bus, name)
    return evidence


if __name__ == "__main__":
    try:
        w.guard()
        w.require(len(sys.argv) == 2 and sys.argv[1] in
                  ("healthy", "abrupt", "slow", "overload", "session"), "unknown guarded actor mode")
        actor(sys.argv[1])
    except Exception as error:
        emit({"error": str(error)})
        sys.exit(1)
