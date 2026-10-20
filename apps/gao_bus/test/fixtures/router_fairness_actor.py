"""Controlled rights0 fairness workload on one explicitly private socket."""
import json
import os
import select
import socket
import sys
import threading
import time

sys.dont_write_bytecode = True
import transport_actor as wire

BUS = "org.freedesktop.DBus"
INTERFACE = "org.foundation.Fairness"
OBSERVER = "org.foundation.Observer"


def emit(event, **details):
    print(json.dumps({"event": event, **details}), flush=True)


def checkpoint(event, **details):
    emit(event, **details)
    assert sys.stdin.readline().strip() == "continue", "controller checkpoint"


def payload(sender, serial):
    return ("%s:%d:" % (sender, serial)).ljust(65536, "x")


def run(path):
    clients = []
    readers, writers, errors = [], [], []
    stop = threading.Event()
    try:
        for _ in range(11):
            clients.append(wire.Client(path, negotiate=False))
        producers, receivers, observer = clients[:2], clients[2:10], clients[10]
        for receiver in receivers:
            for index in range(32):
                member = "FairPulse" if index == 0 else "Never%d" % index
                rule = "type='signal',interface='%s',member='%s'" % (INTERFACE, member)
                serial = 10 + index
                receiver.sock.sendall(wire.call("AddMatch", serial, "s", wire.string(rule)))
                assert receiver.reply(serial)["type"] == 2

        name_body = wire.string(OBSERVER)
        observer.sock.sendall(wire.call("RequestName", 10, "su",
            name_body + wire.padding(len(name_body), 4) + wire.u32(0)))
        assert observer.reply(10)["body"] == wire.u32(1)
        observer.barrier(11)  # Retire the corresponding NameAcquired before health.
        intended, calls = set(), {}
        broadcasts, call_batches = [], []
        for index, producer in enumerate(producers):
            messages = []
            for n in range(64):
                serial = 100000 + index * 1000 + n
                intended.add((producer.name, serial))
                messages.append(wire.frame(4, serial, [(1, "o", "/fairness"),
                    (2, "s", INTERFACE), (3, "s", "FairPulse"), (8, "g", "s")],
                    wire.string(payload(producer.name, serial))))
            broadcasts.append(b"".join(messages))
            messages = []
            for n in range(8):
                serial = 200000 + index * 1000 + n
                calls[(producer.name, serial)] = producer
                messages.append(wire.frame(1, serial, [(1, "o", "/fairness"),
                    (2, "s", INTERFACE), (3, "s", "Hold"), (6, "s", receivers[0].name),
                    (8, "g", "")]))
            call_batches.append(b"".join(messages))
        seen = [set() for _ in receivers]
        held = {}
        held_ready = threading.Condition()

        def ingest(index):
            message = receivers[index].receive()
            assert not message["fds"], "rights0 workload received descriptors"
            key = (message["fields"].get(7), message["serial"])
            assert message["fields"].get(1) == "/fairness"
            assert message["fields"].get(2) == INTERFACE
            if message["type"] == 4 and message["fields"].get(3) == "FairPulse":
                assert key in intended and key not in seen[index], ("broadcast identity/duplicate", key)
                assert message["body"] == wire.string(payload(*key)), "broadcast bytes/serial mismatch"
                seen[index].add(key)
            elif message["type"] == 1 and message["fields"].get(3) == "Hold":
                assert index == 0 and key in calls, ("held call identity", key)
                assert message["body"] == b"" and message["fields"].get(6) == receivers[0].name
                with held_ready:
                    assert key not in held, ("duplicate held call", key)
                    held[key] = message
                    held_ready.notify_all()
            else:
                raise AssertionError(("unexpected receiver frame", message))

        # Each draining receiver must be ready before Router resumes. Serial
        # reads in the controller can let a fast Router fill the callee's queue.
        ready = threading.Barrier(8)

        def pump(index):
            try:
                ready.wait(timeout=3)
                while not stop.is_set():
                    if select.select([receivers[index].sock], [], [], 0.05)[0]:
                        ingest(index)
            except Exception as error:
                with held_ready:
                    errors.append(error)
                    held_ready.notify_all()

        for index in range(7):
            reader = threading.Thread(target=pump, args=(index,))
            readers.append(reader)
            reader.start()
        ready.wait(timeout=3)
        checkpoint("ready", producers=[c.name for c in producers],
                   receivers=[c.name for c in receivers], observer=observer.name, uid=os.getuid())

        def barrier(producer, serial):
            producer.sock.sendall(wire.call("ListNames", serial))
            reply = producer.receive()
            assert reply["type"] == 2 and reply["fields"].get(5) == serial, reply
            assert reply["fields"].get(7) == BUS and not reply["fds"], reply

        # A reader-ready barrier cannot guarantee egress credit retirement.
        # Establish the pending-call precondition in cap-sized batches before
        # timed fanout; controller acknowledgement also fences zero egress.
        for index, producer in enumerate(producers):
            producer.sock.sendall(call_batches[index])
            barrier(producer, 890000 + index)
            expected = (index + 1) * 8
            with held_ready:
                assert held_ready.wait_for(lambda: len(held) == expected or errors, timeout=3), (
                    "held call receipt deadline", len(held), expected)
                assert not errors, errors
            checkpoint("held_batch", batch=index, received=expected)

        loaded = [0, 0]
        writer_ready = threading.Barrier(3)
        write_deadline = time.monotonic() + 5

        def load(index):
            try:
                producers[index].sock.settimeout(5)
                writer_ready.wait(timeout=3)
                producers[index].sock.sendall(broadcasts[index])
                loaded[index] = 64
            except Exception as error:
                with held_ready:
                    errors.append(error)
                    held_ready.notify_all()

        for index in range(2):
            writer = threading.Thread(target=load, args=(index,))
            writers.append(writer)
            writer.start()
        writer_ready.wait(timeout=3)
        checkpoint("load_started", broadcasts=128, calls=16)
        observer.sock.sendall(wire.call("GetNameOwner", 900000, "s", wire.string(OBSERVER)))
        checkpoint("health_queued")

        def healthy_reply(serial, deadline):
            while True:
                assert not errors, errors
                remaining = deadline - time.monotonic()
                assert remaining > 0, "healthy wire deadline 1000ms"
                readable, _, _ = select.select([observer.sock], [], [], remaining)
                assert readable, "healthy wire deadline 1000ms"
                if observer.sock in readable:
                    observer.sock.settimeout(max(deadline - time.monotonic(), 0.001))
                    reply = observer.receive()
                    assert reply["type"] == 2 and reply["fields"].get(5) == serial, reply
                    assert reply["fields"].get(7) == BUS and reply["fields"].get(6) == observer.name
                    assert reply["body"] == wire.string(observer.name) and not reply["fds"]
                    assert time.monotonic() <= deadline, "healthy wire deadline 1000ms"
                    return

        started = time.monotonic()
        healthy_reply(900000, started + 1)
        checkpoint("healthy", latency_ms=(time.monotonic() - started) * 1000)

        for writer in writers:
            writer.join(timeout=max(write_deadline - time.monotonic(), 0))
            assert not writer.is_alive(), "producer sendall completion deadline"
        assert not errors, errors
        assert loaded == [64, 64], ("incomplete broadcasts", loaded)
        for index, producer in enumerate(producers):
            barrier(producer, 910000 + index)
        checkpoint("loaded", broadcasts=sum(loaded), calls=16)
        started = time.monotonic()
        observer.sock.sendall(wire.call("GetNameOwner", 900001, "s", wire.string(OBSERVER)))
        healthy_reply(900001, started + 1)
        checkpoint("postbarrier_healthy", latency_ms=(time.monotonic() - started) * 1000)

        emit("draining")
        deadline = time.monotonic() + 3
        while True:
            assert not errors, errors
            remaining = deadline - time.monotonic()
            assert remaining > 0, "output drain deadline"
            readable, _, _ = select.select([sys.stdin, receivers[7].sock], [], [], remaining)
            assert readable, "output drain deadline"
            if sys.stdin in readable:
                assert sys.stdin.readline().strip() == "continue"
                break
            if receivers[7].sock in readable:
                ingest(7)
        stop.set()
        for reader in readers:
            reader.join(timeout=3)
            assert not reader.is_alive(), "receiver did not stop"
        assert not errors, errors
        # The controller has observed zero egress and fenced every Peer. All
        # successful writes are now in the kernel, including a partial tail.
        for index, receiver in enumerate(receivers):
            while select.select([receiver.sock], [], [], 0)[0]:
                ingest(index)
        assert set(held) == set(calls), ("incomplete held calls", sorted(held))
        assert all(0 < len(rows) <= 128 for rows in seen), "receiver observed no broadcast"
        for index, (sender, serial) in enumerate(held):
            receivers[0].sock.sendall(wire.frame(2, 920000 + index,
                [(5, "u", serial), (6, "s", sender), (8, "g", "u")], wire.u32(serial)))
        for index, producer in enumerate(producers):
            expected = {200000 + index * 1000 + n for n in range(8)}
            received = set()
            for _ in range(8):
                reply = producer.receive()
                serial = reply["fields"].get(5)
                assert serial in expected and serial not in received, "reply identity/duplicate"
                assert reply["type"] == 2 and reply["fields"].get(7) == receivers[0].name
                assert reply["fields"].get(6) == producer.name and not reply["fds"]
                assert reply["body"] == wire.u32(serial), "held reply bytes/serial mismatch"
                received.add(serial)
            assert received == expected
        checkpoint("drained", broadcasts=128, observed=[len(rows) for rows in seen],
                   held_calls=len(held), replies=16,
                   complete_admission_proof="NOT_MEASURED")
    finally:
        stop.set()
        for reader in readers:
            reader.join(timeout=3)
        for producer in clients[:2]:
            try:
                producer.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for writer in writers:
            writer.join(timeout=3)
            assert not writer.is_alive(), "producer did not stop"
        for client in clients:
            client.close()
    emit("closed")


if __name__ == "__main__":
    run(sys.argv[1])
