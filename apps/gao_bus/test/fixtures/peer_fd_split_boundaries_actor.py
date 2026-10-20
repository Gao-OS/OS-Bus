"""All internal frame splits through registered private-bus Peers and real rights."""
import hashlib
import json
import os
import signal as process_signal
import sys

from transport_actor import Client, call, close_fds, signal, string, u32


def emit(event, **details):
    print(json.dumps(dict(event=event, **details)), flush=True)


def command(expected):
    assert sys.stdin.readline().strip() == expected, expected


def inventory(pid):
    directory = "/proc/" + pid + "/fd"
    return {name: os.readlink(directory + "/" + name)
            for name in sorted(os.listdir(directory))}


def bundle(label):
    readers, writers, identities, payloads = [], [], [], []
    for index in range(2):
        reader, writer = os.pipe()
        payload = (label + "-" + str(index)).encode()
        os.write(writer, payload)
        readers.append(reader)
        writers.append(writer)
        identities.append(os.readlink("/proc/self/fd/" + str(reader)))
        payloads.append(payload.hex())
    return readers, writers, identities, payloads


def receipt(client):
    message = client.receive()
    rights = message["fds"]
    try:
        identities = [os.readlink("/proc/self/fd/" + str(fd)) for fd in rights]
        payloads = [os.read(fd, 128).hex() for fd in rights]
    finally:
        close_fds(rights)
    return {"serial": message["serial"], "type": message["type"],
            "fields": message["fields"], "body": message["body"].hex(),
            "identities": identities, "payloads": payloads}


def validate(result, serial, source, target, body, identities, payloads):
    assert result["serial"] == serial, result
    assert result["type"] == 4, result
    assert result["fields"][3] == "Resource", result
    assert result["fields"][6] == target, result
    assert result["fields"][7] == source, result
    assert result["fields"][8] == ("hh" if identities else ""), result
    assert result["fields"].get(9, 0) == len(identities), result
    assert result["body"] == body.hex(), result
    assert result["identities"] == identities, result
    assert result["payloads"] == payloads, result


def negative_controls(result, expected):
    # Mutate observed semantic receipts, never the production source or fixtures.
    for field, value in [("identities", list(reversed(result["identities"]))),
                         ("payloads", list(reversed(result["payloads"]))),
                         ("body", (u32(0) + u32(1)).hex())]:
        changed = dict(result, **{field: value})
        try:
            validate(changed, *expected)
        except AssertionError:
            continue
        raise AssertionError("association oracle missed mutation: " + field)


def reclaimed(writers):
    for writer in writers:
        try:
            os.write(writer, b"LEAK-PROBE")
        except BrokenPipeError:
            continue
        raise AssertionError("a transferred pipe reader survived delivery cleanup")


def health(client, owned, bus_id, serial):
    client.sock.sendall(call("GetNameOwner", serial, "s", string(owned)))
    assert client.reply(serial)["body"] == string(client.name)
    client.sock.sendall(call("GetId", serial + 1))
    assert client.reply(serial + 1)["body"] == bus_id


def run(path, daemon_pid):
    assert os.path.isabs(path) and os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    process_signal.alarm(45)
    clients, readers, writers = [], [], []
    try:
        source, target, healthy = [Client(path) for _ in range(3)]
        clients.extend([source, target, healthy])
        owned = "org.foundation.SplitObserver"
        request = string(owned)
        healthy.sock.sendall(call("RequestName", 3, "su", request + b"\0" * (-len(request) % 4) + u32(0)))
        assert healthy.reply(3)["body"] == u32(1)
        healthy.sock.sendall(call("GetId", 4))
        bus_id = healthy.reply(4)["body"]
        sample = signal(10, target.name, 2, u32(1) + u32(0), "hh")
        emit("ready", source=source.name, target=target.name, healthy=healthy.name,
             owned=owned, bus_id=bus_id.hex(), frame=sample.hex(),
             frame_sha256=hashlib.sha256(sample).hexdigest(), frame_bytes=len(sample),
             splits=list(range(1, len(sample))), modes=["rights_with_prefix", "rights_at_split"])
        command("baseline")
        baseline = inventory(daemon_pid)
        emit("baseline", fds=baseline)
        cases = 0
        for mode in ["rights_with_prefix", "rights_at_split"]:
            for split in range(1, len(sample)):
                command("next")
                serial = 10 + cases * 3
                data = signal(serial, target.name, 2, u32(1) + u32(0), "hh")
                readers, writers, identities, payloads = bundle(str(cases) + "-first")
                if mode == "rights_at_split":
                    source.sock.sendall(data[:split - 1])
                    source.send_fds(data[split - 1:split], readers)
                else:
                    source.send_fds(data[:split], readers)
                close_fds(readers)
                readers = []
                emit("partial", mode=mode, split=split, prefix=data[:split].hex(),
                     identities=identities)
                command("retained")
                emit("retained", fds=inventory(daemon_pid))
                command("finish")
                source.sock.sendall(data[split:])
                second_readers, second_writers, second_ids, second_payloads = bundle(str(cases) + "-second")
                readers.extend(second_readers)
                writers.extend(second_writers)
                source.send_fds(signal(serial + 1, target.name, 2, u32(0) + u32(1), "hh"), readers)
                close_fds(readers)
                readers = []
                source.sock.sendall(signal(serial + 2, target.name, None, b"", ""))
                first, second, tail = [receipt(target) for _ in range(3)]
                expected = (serial, source.name, target.name, u32(1) + u32(0), identities, payloads)
                validate(first, *expected)
                validate(second, serial + 1, source.name, target.name, u32(0) + u32(1), second_ids, second_payloads)
                validate(tail, serial + 2, source.name, target.name, b"", [], [])
                assert set(identities).isdisjoint(second_ids)
                if cases == 0:
                    negative_controls(first, expected)
                source.barrier(5000 + cases)
                target.barrier(5000 + cases)
                health(healthy, owned, bus_id, 6000 + 2 * cases)
                reclaimed(writers)
                close_fds(writers)
                writers = []
                emit("delivered", mode=mode, split=split, receipts=[first, second, tail],
                     reclaimed=4, healthy=True)
                command("snapshot")
                final = inventory(daemon_pid)
                assert final == baseline, (baseline, final)
                emit("quiescent", mode=mode, split=split, fds=final)
                cases += 1
        command("stop")
        emit("result", result="PASS", cases=cases, fd_frames=2 * cases,
             usable_resources=4 * cases, non_fd_tails=cases, negative_controls=3,
             baseline_fds=baseline, final_fds=inventory(daemon_pid))
    finally:
        close_fds(readers)
        close_fds(writers)
        for client in clients:
            client.close()


if __name__ == "__main__":
    assert len(sys.argv) == 3
    run(sys.argv[1], sys.argv[2])
