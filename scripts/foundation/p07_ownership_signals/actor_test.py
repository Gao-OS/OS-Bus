"""Ordinary, socket-free checks of the supplementary ownership recorder."""
import importlib.util
import inspect
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "p07_test_wire", ROOT / "apps/gao_bus/test/fixtures/transport_actor.py")
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)
BUS = "org.freedesktop.DBus"
NAME = "org.foundation.ReferenceQueue"
BUS_ID = "0123456789abcdef0123456789abcdef"


class MemorySocket:
    def __init__(self):
        self.writes = []

    def sendall(self, data):
        self.writes.append(data)

    def settimeout(self, timeout):
        pass


def notification(member, serial, body, signature="s", destination=None):
    fields = [(1, "o", "/org/freedesktop/DBus"), (2, "s", BUS),
              (3, "s", member), (7, "s", BUS), (8, "g", signature)]
    if destination is not None:
        fields.append((6, "s", destination))
    return wire.frame(4, serial, fields, body)


def response(serial, reply_serial, body, signature):
    return wire.frame(2, serial, [(5, "u", reply_serial), (6, "s", ":1.20"),
                                 (7, "s", BUS), (8, "g", signature)], body)


class RecorderTests(unittest.TestCase):
    def setUp(self):
        actor_path = HERE / "actor.py"
        self.assertTrue(actor_path.is_file(),
                        "P07 independent ownership recorder is not implemented")
        spec = importlib.util.spec_from_file_location("p07_recording_actor", actor_path)
        self.actor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.actor)

    def client(self, packets):
        # Bypass the actual socket constructor; exercise the real independent
        # decoder and recording path using bytes in memory instead.
        client = self.actor.RecordingClient.__new__(self.actor.RecordingClient)
        client.serial = 2
        client.receive_index = 0
        client.recorded_bytes = 0
        client.calls = []
        client.receives = []
        client.name = ":1.20"
        client.bus_id = None
        client.deadline = float("inf")
        client.sock = MemorySocket()
        stream = io.BytesIO(b"".join(packets))

        def read(length, fds):
            data = stream.read(length)
            self.assertEqual(len(data), length)
            return data

        client.read = read
        return client

    def test_reply_filter_preserves_intervening_signals_and_physical_serials(self):
        client = self.client([
            notification("NameAcquired", 90, wire.string(NAME), destination=":1.20"),
            response(91, 3, wire.u32(1), "u"),
            notification("NameOwnerChanged", 92,
                         wire.string(NAME) + wire.padding(len(wire.string(NAME)), 4)
                         + wire.string("") + wire.padding(len(wire.string("")), 4)
                         + wire.string(":1.20"), "sss"),
            response(93, 4, wire.string(BUS_ID), "s"),
        ])
        reply = client.query("RequestName", "su", wire.string(NAME)
                             + wire.padding(len(wire.string(NAME)), 4) + wire.u32(0))
        self.assertEqual((reply["serial"], reply["fields"][5]), (91, 3))
        snapshot = client.snapshot()
        self.assertEqual([event["index"] for event in snapshot["receives"]], [1, 2, 3, 4])
        self.assertEqual([event["serial"] for event in snapshot["receives"]], [90, 91, 92, 93])
        self.assertEqual([event["fields"].get("3") for event in snapshot["receives"]],
                         ["NameAcquired", None, "NameOwnerChanged", None])
        self.assertEqual([call["member"] for call in snapshot["calls"]], ["RequestName", "GetId"])
        self.assertEqual([call["serial"] for call in snapshot["calls"]], [3, 4])
        self.assertEqual([bytes.fromhex(call["wire_hex"]) for call in snapshot["calls"]],
                         client.sock.writes)
        self.assertEqual(client.bus_id, BUS_ID)
        self.assertEqual(json.loads(json.dumps(snapshot)), snapshot)
        self.assertTrue(all(event["fd_count"] == 0 for event in snapshot["receives"]))

    def test_snapshots_keep_global_receive_index_without_mutating_prior_records(self):
        client = self.client([response(71, 3, wire.string(BUS_ID), "s"),
                              response(72, 4, wire.string(BUS_ID), "s")])
        first = client.snapshot()
        frozen = json.dumps(first, sort_keys=True)
        second = client.snapshot()
        self.assertEqual([event["index"] for event in first["receives"]], [1])
        self.assertEqual([event["index"] for event in second["receives"]], [2])
        self.assertEqual(first["calls"][0]["serial"], 3)
        self.assertEqual(second["calls"][0]["serial"], 4)
        self.assertEqual(json.dumps(first, sort_keys=True), frozen)
        self.assertEqual(client.calls, [])
        self.assertEqual(client.receives, [])

    def test_source_binding_preserves_the_original_fourteen_actions(self):
        source = self.actor.comparison_source()
        self.assertEqual(source["path"], "apps/gao_bus/test/name_reference_test.exs")
        self.assertEqual(source["sha256"],
                         "57d95a42205808db0a0d554f23b2750e1b3b23be7a125bf99ead277da09c62c5")
        self.assertEqual(source["actions"], [
            ["request", 0, 0], ["request", 0, 1], ["request", 1, 0],
            ["request", 2, 0], ["request", 1, 1], ["request", 3, 2],
            ["request", 1, 2], ["release", 3], ["request", 1, 2],
            ["request", 1, 5], ["request", 3, 2], ["request", 0, 4],
            ["release", 2], ["release", 3]])

    def test_distinct_observer_subscription_keeps_the_participant_rule(self):
        self.assertIn("observer", inspect.signature(self.actor.RecordingClient).parameters,
                      "observer must subscribe to registrations before participant Hello")
        for observer in (False, True):
            with self.subTest(observer=observer):
                stream = io.BytesIO(response(71, 3, b"", ""))

                def memory_constructor(client, path, negotiate=True):
                    self.assertFalse(negotiate)
                    self.assertEqual(path, "unused-memory-only")
                    client.sock = MemorySocket()
                    client.name = ":1.20"

                    def read(length, fds):
                        data = stream.read(length)
                        self.assertEqual(len(data), length)
                        return data

                    client.read = read

                with mock.patch.object(self.actor.wire.Client, "__init__", memory_constructor):
                    client = self.actor.RecordingClient("unused-memory-only", float("inf"),
                                                        observer=observer)
                rule = self.actor.oracle.WATCH_MATCH if observer else self.actor.oracle.MATCH
                expected_rule = ("type='signal',sender='org.freedesktop.DBus',"
                                 "interface='org.freedesktop.DBus',member='NameOwnerChanged'")
                if not observer:
                    expected_rule += ",arg0='org.foundation.ReferenceQueue'"
                self.assertEqual(rule, expected_rule)
                self.assertEqual(client.calls[0]["body_hex"], wire.string(rule).hex())
                self.assertEqual(client.sock.writes,
                                 [wire.call("AddMatch", 3, "s", wire.string(rule))])

    def test_complete_memory_replay_connects_recorder_to_the_pure_oracle(self):
        spec = importlib.util.spec_from_file_location("p07_synthetic_fixture", HERE / "oracle_test.py")
        fixtures = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixtures)
        expected = fixtures.fixture()
        report = json.loads(json.dumps(expected))
        kinds = {1: "o", 2: "s", 3: "s", 4: "s", 5: "u", 6: "s", 7: "s", 8: "g"}
        clients = {}
        for role in "ABCDW":
            snapshots = [expected["setup"][role]]
            if role == "W":
                snapshots += [r["observer"] for r in expected["registrations"]]
            snapshots += [s["peers"][role] for s in expected["steps"]]
            packets = [wire.frame(event["type"], event["serial"],
                                  [(int(k), kinds[int(k)], v) for k, v in event["fields"].items()],
                                  bytes.fromhex(event["body_hex"]))
                       for snapshot in snapshots for event in snapshot["receives"]]
            client = self.client(packets)
            client.name = wire.read_string(client.reply(1)["body"])
            client.reply(2)
            rule = self.actor.oracle.WATCH_MATCH if role == "W" else self.actor.oracle.MATCH
            client.query("AddMatch", "s", wire.string(rule))
            report["setup"][role] = client.snapshot()
            clients[role] = client
        for registration in report["registrations"]:
            registration["observer"] = clients["W"].snapshot()
        for step in report["steps"]:
            action = step["action"]
            client = clients["ABCD"[action[1]]]
            body = wire.string(NAME)
            if action[0] == "request":
                client.query("RequestName", "su", body + wire.padding(len(body), 4)
                             + wire.u32(action[2]))
            else:
                client.query("ReleaseName", "s", body)
            client.query("ListQueuedOwners", "s", wire.string(NAME))
            step["peers"] = {role: peer.snapshot() for role, peer in clients.items()}
        self.assertEqual(report, expected)
        result = self.actor.oracle.validate(report)
        self.assertEqual(result["steps"], 14)
        self.assertEqual([len(result["streams"][r]) for r in "ABCDW"], [10, 8, 6, 10, 6])
        self.assertEqual(len(result["registration_stream"]), 8)
        self.assertTrue(all(len(events) == 5 for events in result["hello_streams"].values()))

    def test_interrupted_observer_journal_keeps_raw_evidence_without_losing_other_records(self):
        self.assertTrue(hasattr(self.actor, "_observer_journal"),
                        "interrupted observer journal must not discard the final report")
        with tempfile.TemporaryDirectory(prefix="osbus-p07-offline-journal-") as directory:
            complete = {"identity": {"unique": ":1.30"}, "snapshot": {"calls": [], "receives": []}}
            Path(directory, "00.json").write_text(json.dumps(complete))
            interrupted = b'{"identity": {"unique": ":1.'
            Path(directory, "01.json").write_bytes(interrupted)
            journal, errors = self.actor._observer_journal(directory)
        self.assertEqual(journal["00.json"], complete)
        self.assertEqual(bytes.fromhex(journal["01.json"]["raw_hex"]), interrupted)
        self.assertIn("01.json", errors[0])


if __name__ == "__main__":
    unittest.main()
