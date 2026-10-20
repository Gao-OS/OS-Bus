"""Data-only C contract regressions; never run an actor or open a socket."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
ACTOR = ROOT / "apps/gao_bus/test/fixtures/peer_whole_stream_actor.py"


def encoded_string(value):
    data = value.encode()
    return (struct.pack("<I", len(data)) + data + b"\0").hex()


class ActorTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(ACTOR.is_file(), "whole-stream actor has not been implemented")
        sys.path.insert(0, str(ACTOR.parent))
        self.addCleanup(sys.path.remove, str(ACTOR.parent))
        spec = importlib.util.spec_from_file_location("whole_stream_actor", ACTOR)
        self.actor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.actor)

    def record(self, uid=1000):
        stream = self.actor.build_stream(uid)
        name, observer, bus_id = ":1.2", ":1.1", encoded_string("b" * 32)
        common = {6: name, 7: "org.freedesktop.DBus", 8: "s"}
        receipts = [
            {"type": 2, "serial": 20, "fields": dict(common), "body": encoded_string(name)},
            {"type": 4, "serial": 21, "fields": {
                1: "/org/freedesktop/DBus", 2: "org.freedesktop.DBus", 3: "NameAcquired",
                6: name, 7: "org.freedesktop.DBus", 8: "s"}, "body": encoded_string(name)},
            {"type": 2, "serial": 22, "fields": dict(common), "body": bus_id},
        ]
        receipts[0]["fields"][5] = 1
        receipts[2]["fields"][5] = 2
        return {
            "event": "completed", "family": "C", "id": "coalesced", "result": "PASS",
            "source": name, "observer": observer, "bus_id": bus_id,
            "identity": {"pid": 123, "starttime_ticks": 456, "uid": uid, "euid": uid,
                         "gid": 100, "egid": 100},
            "connection": {"pid": 123, "starttime_ticks": 456, "fd": 5, "device": 9, "inode": 10},
            "peer_credentials": [321, uid, 100], "writes": [stream.hex()],
            "stream": stream.hex(), "stream_sha256": hashlib.sha256(stream).hexdigest(),
            "ok": (b"OK " + b"a" * 32 + b"\r\n").hex(), "receipts": receipts,
            "reply_serials": [1, 2], "received_fds": 0, "buffered_hex": "", "socket_pending": False,
        }

    def test_stream_has_exact_literals_for_both_existing_identities(self):
        for uid, auth_hash in [(1000, "438be30dcc804334af6952084e1b1d9cf7625169687c1769a1605ca6f74e0ae0"),
                               (1101, "ff2b90ba06046a9ffb1794a46b70b12eb8e1ef1244170d664463d97aa7d9b005")]:
            with self.subTest(uid=uid):
                data = self.actor.build_stream(uid)
                self.assertEqual(len(data), 288)
                self.assertEqual(hashlib.sha256(data[:25]).hexdigest(), auth_hash)
                self.assertEqual(data[25:32], b"BEGIN\r\n")
                self.assertEqual(hashlib.sha256(data[32:160]).hexdigest(),
                                 "a61b73fba939dd84950077ab28fe87bd055d5862b145028aeeb03ac3125fbf31")
                self.assertEqual(hashlib.sha256(data[160:]).hexdigest(),
                                 "f55d450521f6041ef2085a7e893bc6b8c80210feea6d97fb3485d101fe9af575")
                if uid == 1101:
                    self.assertEqual(hashlib.sha256(data).hexdigest(),
                                     "c9524d7e84e97ad70e650de7a1926b3ef2fe0c9c52abdd6273cabe0fb0279753")

    def test_uid_must_be_a_positive_integer_producing_auth25(self):
        for uid in [True, 0, -1, "1000", 999, 10000]:
            with self.subTest(uid=uid), self.assertRaises(AssertionError):
                self.actor.build_stream(uid)

    def test_valid_record_and_json_round_trip_preserve_inputs(self):
        for uid in [1000, 1101]:
            original = self.record(uid)
            unchanged = copy.deepcopy(original)
            self.assertIsNone(self.actor.validate_case(original))
            self.assertEqual(original, unchanged)
            self.assertIsNone(self.actor.validate_case(json.loads(json.dumps(original))))

    def test_only_one_exact_source_write_is_accepted(self):
        original = self.record()
        stream = original["stream"]
        for writes in [[], [stream, stream], [stream[:50], stream[50:]], [stream[:-2]], ["00" + stream]]:
            case = copy.deepcopy(original)
            case["writes"] = writes
            with self.subTest(writes=len(writes)), self.assertRaises(AssertionError):
                self.actor.validate_case(case)

    def test_stream_identity_digest_and_case_status_are_bound(self):
        for key, value in [("stream", "00" * 288), ("stream_sha256", "0" * 64),
                           ("family", "P"), ("id", "pipelined"), ("result", "FAIL")]:
            case = self.record()
            case[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.actor.validate_case(case)
        case = self.record()
        case["identity"]["uid"] = case["identity"]["euid"] = 1101
        with self.assertRaises(AssertionError):
            self.actor.validate_case(case)

    def test_missing_extra_reversed_and_error_replies_are_rejected(self):
        mutations = [lambda rows: rows.pop(), lambda rows: rows.append(copy.deepcopy(rows[0])),
                     lambda rows: rows.reverse(), lambda rows: rows[0].update(type=3),
                     lambda rows: rows[2]["fields"].update({5: 1})]
        for mutate in mutations:
            case = self.record()
            mutate(case["receipts"])
            with self.assertRaises(AssertionError):
                self.actor.validate_case(case)

    def test_reply_bodies_sender_destination_signal_and_rights_are_checked(self):
        mutations = [lambda c: c["receipts"][0].update(body=encoded_string(":1.9")),
                     lambda c: c["receipts"][2].update(body=encoded_string("c" * 32)),
                     lambda c: c["receipts"][0]["fields"].update({7: ":1.9"}),
                     lambda c: c["receipts"][2]["fields"].update({6: ":1.9"}),
                     lambda c: c["receipts"][1]["fields"].update({3: "NameLost"}),
                     lambda c: c["receipts"][1].update(body=encoded_string(":1.9")),
                     lambda c: c["receipts"][0]["fields"].update({9: 1}),
                     lambda c: c["receipts"][2]["fields"].update({4: "org.example.Error"})]
        for mutate in mutations:
            case = self.record()
            mutate(case)
            with self.assertRaises(AssertionError):
                self.actor.validate_case(case)

    def test_ok_pending_rights_and_order_summary_are_checked(self):
        for key, value in [("ok", (b"REJECTED EXTERNAL\r\n").hex()),
                           ("ok", (b"OK " + b"z" * 32 + b"\r\n").hex()),
                           ("socket_pending", True), ("buffered_hex", "00"),
                           ("received_fds", 1), ("received_fds", False), ("reply_serials", [2, 1])]:
            case = self.record()
            case[key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.actor.validate_case(case)

    def health(self, serial):
        case = self.record()
        observer, bus_id = case["observer"], case["bus_id"]
        return [{"type": 2, "serial": 50 + n,
                 "fields": {5: serial + n, 6: observer, 7: "org.freedesktop.DBus", 8: "s"},
                 "body": encoded_string(observer) if n == 0 else bus_id} for n in range(2)]

    def events(self):
        case = self.record()
        case["health"] = self.health(10)
        observer, source, bus_id = case["observer"], case["source"], case["bus_id"]
        control = copy.deepcopy(case["receipts"])
        for row in control:
            row["fields"][6] = observer
            if row["type"] == 4 or row["fields"].get(5) == 1:
                row["body"] = encoded_string(observer)
        return [
            {"event": "ready", **{k: case[k] for k in ["observer", "bus_id", "ok", "identity", "stream", "stream_sha256"]},
             "control": control},
            {"event": "opened", "connection": case["connection"], "peer_credentials": case["peer_credentials"]},
            case,
            {"event": "closed", "source": source, "observer": observer, "bus_id": bus_id,
             "health": self.health(20), "disappearance_serials": [100],
             "ownership_disappearance_seconds": 0.01,
             "ownership_disappearance": [{"type": 3, "serial": 70, "fields": {
                 4: "org.freedesktop.DBus.Error.NameHasNoOwner", 5: 100, 6: observer,
                 7: "org.freedesktop.DBus", 8: "s"}, "body": encoded_string("gone")}]},
            {"event": "result", "observer": observer, "bus_id": bus_id,
             "health": self.health(30), "cases": 1, "result": "PASS"},
        ]

    def test_complete_event_protocol_and_json_round_trip(self):
        events = self.events()
        unchanged = copy.deepcopy(events)
        self.assertIsNone(self.actor.validate_run(events))
        self.assertEqual(events, unchanged)
        self.assertIsNone(self.actor.validate_run(json.loads(json.dumps(events))))

    def test_missing_duplicate_reordered_or_inconsistent_events_are_rejected(self):
        mutations = [lambda e: e.pop(), lambda e: e.append(copy.deepcopy(e[-1])),
                     lambda e: e.reverse(), lambda e: e[0].update(stream="00"),
                     lambda e: e[1].update(connection={}),
                     lambda e: e[3].update(source=":1.99"),
                     lambda e: e[-1].update(cases=2), lambda e: e[-1].update(result="FAIL")]
        for mutate in mutations:
            events = self.events()
            mutate(events)
            with self.assertRaises(AssertionError):
                self.actor.validate_run(events)

    def test_health_and_disappearance_must_match_the_observer_and_source(self):
        mutations = [lambda e: e[2]["health"][0].update(body=encoded_string(":1.99")),
                     lambda e: e[3]["health"][1].update(type=3),
                     lambda e: e[-1]["health"][1].update(body=encoded_string("wrong")),
                     lambda e: e[3].update(ownership_disappearance=[]),
                     lambda e: e[3].update(ownership_disappearance_seconds=1.6),
                     lambda e: e[3]["ownership_disappearance"][0]["fields"].update({4: "org.example.Error"}),
                     lambda e: e[3]["ownership_disappearance"][0]["fields"].update({5: 101})]
        for mutate in mutations:
            events = self.events()
            mutate(events)
            with self.assertRaises(AssertionError):
                self.actor.validate_run(events)


if __name__ == "__main__":
    unittest.main()
