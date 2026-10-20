"""Small data-only checks; importing the actor never connects a socket."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys
import unittest


ROOT = Path(__file__).resolve().parents[3]
ACTOR = ROOT / "apps/gao_bus/test/fixtures/peer_unknown_header_actor.py"


def encoded(value):
    data = value.encode()
    return (struct.pack("<I", len(data)) + data + b"\0").hex()


class ActorTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ACTOR.parent))
        self.addCleanup(sys.path.remove, str(ACTOR.parent))
        spec = importlib.util.spec_from_file_location("unknown_header_actor", ACTOR)
        self.actor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.actor)

    def response(self, serial, destination, body):
        return dict(type=2, serial=50 + serial,
                    fields={5: serial, 6: destination, 7: "org.freedesktop.DBus", 8: "s"}, body=body)

    def registration(self, name, bus_id):
        return [self.response(1, name, encoded(name)),
                dict(type=4, serial=40, fields={1: "/org/freedesktop/DBus", 2: "org.freedesktop.DBus",
                     3: "NameAcquired", 6: name, 7: "org.freedesktop.DBus", 8: "s"}, body=encoded(name)),
                self.response(2, name, bus_id)]

    def events(self):
        observer, source, bus_id = ":1.1", ":1.2", encoded("a" * 32)
        identity = dict(pid=123, starttime_ticks=456, uid=1101, euid=1101, gid=1101, egid=1101)
        connection = dict(pid=123, starttime_ticks=456, fd=5, device=9, inode=10)
        common = dict(observer=observer, bus_id=bus_id)
        ready = dict(event="ready", **common, identity=identity,
                     frame=self.actor.unknown_header_call().hex(), control=self.registration(observer, bus_id),
                     writes=[b"\0AUTH EXTERNAL 31313031\r\n".hex(),
                             (b"BEGIN\r\n" + self.actor.HELLO + self.actor.GET_ID).hex()])
        opened = dict(event="opened", source=source, connection=connection, peer_credentials=[321, 1101, 1101],
                      registration=self.registration(source, bus_id), writes=list(ready["writes"]))
        completed = dict(event="completed", **common, source=source, identity=identity,
                         connection=connection, peer_credentials=opened["peer_credentials"], frame=ready["frame"],
                         writes=[ready["frame"], self.actor.call("GetId", 4).hex()], reply_serials=[3, 4],
                         receipts=[self.response(n, source, bus_id) for n in (3, 4)],
                         received_fds=0, buffered_hex="", socket_pending=False)
        rows = [ready, opened, completed, dict(event="closed", **common, source=source),
                dict(event="result", **common, cases=1, result="PASS")]
        for row, serial in zip(rows[2:], (10, 20, 30)):
            row["health"] = [self.response(serial, observer, encoded(observer)),
                             self.response(serial + 1, observer, bus_id)]
        return rows

    def test_frame_is_an_ordinary_empty_get_id_with_one_string_extension(self):
        data = self.actor.unknown_header_call()
        self.assertEqual(data[:12], b"l\x01\0\x01" + struct.pack("<II", 0, 3))
        header_size, = struct.unpack_from("<I", data, 12)
        self.assertEqual(len(data), 16 + header_size + (-header_size % 8))
        fields, offset = {}, 16
        while offset < 16 + header_size:
            offset += -offset % 8
            code, variant_length, kind, terminator = data[offset:offset + 4]
            self.assertEqual((variant_length, terminator), (1, 0))
            offset += 4
            if kind == ord("g"):
                size = data[offset]
                value = data[offset + 1:offset + 1 + size].decode()
                offset += size + 2
            else:
                self.assertIn(kind, (ord("s"), ord("o")))
                size, = struct.unpack_from("<I", data, offset)
                value = data[offset + 4:offset + 4 + size].decode()
                self.assertEqual(data[offset + 4 + size], 0)
                offset += size + 5
            self.assertNotIn(code, fields)
            fields[code] = (chr(kind), value)
        self.assertEqual(fields, {1: ("o", "/org/freedesktop/DBus"),
                         2: ("s", "org.freedesktop.DBus"), 3: ("s", "GetId"),
                         6: ("s", "org.freedesktop.DBus"), 8: ("g", ""),
                         42: ("s", "org.foundation.UnknownHeader")})
        self.assertNotIn(9, fields)

    def test_complete_contract_survives_json_without_mutation(self):
        events = self.events()
        before = copy.deepcopy(events)
        self.assertIsNone(self.actor.validate_run(events))
        self.assertEqual(events, before)
        self.assertIsNone(self.actor.validate_run(json.loads(json.dumps(events))))

    def test_wrong_correlation_body_or_extra_receipt_is_rejected(self):
        for mutate in [lambda e: e[2]["receipts"][0]["fields"].update({5: 4}),
                       lambda e: e[2]["receipts"][1].update(body=encoded("b" * 32)),
                       lambda e: e[2]["receipts"].append(copy.deepcopy(e[2]["receipts"][0])),
                       lambda e: e[3]["health"][0].update(body=encoded(":1.9"))]:
            events = self.events()
            mutate(events)
            with self.assertRaises(AssertionError):
                self.actor.validate_run(events)

    def test_data_or_rights_and_incomplete_run_are_rejected(self):
        for key, value in [("received_fds", 1), ("socket_pending", True), ("buffered_hex", "00")]:
            events = self.events()
            events[2][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                self.actor.validate_run(events)
        with self.assertRaises(AssertionError):
            self.actor.validate_run(self.events()[:-1])


if __name__ == "__main__":
    unittest.main()
