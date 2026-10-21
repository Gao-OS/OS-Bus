"""Offline synthetic ownership transcripts; these never qualify runtime evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import struct
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NAME = "org.foundation.ReferenceQueue"
BUS = "org.freedesktop.DBus"
PATH = "/org/freedesktop/DBus"
ROLES = "ABCDW"
ACTIONS = [["request", 0, 0], ["request", 0, 1], ["request", 1, 0],
           ["request", 2, 0], ["request", 1, 1], ["request", 3, 2],
           ["request", 1, 2], ["release", 3], ["request", 1, 2],
           ["request", 1, 5], ["request", 3, 2], ["request", 0, 4],
           ["release", 2], ["release", 3]]
EXPECTED = [(1, "A"), (4, "A"), (2, "AB"), (2, "ABC"), (2, "ABC"),
            (1, "DABC"), (2, "DABC"), (1, "ABC"), (1, "BAC"),
            (4, "BAC"), (1, "DAC"), (3, "DC"), (1, "D"), (1, None)]
TRANSITIONS = {1: ("", "A"), 6: ("A", "D"), 8: ("D", "A"),
               9: ("A", "B"), 11: ("B", "D"), 14: ("D", "")}
MATCH = ("type='signal',sender='org.freedesktop.DBus',"
         "interface='org.freedesktop.DBus',member='NameOwnerChanged',"
         "arg0='org.foundation.ReferenceQueue'")
WATCH_MATCH = ("type='signal',sender='org.freedesktop.DBus',"
               "interface='org.freedesktop.DBus',member='NameOwnerChanged'")


def u32(value):
    return struct.pack("<I", value)


def strings(*values):
    data = b""
    for value in values:
        data += b"\0" * (-len(data) % 4)
        encoded = value.encode()
        data += u32(len(encoded)) + encoded + b"\0"
    return data


def array(values):
    data = strings(*values)
    return u32(len(data)) + data


def wire(member, serial, signature, body):
    fields = [(1, "o", PATH), (2, "s", BUS), (3, "s", member),
              (6, "s", BUS), (8, "g", signature)]
    data = b""
    for code, kind, value in fields:
        data += b"\0" * (-len(data) % 8) + bytes([code, 1]) + kind.encode() + b"\0"
        if kind == "g":
            data += bytes([len(value)]) + value.encode() + b"\0"
        else:
            data += strings(value)
    return (b"l\x01\x00\x01" + u32(len(body)) + u32(serial) + u32(len(data))
            + data + b"\0" * (-len(data) % 8) + body).hex()


def fixture(offset=0):
    import hashlib
    names = {role: f":1.{offset + i + 1}" for i, role in enumerate("WABCD")}
    bus_id = "a" * 32
    report = {"schema": 2, "kind": "synthetic", "backend": "candidate",
              "profile": "synthetic-ordinary", "name": NAME,
              "source": {"path": "apps/gao_bus/test/name_reference_test.exs",
                         "sha256": hashlib.sha256((ROOT / "apps/gao_bus/test/name_reference_test.exs").read_bytes()).hexdigest(),
                         "actions": copy.deepcopy(ACTIONS)},
              "actors": {r: {"unique": names[r], "pid": 700 if r != "W" else 701,
                              "uid": 1000, "gid": 1000, "bus_id": bus_id} for r in ROLES},
              "setup": {}, "registrations": [], "steps": []}
    serials = dict.fromkeys(ROLES, 4)
    indexes = dict.fromkeys(ROLES, 0)
    physical = 1000 + offset

    def event(role, kind, fields, body):
        nonlocal physical
        physical += 1
        indexes[role] += 1
        return {"index": indexes[role], "type": kind, "serial": physical,
                "fields": fields, "body_hex": body.hex(), "fd_count": 0}

    def reply(role, serial, signature, body, error=None):
        fields = {"5": serial, "6": names[role], "7": BUS, "8": signature}
        if error:
            fields["4"] = BUS + ".Error." + error
        return event(role, 3 if error else 2, fields, body)

    def call(member, serial, signature="", body=b""):
        return {"serial": serial, "member": member, "signature": signature,
                "body_hex": body.hex(), "wire_hex": wire(member, serial, signature, body)}

    def acquired(role):
        return event(role, 4, {"1": PATH, "2": BUS, "3": "NameAcquired",
                               "6": names[role], "7": BUS, "8": "s"}, strings(names[role]))

    for role in "WABCD":
        report["setup"][role] = {
            "calls": [call("AddMatch", 3, "s", strings(WATCH_MATCH if role == "W" else MATCH)),
                      call("GetId", 4)],
            "receives": [reply(role, 1, "s", strings(names[role])),
                         acquired(role),
                         reply(role, 2, "as", array([BUS, names[role]])),
                         reply(role, 3, "", b""), reply(role, 4, "s", strings(bus_id))]}
        if role != "W":
            serials["W"] += 1
            fields = {"1": PATH, "2": BUS, "3": "NameOwnerChanged", "7": BUS, "8": "sss"}
            report["registrations"].append({"role": role, "observer": {
                "calls": [call("GetId", serials["W"])],
                "receives": [event("W", 4, fields, strings(names[role], "", names[role])),
                             reply("W", serials["W"], "s", strings(bus_id))]}})
    for index, (action, (result, queue)) in enumerate(zip(ACTIONS, EXPECTED), 1):
        peers = {r: {"calls": [], "receives": []} for r in ROLES}
        mutator = ROLES[action[1]]
        peer = peers[mutator]
        serials[mutator] += 1
        member = "RequestName" if action[0] == "request" else "ReleaseName"
        body = strings(NAME)
        if action[0] == "request":
            body += b"\0" * (-len(body) % 4) + u32(action[2])
        peer["calls"].append(call(member, serials[mutator], "su" if action[0] == "request" else "s", body))
        peer["receives"].append(reply(mutator, serials[mutator], "u", u32(result)))
        if index in TRANSITIONS:
            old, new = TRANSITIONS[index]
            for role in ROLES:
                fields = {"1": PATH, "2": BUS, "3": "NameOwnerChanged", "7": BUS, "8": "sss"}
                peers[role]["receives"].append(event(role, 4, fields, strings(NAME, names.get(old, ""), names.get(new, ""))))
                if role in (old, new):
                    fields = {"1": PATH, "2": BUS, "3": "NameLost" if role == old else "NameAcquired",
                              "6": names[role], "7": BUS, "8": "s"}
                    peers[role]["receives"].append(event(role, 4, fields, strings(NAME)))
        serials[mutator] += 1
        peer["calls"].append(call("ListQueuedOwners", serials[mutator], "s", strings(NAME)))
        peer["receives"].append(reply(mutator, serials[mutator], "as" if queue else "s",
                                       array([names[r] for r in queue]) if queue else strings("No owner"),
                                       None if queue else "NameHasNoOwner"))
        for role in ROLES:
            serials[role] += 1
            peers[role]["calls"].append(call("GetId", serials[role]))
            peers[role]["receives"].append(reply(role, serials[role], "s", strings(bus_id)))
        report["steps"].append({"index": index, "action": copy.deepcopy(action), "peers": peers})
    return report


def reindex(report):
    for role in ROLES:
        index = 0
        registrations = [r["observer"] for r in report["registrations"]] if role == "W" else []
        for snapshot in [report["setup"][role]] + registrations + [s["peers"][role] for s in report["steps"]]:
            for event in snapshot["receives"]:
                index += 1
                event["index"] = index


class OracleTests(unittest.TestCase):
    def setUp(self):
        path = HERE / "oracle.py"
        if not path.exists():
            self.fail("P07 transcript oracle behavior is absent")
        spec = importlib.util.spec_from_file_location("p07_oracle", path)
        self.oracle = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.oracle)

    def test_schema2_hello_and_observer_registration_streams_are_derived(self):
        try:
            result = self.oracle.validate(fixture())
        except ValueError as error:
            self.fail(f"complete schema2 Hello/registration transcript must validate: {error}")
        for role in ROLES:
            stream = result["hello_streams"][role]
            self.assertEqual([e.get("reply_to", e.get("member")) for e in stream],
                             ["Hello", "NameAcquired", "ListNames", "AddMatch", "GetId"])
            self.assertEqual(stream[1]["body"], [role])
            self.assertEqual(stream[1]["destination"], role)
            self.assertEqual(stream[0]["body"], [role])
            self.assertNotIn("body", stream[2])
            self.assertNotIn("body", stream[4])
        stream = result["registration_stream"]
        self.assertEqual(len(stream), 8)
        self.assertEqual([e["body"] for e in stream if e.get("member") == "NameOwnerChanged"],
                         [[r, "", r] for r in "ABCD"])
        self.assertEqual([e["reply_to"] for e in stream if "reply_to" in e], ["GetId"] * 4)

    def test_unique_name_acquisition_is_required_correct_and_after_hello(self):
        def duplicate(report, role):
            events = report["setup"][role]["receives"]
            event = copy.deepcopy(events[1])
            event["serial"] += 100000
            events.insert(2, event)

        def before_hello(report, role):
            events = report["setup"][role]["receives"]
            events[0], events[1] = events[1], events[0]

        def after_barrier(report, role):
            events = report["setup"][role]["receives"]
            events.append(events.pop(1))

        mutations = [
            lambda r, role: r["setup"][role]["receives"].pop(1),
            duplicate,
            before_hello, after_barrier,
            lambda r, role: r["setup"][role]["receives"][1]["fields"].update({"1": "/wrong"}),
            lambda r, role: r["setup"][role]["receives"][1]["fields"].update({"2": "org.wrong.Interface"}),
            lambda r, role: r["setup"][role]["receives"][1]["fields"].update({"7": ":1.unknown"}),
            lambda r, role: r["setup"][role]["receives"][1]["fields"].update({"6": ":1.unknown"}),
            lambda r, role: r["setup"][role]["receives"][1]["fields"].update({"8": "u"}),
            lambda r, role: r["setup"][role]["receives"][1]["fields"].update({"5": 1}),
            lambda r, role: r["setup"][role]["receives"][1].update({"body_hex": strings(":1.unknown").hex()}),
        ]
        for role in ROLES:
            for index, mutate in enumerate(mutations):
                with self.subTest(role=role, mutation=index):
                    report = fixture()
                    mutate(report, role)
                    reindex(report)
                    with self.assertRaises((AssertionError, ValueError)):
                        self.oracle.validate(report)

    def test_observer_registration_observations_are_complete_and_ordered(self):
        def duplicate(report):
            events = report["registrations"][0]["observer"]["receives"]
            event = copy.deepcopy(events[0])
            event["serial"] += 100000
            events.insert(1, event)

        def wrong_order(report):
            report["registrations"][0], report["registrations"][1] = report["registrations"][1], report["registrations"][0]

        mutations = [
            lambda r: r["registrations"].pop(),
            lambda r: r["registrations"].append(copy.deepcopy(r["registrations"][-1])),
            wrong_order,
            lambda r: r["registrations"][0]["observer"]["receives"].pop(0),
            duplicate,
            lambda r: r["registrations"][0]["observer"]["receives"].reverse(),
            lambda r: r["registrations"][0]["observer"]["receives"][0]["fields"].update({"6": r["actors"]["W"]["unique"]}),
            lambda r: r["registrations"][0]["observer"]["receives"][0]["fields"].update({"7": ":1.unknown"}),
            lambda r: r["registrations"][0]["observer"]["receives"][0]["fields"].update({"8": "s"}),
            lambda r: r["registrations"][0]["observer"]["receives"][0].update({"body_hex": strings(r["actors"]["B"]["unique"], "", r["actors"]["B"]["unique"]).hex()}),
            lambda r: r["registrations"][0]["observer"]["receives"][1]["fields"].update({"5": 4}),
            lambda r: r["registrations"][0]["observer"]["calls"].clear(),
            lambda r: r["registrations"][0]["observer"]["receives"].clear(),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                report = fixture()
                mutate(report)
                reindex(report)
                with self.assertRaises((AssertionError, ValueError)):
                    self.oracle.validate(report)

    def test_valid_hello_receive_order_difference_is_compared(self):
        left, right = fixture(), fixture()
        left["backend"] = "reference"
        events = right["setup"]["A"]["receives"]
        events[1], events[2] = events[2], events[1]
        reindex(right)
        self.oracle.validate(right)
        result = self.oracle.compare(left, right)
        self.assertFalse(result["equal"])
        self.assertIn("A", result["differences"]["hello"])
        self.assertFalse(result["qualifies_original_gate"])

    def test_legacy_schema_without_registration_observations_is_rejected(self):
        report = fixture()
        report["schema"] = 1
        report.pop("registrations")
        with self.assertRaises((AssertionError, ValueError)):
            self.oracle.validate(report)

    def test_complete_synthetic_transcript_derives_replies_and_signal_streams(self):
        result = self.oracle.validate(fixture())
        self.assertEqual(self.oracle.ACTIONS, ACTIONS)
        self.assertEqual(result["steps"], 14)
        self.assertEqual([len(result["streams"][r]) for r in ROLES], [10, 8, 6, 10, 6])
        self.assertEqual(result["derived"], [{"result": n, "queue": list(q) if q else None} for n, q in EXPECTED])

    def test_json_roundtrip_and_unique_name_remapping_compare_equal(self):
        reference = json.loads(json.dumps(fixture(90)))
        reference["backend"] = "reference"
        for role in ROLES:
            reference["actors"][role]["bus_id"] = "b" * 32
            reference["actors"][role]["pid"] += 1000
            snapshots = [reference["setup"][role]] + [s["peers"][role] for s in reference["steps"]]
            if role == "W":
                snapshots += [r["observer"] for r in reference["registrations"]]
            for snapshot in snapshots:
                # GetId is each snapshot's last reply; its actual bus ID is
                # validated against this backend, then excluded from comparison.
                snapshot["receives"][-1]["body_hex"] = strings("b" * 32).hex()
            listed = next(e for e in reference["setup"][role]["receives"] if e["fields"].get("5") == 2)
            listed["body_hex"] = array([BUS, reference["actors"][role]["unique"], "org.foundation.OtherName"]).hex()
        result = self.oracle.compare(reference, fixture())
        self.assertTrue(result["equal"])
        self.assertFalse(result["qualifies_original_gate"])

    def test_physical_sender_serial_is_not_reply_serial(self):
        report = fixture()
        self.assertNotEqual(report["steps"][0]["peers"]["A"]["receives"][0]["serial"], 5)
        self.oracle.validate(report)
        report["steps"][0]["peers"]["A"]["receives"][0]["fields"]["5"] = 999
        with self.assertRaises((AssertionError, ValueError)):
            self.oracle.validate(report)

    def test_barrier_must_correlate_and_follow_all_observed_signals(self):
        def move_barrier(report):
            events = report["steps"][0]["peers"]["W"]["receives"]
            events.reverse()
            reindex(report)

        def wrong_bus(report):
            report["steps"][0]["peers"]["W"]["receives"][-1]["body_hex"] = strings("b" * 32).hex()

        def wrong_correlation(report):
            report["steps"][0]["peers"]["W"]["receives"][-1]["fields"]["5"] = 4

        for mutate in (move_barrier, wrong_bus, wrong_correlation):
            with self.subTest(mutation=mutate.__name__):
                report = fixture()
                mutate(report)
                with self.assertRaises((AssertionError, ValueError)):
                    self.oracle.validate(report)

    def test_other_valid_interleaving_remains_comparison_difference(self):
        left, right = fixture(), fixture()
        left["backend"] = "reference"
        events = right["steps"][0]["peers"]["A"]["receives"]
        events[1], events[2] = events[2], events[1]
        reindex(right)
        self.oracle.validate(right)
        result = self.oracle.compare(left, right)
        self.assertFalse(result["equal"])
        self.assertIn("A", result["differences"])

    def test_comparison_requires_matching_provenance_and_backend_roles(self):
        mutations = [
            lambda left, right: left.update({"backend": "candidate"}),
            lambda left, right: right.update({"backend": "reference"}),
            lambda left, right: right.update({"profile": "different-profile"}),
            lambda left, right: right.update({"kind": "runtime"}),
            lambda left, right: right["source"].update({"sha256": "0" * 64}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(mutation=index):
                left, right = fixture(), fixture()
                left["backend"] = "reference"
                mutate(left, right)
                with self.assertRaises((AssertionError, ValueError)):
                    self.oracle.compare(left, right)

    def test_runtime_comparison_requires_successful_complete_collection(self):
        def reports():
            left, right = fixture(), fixture()
            left["backend"] = "reference"
            for report in (left, right):
                report.update({"kind": "runtime", "status": "RECORDED_VALID",
                               "observer_exitcode": 0})
            return left, right

        left, right = reports()
        self.assertTrue(self.oracle.compare(left, right)["equal"])
        mutations = [
            lambda r: r.update({"status": "FAIL"}),
            lambda r: r.pop("status"),
            lambda r: r.update({"observer_exitcode": 1}),
            lambda r: r.pop("observer_exitcode"),
            lambda r: r.update({"observer_exitcode": False}),
            lambda r: r.update({"error": "collection failed"}),
            lambda r: r.update({"cleanup_error": "observer cleanup failed"}),
            lambda r: r.update({"journal_errors": ["receive journal incomplete"]}),
        ]
        for side in (0, 1):
            for index, mutate in enumerate(mutations):
                with self.subTest(side=side, mutation=index):
                    pair = reports()
                    mutate(pair[side])
                    # Structural validation remains available before cleanup.
                    self.oracle.validate(pair[side])
                    with self.assertRaises((AssertionError, ValueError)):
                        self.oracle.compare(*pair)

    def test_missing_duplicate_wrong_and_out_of_order_observations_fail(self):
        mutations = [
            lambda r: r["steps"][0]["peers"]["W"]["receives"].pop(0),
            lambda r: r["steps"][0]["peers"]["A"]["receives"].append(copy.deepcopy(r["steps"][0]["peers"]["A"]["receives"][1])),
            lambda r: r["steps"][0]["peers"]["A"]["receives"][1]["fields"].update({"7": ":1.unknown"}),
            lambda r: r["steps"].reverse(),
            lambda r: r["steps"][0]["peers"]["W"]["calls"].clear(),
            lambda r: r["steps"][0]["peers"]["W"]["receives"].clear(),
            lambda r: r["steps"][0]["peers"]["A"]["receives"][0].update({"body_hex": u32(2).hex()}),
            lambda r: r["steps"][0]["peers"]["A"]["receives"][-2].update({"body_hex": array([r["actors"]["B"]["unique"]]).hex()}),
            lambda r: r["actors"]["W"].update({"pid": 700}),
            lambda r: r["setup"]["A"]["calls"][0].update({"wire_hex": "00"}),
            lambda r: r["steps"][0]["peers"]["A"]["receives"][1]["fields"].update({"6": r["actors"]["A"]["unique"]}),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                report = fixture()
                mutate(report)
                with self.assertRaises((AssertionError, ValueError)):
                    self.oracle.validate(report)


if __name__ == "__main__":
    unittest.main()
