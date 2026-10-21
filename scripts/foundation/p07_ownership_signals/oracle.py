"""Pure P07 ownership transcript checks; no socket or process operations.

Synthetic transcripts exercise this oracle only. Even equal runtime streams do
not qualify the original SEM gate, which has additional required evidence.
"""
import re
import struct

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


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _uint(value):
    return type(value) is int and 0 < value < 2**32


def _hex(value):
    _require(isinstance(value, str) and re.fullmatch(r"(?:[0-9a-f]{2})*", value),
             "noncanonical hex body/wire")
    return bytes.fromhex(value)


def _u32(value):
    return struct.pack("<I", value)


def _strings(*values):
    data = b""
    for value in values:
        encoded = value.encode()
        data += b"\0" * (-len(data) % 4) + _u32(len(encoded)) + encoded + b"\0"
    return data


def _decode(signature, data):
    """Decode just the ordinary u/s/sss/as bodies used by this sequence."""
    def string_at(offset):
        aligned = offset + (-offset % 4)
        _require(data[offset:aligned] == b"\0" * (aligned - offset), "body padding")
        _require(aligned + 4 <= len(data), "truncated string length")
        length = struct.unpack_from("<I", data, aligned)[0]
        end = aligned + 4 + length
        _require(end < len(data) and data[end] == 0, "truncated string")
        try:
            value = data[aligned + 4:end].decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("invalid ordinary string") from error
        _require("\0" not in value, "embedded string terminator")
        return value, end + 1

    if signature == "u":
        _require(len(data) == 4, "UINT32 reply size")
        return [struct.unpack("<I", data)[0]]
    if signature == "as":
        _require(len(data) >= 4 and struct.unpack_from("<I", data)[0] == len(data) - 4,
                 "array extent")
        values, offset = [], 4
        while offset < len(data):
            value, offset = string_at(offset)
            values.append(value)
        return [values]
    _require(signature in ("", "s", "sss"), "unexpected body signature")
    values, offset = [], 0
    for _ in signature:
        value, offset = string_at(offset)
        values.append(value)
    _require(offset == len(data), "body extent")
    return values


def _wire(member, serial, signature, body):
    header = b""
    for code, kind, value in [(1, "o", PATH), (2, "s", BUS), (3, "s", member),
                              (6, "s", BUS), (8, "g", signature)]:
        header += b"\0" * (-len(header) % 8) + bytes([code, 1]) + kind.encode() + b"\0"
        header += bytes([len(value)]) + value.encode() + b"\0" if kind == "g" else _strings(value)
    return (b"l\x01\x00\x01" + _u32(len(body)) + _u32(serial) + _u32(len(header))
            + header + b"\0" * (-len(header) % 8) + body)


def _call(call, serial, member, signature="", body=b""):
    _require(call.get("serial") == serial and _uint(serial), "call serial sequence")
    _require(call.get("member") == member and call.get("signature") == signature,
             "call member/signature sequence")
    _require(_hex(call.get("body_hex")) == body, "call body sequence")
    _require(_hex(call.get("wire_hex")) == _wire(member, serial, signature, body),
             "call wire does not encode the recorded ordinary call")


def _reply(event, serial, unique, signature, body=None, error=None):
    fields = event["fields"]
    _require(event["type"] == (3 if error else 2), "reply type")
    _require(fields.get("5") == serial, "reply correlation")
    _require(fields.get("6") == unique and fields.get("7") == BUS, "reply routing")
    _require(fields.get("8", "") == signature, "reply signature")
    _require(fields.get("4") == error, "reply error name")
    decoded = _decode(signature, _hex(event["body_hex"]))
    if body is not None:
        _require(decoded == body, "reply body")
    return decoded


def _events(snapshot, role, state):
    _require(isinstance(snapshot, dict) and isinstance(snapshot.get("calls"), list)
             and isinstance(snapshot.get("receives"), list), "snapshot structure")
    for event in snapshot["receives"]:
        state[role]["index"] += 1
        _require(event.get("index") == state[role]["index"], "receive index sequence")
        _require(event.get("type") in (2, 3, 4) and _uint(event.get("serial")), "event type/serial")
        _require(event["serial"] not in state[role]["physical"], "duplicate physical message")
        state[role]["physical"].add(event["serial"])
        _require(event.get("fd_count") == 0, "unexpected descriptor")
        fields = event.get("fields")
        _require(isinstance(fields, dict) and all(isinstance(k, str) for k in fields),
                 "JSON header keys")
        _require(fields.get("9", 0) == 0, "unexpected UNIX_FDS header")
        _hex(event.get("body_hex"))
    return snapshot["calls"], snapshot["receives"]


def _signals(events, step, role, names):
    result = []
    for event in events:
        if event["type"] != 4:
            continue
        fields = event["fields"]
        member = fields.get("3")
        if member not in ("NameOwnerChanged", "NameAcquired", "NameLost"):
            continue
        signature = "sss" if member == "NameOwnerChanged" else "s"
        _require(fields.get("8") == signature, "ownership signal signature")
        body = _decode(signature, _hex(event["body_hex"]))
        if body[0] != NAME:
            _require(step == 0, "unexpected ownership name during action")
            continue
        _require(fields.get("1") == PATH and fields.get("2") == BUS
                 and fields.get("7") == BUS and "5" not in fields, "ownership signal metadata")
        destination = fields.get("6")
        _require(destination == (None if member == "NameOwnerChanged" else names[role]),
                 "ownership signal destination")
        normalized = {value: key for key, value in names.items()}
        result.append({"step": step, "member": member, "path": fields["1"],
                       "interface": fields["2"], "sender": fields["7"],
                       "destination": normalized.get(destination, destination),
                       "signature": signature, "body": [normalized.get(v, v) for v in body]})
    return result


def _registration_signal(event, member, unique, destination, names):
    fields = event["fields"]
    signature = "s" if member == "NameAcquired" else "sss"
    body = [unique] if member == "NameAcquired" else [unique, "", unique]
    _require(event["type"] == 4 and fields.get("1") == PATH
             and fields.get("2") == BUS and fields.get("3") == member
             and fields.get("6") == destination and fields.get("7") == BUS
             and fields.get("8") == signature and "5" not in fields
             and "4" not in fields, "registration signal metadata")
    _require(_decode(signature, _hex(event["body_hex"])) == body,
             "registration signal unique name")
    normalized = {value: key for key, value in names.items()}
    return {"type": 4, "member": member, "path": PATH, "interface": BUS,
            "sender": BUS, "destination": normalized.get(destination, destination),
            "signature": signature, "body": [normalized.get(v, v) for v in body]}


def _setup_reply(event, member, role):
    # ListNames contents and bus IDs are checked above but vary between runs.
    # Keep their position and reply metadata without comparing those values.
    result = {"type": 2, "reply_to": member, "sender": BUS, "destination": role,
              "signature": event["fields"].get("8", "")}
    if member == "Hello":
        result["body"] = [role]
    elif member == "AddMatch":
        result["body"] = []
    return result


def _hello_stream(events, replies, role, names):
    acquired = [e for e in events if e["type"] == 4 and e["fields"].get("3") == "NameAcquired"]
    _require(len(acquired) == 1, "exactly one own unique-name acquisition required")
    acquisition = acquired[0]
    signal = _registration_signal(acquisition, "NameAcquired", names[role], names[role], names)
    # Current SEM-05/candidate causal contract. This is not an assertion of
    # universal specification wording or an executed pristine-reference result.
    _require(replies[0]["index"] < acquisition["index"] < replies[-1]["index"],
             "unique-name acquisition must follow Hello reply and precede setup barrier")
    reply_members = {1: "Hello", 2: "ListNames", 3: "AddMatch", 4: "GetId"}
    stream = []
    for event in events:
        if event is acquisition:
            stream.append(signal)
        elif event["type"] in (2, 3):
            stream.append(_setup_reply(event, reply_members[event["fields"]["5"]], role))
    return stream


def validate(report):
    """Validate complete observations and retain each connection's signal order."""
    _require(isinstance(report, dict) and report.get("schema") == 2, "report schema")
    _require(report.get("kind") in ("synthetic", "runtime") and
             report.get("backend") in ("candidate", "reference"), "report provenance")
    _require(isinstance(report.get("profile"), str) and report["profile"], "profile")
    _require(report.get("name") == NAME, "target name")
    source = report.get("source", {})
    _require(source.get("path") == "apps/gao_bus/test/name_reference_test.exs"
             and re.fullmatch(r"[0-9a-f]{64}", source.get("sha256", ""))
             and source.get("actions") == ACTIONS, "source binding/actions")
    actors = report.get("actors", {})
    _require(set(actors) == set(ROLES), "five actors required")
    names = {}
    for role, actor in actors.items():
        _require(re.fullmatch(r":[0-9]+\.[0-9]+", actor.get("unique", "")), "unique identity")
        _require(_uint(actor.get("pid")) and all(type(actor.get(k)) is int and actor[k] >= 0
                                                for k in ("uid", "gid")), "process identity")
        _require(re.fullmatch(r"[0-9a-f]{32}", actor.get("bus_id", "")), "bus identity")
        names[role] = actor["unique"]
    _require(len(set(names.values())) == 5, "unique connections")
    _require(len({actors[r]["pid"] for r in "ABCD"}) == 1
             and actors["W"]["pid"] != actors["A"]["pid"], "independent observer PID")
    _require(len({actors[r]["bus_id"] for r in ROLES}) == 1, "shared bus identity")
    state = {r: {"index": 0, "physical": set(), "serial": 4} for r in ROLES}
    streams, derived = {r: [] for r in ROLES}, []
    hello_streams, registration_stream = {}, []
    _require(set(report.get("setup", {})) == set(ROLES), "setup actors")
    for role in ROLES:
        calls, events = _events(report["setup"][role], role, state)
        _require(len(calls) == 2, "setup calls")
        _call(calls[0], 3, "AddMatch", "s", _strings(WATCH_MATCH if role == "W" else MATCH))
        _call(calls[1], 4, "GetId")
        replies = [e for e in events if e["type"] != 4]
        _require(len(replies) == 4, "setup replies")
        _reply(replies[0], 1, names[role], "s", [names[role]])
        listed = _reply(replies[1], 2, names[role], "as")[0]
        _require(BUS in listed and names[role] in listed, "ListNames baseline")
        _reply(replies[2], 3, names[role], "", [])
        _reply(replies[3], 4, names[role], "s", [actors[role]["bus_id"]])
        _require(events[-1] is replies[-1], "setup barrier must end snapshot")
        _require(not _signals(events, 0, role, names), "target name present before sequence")
        hello_streams[role] = _hello_stream(events, replies, role, names)
    registrations = report.get("registrations", [])
    _require(isinstance(registrations, list) and len(registrations) == 4,
             "four observer registration checkpoints required")
    for role, registration in zip("ABCD", registrations):
        _require(registration.get("role") == role, "observer registration checkpoint order")
        calls, events = _events(registration.get("observer"), "W", state)
        _require(len(calls) == 1 and len(events) == 2, "complete observer registration checkpoint")
        serial = state["W"]["serial"] + 1
        _call(calls[0], serial, "GetId")
        signal = _registration_signal(events[0], "NameOwnerChanged", names[role], None, names)
        _reply(events[1], serial, names["W"], "s", [actors["W"]["bus_id"]])
        registration_stream.extend([dict(signal, registration=role),
                                    dict(_setup_reply(events[1], "GetId", "W"), registration=role)])
        state["W"]["serial"] = serial
    steps = report.get("steps", [])
    _require(len(steps) == len(ACTIONS), "fourteen action steps required")
    for index, (step, action, expected) in enumerate(zip(steps, ACTIONS, EXPECTED), 1):
        _require(step.get("index") == index and step.get("action") == action, "action order")
        _require(set(step.get("peers", {})) == set(ROLES), "step actors")
        mutator = ROLES[action[1]]
        for role in ROLES:
            calls, events = _events(step["peers"][role], role, state)
            replies = [e for e in events if e["type"] != 4]
            count = 3 if role == mutator else 1
            _require(len(calls) == len(replies) == count, "complete calls/replies/barriers required")
            serial = state[role]["serial"]
            if role == mutator:
                member = "RequestName" if action[0] == "request" else "ReleaseName"
                body = _strings(NAME)
                signature = "s"
                if action[0] == "request":
                    signature = "su"
                    body += b"\0" * (-len(body) % 4) + _u32(action[2])
                _call(calls[0], serial + 1, member, signature, body)
                result = _reply(replies[0], serial + 1, names[role], "u")[0]
                _require(result == expected[0], "ownership result mismatch")
                _call(calls[1], serial + 2, "ListQueuedOwners", "s", _strings(NAME))
                if expected[1] is None:
                    _reply(replies[1], serial + 2, names[role], "s", error=BUS + ".Error.NameHasNoOwner")
                    queue = None
                else:
                    queue_names = _reply(replies[1], serial + 2, names[role], "as")[0]
                    _require(queue_names == [names[r] for r in expected[1]], "ownership queue mismatch")
                    queue = list(expected[1])
                derived.append({"result": result, "queue": queue})
                serial += 2
            _call(calls[-1], serial + 1, "GetId")
            _reply(replies[-1], serial + 1, names[role], "s", [actors[role]["bus_id"]])
            state[role]["serial"] = serial + 1
            _require(events[-1] is replies[-1], "barrier must end snapshot")
            observed = _signals(events, index, role, names)
            expected_signals = []
            if index in TRANSITIONS:
                old, new = TRANSITIONS[index]
                expected_signals.append(("NameOwnerChanged", [NAME, old, new]))
                if role in (old, new):
                    expected_signals.append(("NameLost" if role == old else "NameAcquired", [NAME]))
            actual = [(s["member"], s["body"]) for s in observed]
            # Membership is normative here; observed interleaving is retained for
            # comparison below without inventing a cross-connection total order.
            _require(sorted(actual) == sorted(expected_signals), "ownership signal set mismatch")
            streams[role].extend(observed)
    return {"steps": len(steps), "streams": streams, "derived": derived,
            "hello_streams": hello_streams, "registration_stream": registration_stream}


def compare(reference, candidate):
    """Compare complete normalized streams without sorting their receive order."""
    left, right = validate(reference), validate(candidate)
    _require(reference["backend"] == "reference" and candidate["backend"] == "candidate",
             "comparison requires reference and candidate backend roles")
    _require(reference["profile"] == candidate["profile"], "comparison profile mismatch")
    _require(reference["kind"] == candidate["kind"], "comparison evidence kind mismatch")
    _require(reference["source"] == candidate["source"], "comparison source binding mismatch")
    if reference["kind"] == "runtime":
        for report in (reference, candidate):
            _require(report.get("status") == "RECORDED_VALID", "runtime collection status")
            _require(type(report.get("observer_exitcode")) is int
                     and report["observer_exitcode"] == 0, "runtime observer exit status")
            _require(not any(report.get(key) for key in ("error", "cleanup_error", "journal_errors")),
                     "runtime collection or cleanup error")
    differences = {role: {"reference": left["streams"][role], "candidate": right["streams"][role]}
                   for role in ROLES if left["streams"][role] != right["streams"][role]}
    hello_differences = {role: {"reference": left["hello_streams"][role],
                               "candidate": right["hello_streams"][role]}
                         for role in ROLES if left["hello_streams"][role] != right["hello_streams"][role]}
    if hello_differences:
        differences["hello"] = hello_differences
    if left["registration_stream"] != right["registration_stream"]:
        differences["registrations"] = {"reference": left["registration_stream"],
                                         "candidate": right["registration_stream"]}
    return {"equal": not differences, "differences": differences, "qualifies_original_gate": False}
