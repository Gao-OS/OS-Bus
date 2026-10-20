"""Expected wire recipes for the six accepted finite native PRO-05 subsets.

This module performs no I/O and imports no actor, bus, or decoder. The frozen
receipts in vectors.json come from saved accepted inputs, not a new target run.
"""

import hashlib
import struct


CASE_ORDER = (
    "variant64", "variant65", "array32", "array33", "struct32", "struct33",
    "match_string", "match_uint32", "collection", "prefix",
)

CASES = {
    "variant64": {
        "category": "deep signatures/containers",
        "family": "variant",
        "oracle": "invalid_args",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 3,
        "bytes": 337,
        "sha256": "38ae33d82ea52136aebe2efe3cf03b878c3d4238f40f927bd351997ea0f51964",
        "body_bytes": 193,
        "header_bytes": 127,
        "padded_header_bytes": 128,
        "signature": "v",
        "depth": 64
    },
    "variant65": {
        "category": "deep signatures/containers",
        "family": "variant",
        "oracle": "close",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 6,
        "bytes": 340,
        "sha256": "ac249fbb47fb8ce2aa7d0ae8129c6ebafda415b20870ff9976755158ae4f396f",
        "body_bytes": 196,
        "header_bytes": 127,
        "padded_header_bytes": 128,
        "signature": "v",
        "depth": 65
    },
    "array32": {
        "category": "deep signatures/containers",
        "family": "array",
        "oracle": "invalid_args",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 3,
        "bytes": 297,
        "sha256": "9ac01f8220e7d68fdd04108bd2dcc5d9a48efc2a518920080cc1e0ff38f13e12",
        "body_bytes": 129,
        "header_bytes": 151,
        "padded_header_bytes": 152,
        "signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay",
        "depth": 32
    },
    "array33": {
        "category": "deep signatures/containers",
        "family": "array",
        "oracle": "close",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 6,
        "bytes": 301,
        "sha256": "7c746b739c986050970aab421ff811be52371484ff0492f6c734eaaa7b5aa991",
        "body_bytes": 133,
        "header_bytes": 152,
        "padded_header_bytes": 152,
        "signature": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay",
        "depth": 33
    },
    "struct32": {
        "category": "deep signatures/containers",
        "family": "struct",
        "oracle": "invalid_args",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 3,
        "bytes": 201,
        "sha256": "5f17ae0563c765747319fd6632fc819741568a7002ed64a37294c51284a675a5",
        "body_bytes": 1,
        "header_bytes": 183,
        "padded_header_bytes": 184,
        "signature": "((((((((((((((((((((((((((((((((y))))))))))))))))))))))))))))))))",
        "depth": 32
    },
    "struct33": {
        "category": "deep signatures/containers",
        "family": "struct",
        "oracle": "close",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 6,
        "bytes": 209,
        "sha256": "ed45fc13646868dfcfd6b14cac8a2847902d8eb652b1027d115fff2183b2a8f2",
        "body_bytes": 1,
        "header_bytes": 185,
        "padded_header_bytes": 192,
        "signature": "(((((((((((((((((((((((((((((((((y)))))))))))))))))))))))))))))))))",
        "depth": 33
    },
    "match_string": {
        "category": "adversarial match argument values",
        "family": "match",
        "oracle": "match",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 3,
        "bytes": 99,
        "sha256": "25810734ac5bfa93f208835f98363106364d2c1e7a8ae57220fd9b4e8cc02228",
        "body_bytes": 11,
        "header_bytes": 71,
        "padded_header_bytes": 72,
        "signature": "s",
        "rule": "type='signal',arg0path='/probe'"
    },
    "match_uint32": {
        "category": "adversarial match argument values",
        "family": "match",
        "oracle": "nonmatch",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 6,
        "bytes": 92,
        "sha256": "7c8b12c0c6ea4ab506eec91dda65ccb39f7d702325f419031065f642cbcc6a07",
        "body_bytes": 4,
        "header_bytes": 71,
        "padded_header_bytes": 72,
        "signature": "u",
        "rule": "type='signal',arg0path='/probe'"
    },
    "collection": {
        "category": "large collections",
        "family": "collection",
        "oracle": "invalid_args",
        "repetitions": 1,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 3,
        "bytes": 1048576,
        "sha256": "e3009a4e8ae92a9fbc17d3df38ab911bdf9665a88e0aaa7f799a6405db798f81",
        "body_bytes": 1048440,
        "header_bytes": 120,
        "padded_header_bytes": 120,
        "signature": "ay",
        "element_count": 1048436,
        "element_byte": 42,
        "body_sha256": "e38f00e60aa8070844de50d19e223d947206c67e467bcb35d5d46a2d195ac60c",
        "payload_sha256": "f6fe5332f0ccb17db2e9cc92f8007373cd5af0aeb1518af83bb20bdcfef7f19c",
        "header_hex": "6c01000178ff0f00030000007800000001016f00150000002f6f72672f667265656465736b746f702f4442757300000002017300140000006f72672e667265656465736b746f702e44427573000000000301730005000000476574496400000006017300140000006f72672e667265656465736b746f702e44427573000000000801670002617900",
        "fixed_hex": "6c01000178ff0f000300000078000000",
        "array_length_hex": "74ff0f00"
    },
    "prefix": {
        "category": "repeated invalid prefixes",
        "family": "prefix",
        "oracle": "close",
        "repetitions": 32,
        "request_ms": 3000,
        "down_ms": 1500,
        "observer_health_ms": 1000,
        "serial": 3,
        "bytes": 16,
        "sha256": "73957a51d34281e8a7489d57fbad87aa6c8c7395396cc6426c5f67959a5eb8f8",
        "body_bytes": 0,
        "header_bytes": 0,
        "padded_header_bytes": 0
    }
}


def receipt(data):
    """Return the byte count and SHA256 of the supplied wire bytes."""
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def _u32(value):
    return struct.pack("<I", value)


def wire_string(value):
    """Encode an ASCII D-Bus string used by the accepted targets and health calls."""
    encoded = value.encode("ascii")
    return _u32(len(encoded)) + encoded + b"\0"


def _message(kind, serial, fields, body):
    header = b""
    for code, signature, value in fields:
        header += b"\0" * (-len(header) % 8)
        header += bytes((code, 1)) + signature.encode("ascii") + b"\0"
        if signature == "g":
            encoded = value.encode("ascii")
            header += bytes((len(encoded),)) + encoded + b"\0"
        else:
            header += wire_string(value)
    fixed = b"l" + bytes((kind, 0, 1))
    fixed += _u32(len(body)) + _u32(serial) + _u32(len(header))
    return fixed + header + b"\0" * (-len(header) % 8) + body


def call(member, serial, signature="", body=b""):
    """Build a call to the bus using the accepted target/health wire layout."""
    return _message(1, serial, (
        (1, "o", "/org/freedesktop/DBus"),
        (2, "s", "org.freedesktop.DBus"),
        (3, "s", member),
        (6, "s", "org.freedesktop.DBus"),
        (8, "g", signature),
    ), body)


def frame(case):
    """Build exactly one named accepted target; prefix repetitions are metadata."""
    spec = CASES[case]
    family = spec["family"]
    serial = spec["serial"]
    if family == "prefix":
        return bytes((255, 1, 0, 1)) + struct.pack("<III", 0, 3, 0)
    if family == "match":
        body = wire_string("/probe") if case == "match_string" else _u32(42)
        return _message(4, serial, (
            (1, "o", "/probe"),
            (2, "s", "org.foundation.Probe"),
            (3, "s", "Changed"),
            (8, "g", spec["signature"]),
        ), body)
    if family == "variant":
        body = b"\x01v\0" * (spec["depth"] - 1) + b"\x01y\0\x2a"
        member = "RequestName"
    elif family == "array":
        body = b"".join(_u32(size) for size in range(4 * (spec["depth"] - 1) + 1, 0, -4))
        body += b"\x2a"
        member = "GetId"
    elif family == "struct":
        body = b"\x2a"
        member = "GetId"
    else:
        body = _u32(spec["element_count"]) + bytes((spec["element_byte"],)) * spec["element_count"]
        member = "GetId"
    return call(member, serial, spec["signature"], body)

