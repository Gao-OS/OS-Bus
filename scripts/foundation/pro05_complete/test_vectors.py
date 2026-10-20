"""Pure recipe/pin checks only; these tests establish no bus runtime result."""

import json
from pathlib import Path
import struct
import unittest

from vectors import CASE_ORDER, CASES, frame, receipt


EXPECTED_ORDER = (
    "variant64", "variant65", "array32", "array33", "struct32", "struct33",
    "match_string", "match_uint32", "collection", "prefix",
)
# Literal pins prepared from saved accepted target bytes, independent of frame().
HARD_PINS = {
    "variant64": {
        "bytes": 337,
        "sha256": "38ae33d82ea52136aebe2efe3cf03b878c3d4238f40f927bd351997ea0f51964"
    },
    "variant65": {
        "bytes": 340,
        "sha256": "ac249fbb47fb8ce2aa7d0ae8129c6ebafda415b20870ff9976755158ae4f396f"
    },
    "array32": {
        "bytes": 297,
        "sha256": "9ac01f8220e7d68fdd04108bd2dcc5d9a48efc2a518920080cc1e0ff38f13e12"
    },
    "array33": {
        "bytes": 301,
        "sha256": "7c746b739c986050970aab421ff811be52371484ff0492f6c734eaaa7b5aa991"
    },
    "struct32": {
        "bytes": 201,
        "sha256": "5f17ae0563c765747319fd6632fc819741568a7002ed64a37294c51284a675a5"
    },
    "struct33": {
        "bytes": 209,
        "sha256": "ed45fc13646868dfcfd6b14cac8a2847902d8eb652b1027d115fff2183b2a8f2"
    },
    "match_string": {
        "bytes": 99,
        "sha256": "25810734ac5bfa93f208835f98363106364d2c1e7a8ae57220fd9b4e8cc02228"
    },
    "match_uint32": {
        "bytes": 92,
        "sha256": "7c8b12c0c6ea4ab506eec91dda65ccb39f7d702325f419031065f642cbcc6a07"
    },
    "prefix": {
        "bytes": 16,
        "sha256": "73957a51d34281e8a7489d57fbad87aa6c8c7395396cc6426c5f67959a5eb8f8"
    },
    "collection": {
        "bytes": 1048576,
        "sha256": "e3009a4e8ae92a9fbc17d3df38ab911bdf9665a88e0aaa7f799a6405db798f81"
    }
}
FIXED_FIELDS = {
    "variant64": (1, 193, 3, 127, 128),
    "variant65": (1, 196, 6, 127, 128),
    "array32": (1, 129, 3, 151, 152),
    "array33": (1, 133, 6, 152, 152),
    "struct32": (1, 1, 3, 183, 184),
    "struct33": (1, 1, 6, 185, 192),
    "match_string": (4, 11, 3, 71, 72),
    "match_uint32": (4, 4, 6, 71, 72),
    "collection": (1, 1048440, 3, 120, 120),
}
COLLECTION_HEADER = "6c01000178ff0f00030000007800000001016f00150000002f6f72672f667265656465736b746f702f4442757300000002017300140000006f72672e667265656465736b746f702e44427573000000000301730005000000476574496400000006017300140000006f72672e667265656465736b746f702e44427573000000000801670002617900"


def body_of(packet):
    header_bytes = struct.unpack_from("<I", packet, 12)[0]
    return packet[16 + (header_bytes + 7) // 8 * 8:]


class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frozen = json.loads(Path(__file__).with_name("vectors.json").read_text())

    def test_exact_inventory_and_native_metadata(self):
        self.assertEqual(CASE_ORDER, EXPECTED_ORDER)
        self.assertEqual(tuple(CASES), EXPECTED_ORDER)
        self.assertEqual(tuple(self.frozen["case_order"]), EXPECTED_ORDER)
        self.assertEqual(tuple(self.frozen["cases"]), EXPECTED_ORDER)
        self.assertEqual(self.frozen["version"], 1)
        expected = {
            "variant64": ("variant", "invalid_args", 1, 3),
            "variant65": ("variant", "close", 1, 6),
            "array32": ("array", "invalid_args", 1, 3),
            "array33": ("array", "close", 1, 6),
            "struct32": ("struct", "invalid_args", 1, 3),
            "struct33": ("struct", "close", 1, 6),
            "match_string": ("match", "match", 1, 3),
            "match_uint32": ("match", "nonmatch", 1, 6),
            "collection": ("collection", "invalid_args", 1, 3),
            "prefix": ("prefix", "close", 32, 3),
        }
        categories = {
            "variant": "deep signatures/containers",
            "array": "deep signatures/containers",
            "struct": "deep signatures/containers",
            "match": "adversarial match argument values",
            "collection": "large collections",
            "prefix": "repeated invalid prefixes",
        }
        for name, (family, oracle, repetitions, serial) in expected.items():
            with self.subTest(case=name):
                spec = CASES[name]
                self.assertEqual(
                    (spec["family"], spec["oracle"], spec["repetitions"], spec["serial"]),
                    (family, oracle, repetitions, serial),
                )
                self.assertEqual(spec["category"], categories[family])
                self.assertEqual(spec["request_ms"], 3000)
                self.assertEqual(spec["down_ms"], 1500)
                self.assertEqual(spec["observer_health_ms"], 1000)
                for key, value in spec.items():
                    self.assertEqual(self.frozen["cases"][name][key], value)
        self.assertEqual(sum(spec["repetitions"] for spec in CASES.values()), 41)
        with self.assertRaises(KeyError):
            frame("variant66")

    def test_all_recipes_match_literal_pins_and_saved_hex(self):
        for name in EXPECTED_ORDER:
            with self.subTest(case=name):
                packet = frame(name)
                self.assertEqual(receipt(packet), HARD_PINS[name])
                frozen = self.frozen["cases"][name]
                self.assertEqual(
                    {"bytes": frozen["bytes"], "sha256": frozen["sha256"]},
                    HARD_PINS[name],
                )
                if name == "collection":
                    self.assertNotIn("hex", frozen)
                else:
                    self.assertEqual(packet.hex(), frozen["hex"])

    def test_fixed_lengths_serials_signatures_and_padding(self):
        for name, (kind, body_bytes, serial, header_bytes, padded) in FIXED_FIELDS.items():
            with self.subTest(case=name):
                packet = frame(name)
                self.assertEqual(
                    struct.unpack_from("<BBBBIII", packet),
                    (108, kind, 0, 1, body_bytes, serial, header_bytes),
                )
                self.assertEqual(len(packet), 16 + padded + body_bytes)
                self.assertEqual(packet[16 + header_bytes:16 + padded],
                                 b"\0" * (padded - header_bytes))
                self.assertEqual(len(body_of(packet)), body_bytes)
                signature = CASES[name]["signature"].encode("ascii")
                marker = b"\x08\x01g\0" + bytes((len(signature),)) + signature + b"\0"
                self.assertTrue(packet[16:16 + header_bytes].endswith(marker))

    def test_dynamic_variant_64_65_boundary(self):
        for depth in (64, 65):
            with self.subTest(depth=depth):
                body = body_of(frame("variant" + str(depth)))
                self.assertEqual(body[:-4], b"\x01v\0" * (depth - 1))
                self.assertEqual(body[-4:], b"\x01y\0\x2a")
                self.assertEqual(len(body), 3 * depth + 1)
                self.assertEqual(CASES["variant" + str(depth)]["signature"], "v")

    def test_static_array_32_33_extent_chain(self):
        for depth in (32, 33):
            with self.subTest(depth=depth):
                spec = CASES["array" + str(depth)]
                self.assertEqual(spec["signature"], "a" * depth + "y")
                body = body_of(frame("array" + str(depth)))
                self.assertEqual(len(body), depth * 4 + 1)
                for offset in range(0, depth * 4, 4):
                    self.assertEqual(struct.unpack_from("<I", body, offset)[0],
                                     len(body) - offset - 4)
                self.assertEqual(body[-1:], b"\x2a")

    def test_static_struct_32_33_signature_and_body(self):
        for depth, signature_bytes in ((32, 65), (33, 67)):
            with self.subTest(depth=depth):
                signature = CASES["struct" + str(depth)]["signature"]
                self.assertEqual(signature, "(" * depth + "y" + ")" * depth)
                self.assertEqual(len(signature), signature_bytes)
                self.assertEqual(body_of(frame("struct" + str(depth))), b"\x2a")

    def test_typed_match_positive_string_then_uint32_nonmatch(self):
        self.assertLess(EXPECTED_ORDER.index("match_string"),
                        EXPECTED_ORDER.index("match_uint32"))
        self.assertEqual(CASES["match_string"]["rule"], "type='signal',arg0path='/probe'")
        self.assertEqual(CASES["match_uint32"]["rule"], CASES["match_string"]["rule"])
        self.assertEqual(CASES["match_string"]["signature"], "s")
        self.assertEqual(CASES["match_uint32"]["signature"], "u")
        self.assertEqual(body_of(frame("match_string")), bytes.fromhex("060000002f70726f626500"))
        self.assertEqual(body_of(frame("match_uint32")), bytes.fromhex("2a000000"))

    def test_materialized_collection_uses_exact_native_frame_ceiling(self):
        packet = frame("collection")
        self.assertEqual(len(packet), 1048576)
        self.assertEqual(packet[:136].hex(), COLLECTION_HEADER)
        self.assertEqual(CASES["collection"]["header_hex"], COLLECTION_HEADER)
        body = body_of(packet)
        self.assertEqual(len(body), 1048440)
        self.assertEqual(body[:4].hex(), "74ff0f00")
        self.assertEqual(struct.unpack_from("<I", body)[0], 1048436)
        self.assertEqual(len(body[4:]), 1048436)
        self.assertEqual(body[4:], b"\x2a" * 1048436)
        self.assertEqual(receipt(body), {
            "bytes": 1048440,
            "sha256": "e38f00e60aa8070844de50d19e223d947206c67e467bcb35d5d46a2d195ac60c",
        })
        self.assertEqual(receipt(body[4:]), {
            "bytes": 1048436,
            "sha256": "f6fe5332f0ccb17db2e9cc92f8007373cd5af0aeb1518af83bb20bdcfef7f19c",
        })

    def test_repeated_prefix_is_one_fixed_vector_without_payload(self):
        prefix = frame("prefix")
        self.assertEqual(prefix, bytes.fromhex("ff010001000000000300000000000000"))
        self.assertEqual(struct.unpack("<BBBBIII", prefix), (255, 1, 0, 1, 0, 3, 0))
        self.assertEqual(CASES["prefix"]["repetitions"], 32)
        self.assertEqual(len(prefix), 16)


if __name__ == "__main__":
    unittest.main()

