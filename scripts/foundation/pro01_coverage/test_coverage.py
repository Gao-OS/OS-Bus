"""Data-only contract tests; no execution fixture or runtime is imported."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


IMPLEMENTATION = Path(__file__).with_name("qualify.py")


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(IMPLEMENTATION.is_file(), "qualify.py has not been implemented")
        spec = importlib.util.spec_from_file_location("pro01_coverage", IMPLEMENTATION)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.reconcile = module.reconcile
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.manifest = {"version": 1, "inputs": {}, "receipts": {}, "cells": []}
        self.manifest["metadata"] = {"native_coalescing": "accepted saved support only"}
        for backend in ("reference", "gao_bus"):
            receipt_id = backend + "-acceptance"
            self.pin(receipt_id, {"status": "ACCEPT_NATIVE_PARTIAL_EVIDENCE_ONLY", "passed": True})
            self.manifest["receipts"][receipt_id] = {
                "input": receipt_id,
                "acceptance": {"pointer": "/status", "value": "ACCEPT_NATIVE_PARTIAL_EVIDENCE_ONLY"},
                "checks": [{"pointer": "/passed", "value": True}],
            }
            for family in ("A", "B", "H", "F", "C", "P", "D"):
                input_id = backend + "-" + family
                rows = self.rows(family)
                self.pin(input_id, {"records": rows})
                self.manifest["cells"].append({
                    "backend": backend,
                    "family": family,
                    "receipt": receipt_id,
                    "records": {"input": input_id, "format": "json", "pointer": "/records"},
                    "keys": ["/mode", "/split"] if family == "D" else ["/id" if family in ("C", "P") else "/split"],
                    "checks": [{"pointer": "/result", "value": "PASS"}],
                    "provenance": {"source": backend + "-frozen", "uid": 1101 if family in ("C", "P") else 1000},
                })

    @staticmethod
    def rows(family):
        if family in ("C", "P"):
            return [{"id": "coalesced" if family == "C" else "pipelined", "result": "PASS"}]
        if family == "D":
            return [{"mode": mode, "split": split, "result": "PASS"}
                    for mode in ("rights_with_prefix", "rights_at_split") for split in range(1, 144)]
        count = {"A": 24, "B": 6, "H": 127, "F": 127}[family]
        return [{"split": split, "result": "PASS"} for split in range(1, count + 1)]

    def pin(self, input_id, value=None, raw=None):
        data = raw if raw is not None else json.dumps(value, sort_keys=True).encode()
        path = self.root / (input_id + ".data")
        path.write_bytes(data)
        self.manifest["inputs"][input_id] = {
            "path": path.name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)
        }

    def cell(self, family="A", backend="reference"):
        return next(c for c in self.manifest["cells"] if c["family"] == family and c["backend"] == backend)

    def rewrite_rows(self, family, mutate):
        cell = self.cell(family)
        input_id = cell["records"]["input"]
        rows = self.rows(family)
        mutate(rows)
        self.pin(input_id, {"records": rows})

    def reject(self):
        with self.assertRaises(ValueError):
            self.reconcile(self.root, self.manifest)

    def test_complete_census_preserves_provenance_and_limits(self):
        original = copy.deepcopy(self.manifest)
        report = self.reconcile(self.root, self.manifest)
        self.assertEqual(report["accepted_saved_cases"], {"reference": 572, "gao_bus": 572, "total": 1144})
        self.assertEqual(len(report["cells"]), 14)
        for cell, result in zip(self.manifest["cells"], report["cells"]):
            self.assertEqual((result["backend"], result["family"]), (cell["backend"], cell["family"]))
            self.assertEqual(result["provenance"], cell["provenance"])
            self.assertEqual(result["accepted_saved_cases"], len(self.rows(cell["family"])))
        self.assertFalse(report["full_row_qualified"])
        self.assertFalse(report["current_paired_qualified"])
        self.assertFalse(report["product_qualified"])
        self.assertEqual(report["readiness"], "L0")
        self.assertEqual(report["required_row_promotions"], 0)
        self.assertEqual(report["new_runtime_executions"], 0)
        self.assertEqual(report["metadata"], original["metadata"])
        self.assertEqual(self.manifest, original)
        self.assertEqual(report, self.reconcile(self.root, self.manifest))

    def test_missing_or_changed_saved_input_is_rejected(self):
        path = self.root / self.manifest["inputs"]["reference-A"]["path"]
        original = path.read_bytes()
        for replacement in (None, b"changed", original + b" "):
            with self.subTest(replacement=replacement):
                if replacement is None:
                    path.unlink()
                else:
                    path.write_bytes(replacement)
                self.reject()
                path.write_bytes(original)

    def test_byte_count_is_checked_independently_of_digest(self):
        self.manifest["inputs"]["reference-A"]["bytes"] += 1
        self.reject()

    def test_unaccepted_or_contradictory_receipt_is_rejected(self):
        for status, passed in (("FAIL", True), ("ACCEPT_NATIVE_PARTIAL_EVIDENCE_ONLY", False)):
            with self.subTest(status=status, passed=passed):
                self.pin("reference-acceptance", {"status": status, "passed": passed})
                self.reject()

    def test_arbitrary_status_cannot_be_self_authorized(self):
        self.pin("reference-acceptance", {"status": "invented-success", "passed": True})
        self.manifest["receipts"]["reference-acceptance"]["acceptance"]["value"] = "invented-success"
        self.reject()

    def test_receipt_checks_can_bind_other_pinned_inputs(self):
        self.pin("source-binding", {"raw_sha256": self.manifest["inputs"]["reference-A"]["sha256"]})
        self.manifest["receipts"]["reference-acceptance"]["checks"].append({
            "input": "source-binding", "pointer": "/raw_sha256",
            "value": self.manifest["inputs"]["reference-A"]["sha256"],
        })
        self.assertEqual(self.reconcile(self.root, self.manifest)["accepted_saved_cases"]["total"], 1144)
        self.pin("source-binding", {"raw_sha256": "contradictory"})
        self.reject()
        self.manifest["receipts"]["reference-acceptance"]["checks"][-1]["input"] = "not-pinned"
        self.reject()

    def test_receipts_and_cases_require_nonempty_checks(self):
        receipt = self.manifest["receipts"]["reference-acceptance"]
        checks = receipt.pop("checks")
        self.reject()
        receipt["checks"] = checks
        self.cell()["checks"] = []
        self.reject()

    def test_missing_or_duplicate_cell_is_rejected(self):
        cell = self.manifest["cells"].pop()
        self.reject()
        self.manifest["cells"].append(cell)
        self.manifest["cells"][-1] = copy.deepcopy(self.manifest["cells"][0])
        self.reject()

    def test_missing_duplicate_reordered_out_of_range_or_failed_case_is_rejected(self):
        mutations = {
            "missing": lambda rows: rows.pop(),
            "duplicate": lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])),
            "reordered": lambda rows: rows.reverse(),
            "out_of_range": lambda rows: rows[-1].update(split=25),
            "failed": lambda rows: rows[0].update(result="FAIL"),
            "missing_check": lambda rows: rows[0].pop("result"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.rewrite_rows("A", mutate)
                self.reject()

    def test_fd_mode_and_cp_ids_are_part_of_exact_catalogue(self):
        for family, mutation in (("D", lambda rows: rows[0].update(mode="unknown")),
                                 ("C", lambda rows: rows[0].update(id="pipelined")),
                                 ("P", lambda rows: rows.append(copy.deepcopy(rows[0])))):
            with self.subTest(family=family):
                self.rewrite_rows(family, mutation)
                self.reject()
                self.pin(self.cell(family)["records"]["input"], {"records": self.rows(family)})

    def test_booleans_do_not_equal_integer_keys_or_checks(self):
        self.rewrite_rows("A", lambda rows: rows[0].update(split=True))
        self.reject()
        self.pin("reference-A", {"records": self.rows("A")})
        self.pin("reference-acceptance", {"status": "ACCEPT_NATIVE_PARTIAL_EVIDENCE_ONLY", "passed": 1})
        self.reject()

    def test_jsonl_selection_preserves_order_and_requires_cases(self):
        cell = self.cell()
        rows = [{"event": "ready"}] + [dict(row, event="case") for row in self.rows("A")]
        self.pin("reference-A", raw=("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        cell["records"] = {"input": "reference-A", "format": "jsonl", "select": {"pointer": "/event", "value": "case"}}
        self.assertEqual(self.reconcile(self.root, self.manifest)["accepted_saved_cases"]["reference"], 572)
        cell["records"]["select"]["value"] = "absent"
        self.reject()

    def test_marker_extraction_ignores_other_log_lines_and_requires_records(self):
        cell = self.cell("H", "gao_bus")
        raw = "compiler log\n" + "\n".join("[info] HELLO_SPLIT_CASE " + json.dumps(row) for row in self.rows("H"))
        self.pin("gao_bus-H", raw=raw.encode())
        cell["records"] = {"input": "gao_bus-H", "format": "markers", "prefix": "HELLO_SPLIT_CASE "}
        self.assertEqual(self.reconcile(self.root, self.manifest)["accepted_saved_cases"]["gao_bus"], 572)
        cell["records"]["prefix"] = "MISSING_CASE "
        self.reject()

    def test_conjunctive_jsonl_selectors_filter_shared_auth_begin_records(self):
        rows = [{"event": "ready", "family": "AUTH"}]
        rows += [dict(row, event="case", family=family)
                 for family, catalogue_family in (("AUTH", "A"), ("BEGIN", "B"))
                 for row in self.rows(catalogue_family)]
        self.pin("reference-AB", raw=("\n".join(json.dumps(row) for row in rows) + "\n").encode())
        for family, raw_family in (("A", "AUTH"), ("B", "BEGIN")):
            self.cell(family)["records"] = {
                "input": "reference-AB", "format": "jsonl", "select": [
                    {"pointer": "/event", "value": "case"},
                    {"pointer": "/family", "value": raw_family},
                ],
            }
        self.assertEqual(self.reconcile(self.root, self.manifest)["accepted_saved_cases"]["reference"], 572)
        self.cell("A")["records"]["select"][1]["value"] = "BEGIN"
        self.reject()

    def test_malformed_json_or_missing_pointer_is_rejected(self):
        self.pin("reference-A", raw=b"{malformed")
        self.reject()
        self.pin("reference-A", {"records": self.rows("A")})
        self.cell()["records"]["pointer"] = "/missing"
        self.reject()

    def test_manifest_metadata_cannot_promote_qualification(self):
        self.manifest["metadata"].update(full_row_qualified=True, current_paired_qualified=True,
                                         product_qualified=True, readiness="L4", new_runtime_executions=99)
        report = self.reconcile(self.root, self.manifest)
        self.assertFalse(report["full_row_qualified"])
        self.assertFalse(report["current_paired_qualified"])
        self.assertFalse(report["product_qualified"])
        self.assertEqual(report["readiness"], "L0")
        self.assertEqual(report["new_runtime_executions"], 0)

    def test_cli_prints_report_without_writing_files(self):
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(self.manifest))
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        result = subprocess.run([sys.executable, "-B", str(IMPLEMENTATION), "--root", str(self.root),
                                 "--manifest", str(manifest_path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), self.reconcile(self.root, self.manifest))
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})


if __name__ == "__main__":
    unittest.main()
