"""Reconcile pinned, accepted saved PRO01 observations. Never execute fixtures."""

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys


ACCEPTED = frozenset({
    "PASS_PARTIAL_REFERENCE_AUTH_BEGIN",
    "PASS_PARTIAL_REFERENCE_HELLO_127",
    "PASS_PARTIAL_REFERENCE_GET_ID",
    "ACCEPTED_SCOPED_POSITIVE_REFERENCE_D286",
    "ACCEPT_NATIVE_PARTIAL_EVIDENCE_ONLY",
    "ADOPTED_COMPLETE_CURRENT_SEC01_CORE",
})
BACKENDS = ("reference", "gao_bus")
FAMILIES = ("A", "B", "H", "F", "C", "P", "D")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def equal(actual, expected):
    """JSON equality that never treats true as the integer 1."""
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(equal(actual[k], expected[k]) for k in actual)
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def pointer(document, path, context):
    require(isinstance(path, str) and (path == "" or path.startswith("/")),
            f"{context}: invalid JSON pointer")
    for token in path.split("/")[1:] if path else []:
        require(re.search(r"~(?![01])", token) is None, f"{context}: invalid JSON pointer escape")
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(document, dict) and token in document:
            document = document[token]
        elif isinstance(document, list) and re.fullmatch(r"0|[1-9][0-9]*", token):
            index = int(token)
            require(index < len(document), f"{context}: missing pointer {path}")
            document = document[index]
        else:
            raise ValueError(f"{context}: missing pointer {path}")
    return document


def parse_json(text, context):
    def object_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"{context}: duplicate JSON key {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError(f"{context}: invalid JSON constant {value}")

    try:
        return json.loads(text, object_pairs_hook=object_pairs, parse_constant=invalid_constant)
    except json.JSONDecodeError as error:
        raise ValueError(f"{context}: invalid JSON at line {error.lineno}") from error


def catalogue(family):
    if family in ("C", "P"):
        return [["coalesced" if family == "C" else "pipelined"]]
    if family == "D":
        return [[mode, split] for mode in ("rights_with_prefix", "rights_at_split")
                for split in range(1, 144)]
    return [[split] for split in range(1, {"A": 24, "B": 6, "H": 127, "F": 127}[family] + 1)]


class SavedInputs:
    def __init__(self, root, pins):
        require(isinstance(pins, dict) and pins, "manifest: inputs must be a nonempty mapping")
        self.data = {}
        self.parsed = {}
        for name, pin in pins.items():
            context = f"input {name}"
            require(isinstance(pin, dict), f"{context}: invalid pin")
            relative = pin.get("path")
            require(isinstance(relative, str) and relative and not Path(relative).is_absolute(),
                    f"{context}: path must be relative to root")
            path = (root / relative).resolve()
            require(path.is_relative_to(root), f"{context}: path escapes root")
            require(type(pin.get("bytes")) is int and pin["bytes"] >= 0, f"{context}: invalid bytes")
            digest = pin.get("sha256")
            require(isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
                    f"{context}: invalid sha256")
            try:
                require(path.is_file(), f"{context}: missing saved file {relative}")
                data = path.read_bytes()
            except OSError as error:
                raise ValueError(f"{context}: cannot read {relative}: {error}") from error
            require(len(data) == pin["bytes"], f"{context}: saved byte count changed")
            require(hashlib.sha256(data).hexdigest() == digest, f"{context}: saved sha256 changed")
            self.data[name] = data

    def read(self, name, format="json", prefix=None):
        require(isinstance(name, str) and name in self.data, f"input {name}: not pinned")
        require(format in ("json", "jsonl", "markers"), f"input {name}: unsupported record format")
        require(prefix is None or isinstance(prefix, str), f"input {name}: invalid marker prefix")
        if format == "markers":
            require(isinstance(prefix, str) and prefix, f"input {name}: marker prefix is required")
        cache_key = (name, format, prefix)
        if cache_key not in self.parsed:
            try:
                text = self.data[name].decode("utf-8")
            except UnicodeDecodeError as error:
                raise ValueError(f"input {name}: invalid UTF-8") from error
            if format == "json":
                result = parse_json(text, f"input {name}")
            else:
                result = []
                for number, line in enumerate(text.splitlines(), 1):
                    if format == "markers":
                        if prefix not in line:
                            continue
                        line = line.split(prefix, 1)[1]
                    elif not line.strip():
                        continue
                    result.append(parse_json(line, f"input {name} line {number}"))
            self.parsed[cache_key] = result
        return self.parsed[cache_key]


def check(document, assertion, context):
    require(isinstance(assertion, dict) and "value" in assertion, f"{context}: invalid equality check")
    actual = pointer(document, assertion.get("pointer"), context)
    require(equal(actual, assertion["value"]), f"{context}: check mismatch at {assertion['pointer']}")


def reconcile(root: Path, manifest: dict) -> dict:
    require(isinstance(manifest, dict) and type(manifest.get("version")) is int
            and manifest["version"] == 1, "manifest: expected version 1")
    root = Path(root).resolve()
    inputs = SavedInputs(root, manifest.get("inputs"))
    receipts = manifest.get("receipts")
    require(isinstance(receipts, dict) and receipts, "manifest: receipts must be a nonempty mapping")
    accepted = {}
    for name, receipt in receipts.items():
        context = f"receipt {name}"
        require(isinstance(receipt, dict), f"{context}: invalid receipt")
        document = inputs.read(receipt.get("input"))
        acceptance = receipt.get("acceptance")
        require(isinstance(acceptance, dict) and isinstance(acceptance.get("value"), str)
                and acceptance["value"] in ACCEPTED, f"{context}: unaccepted status")
        check(document, acceptance, context)
        checks = receipt.get("checks")
        require(isinstance(checks, list) and checks, f"{context}: nonempty checks required")
        for assertion in checks:
            require(isinstance(assertion, dict), f"{context}: invalid check")
            check(inputs.read(assertion.get("input", receipt["input"])), assertion, context)
        accepted[name] = acceptance["value"]

    cells = manifest.get("cells")
    require(isinstance(cells, list) and len(cells) == 14, "manifest: exactly 14 cells required")
    results, seen = [], set()
    counts = {backend: 0 for backend in BACKENDS}
    for cell in cells:
        require(isinstance(cell, dict), "manifest: invalid cell")
        backend, family = cell.get("backend"), cell.get("family")
        context = f"cell {backend}/{family}"
        require(backend in BACKENDS and family in FAMILIES, f"{context}: unknown catalogue cell")
        identity = (backend, family)
        require(identity not in seen, f"{context}: duplicate cell")
        seen.add(identity)
        receipt_id = cell.get("receipt")
        require(isinstance(receipt_id, str) and receipt_id in accepted, f"{context}: missing accepted receipt")
        records = cell.get("records")
        require(isinstance(records, dict), f"{context}: invalid records selector")
        rows = inputs.read(records.get("input"), records.get("format"), records.get("prefix"))
        rows = pointer(rows, records.get("pointer", ""), context)
        require(isinstance(rows, list), f"{context}: records must be a list")
        selection = records.get("select")
        if selection is not None:
            selections = selection if isinstance(selection, list) else [selection]
            require(selections and all(isinstance(s, dict) and "value" in s for s in selections),
                    f"{context}: invalid selection")
            selected = []
            for row in rows:
                matches = True
                for selector in selections:
                    try:
                        value = pointer(row, selector.get("pointer"), context)
                    except ValueError as error:
                        if "missing pointer" not in str(error):
                            raise
                        matches = False
                        break
                    if not equal(value, selector["value"]):
                        matches = False
                        break
                if matches:
                    selected.append(row)
            rows = selected
        keys, checks = cell.get("keys"), cell.get("checks")
        require(isinstance(keys, list) and keys, f"{context}: nonempty keys required")
        require(isinstance(checks, list) and checks, f"{context}: nonempty checks required")
        vectors = []
        for number, row in enumerate(rows, 1):
            row_context = f"{context} record {number}"
            vectors.append([pointer(row, key, row_context) for key in keys])
            for assertion in checks:
                check(row, assertion, row_context)
        require(equal(vectors, catalogue(family)), f"{context}: ordered case census differs from catalogue")
        provenance = cell.get("provenance")
        require(isinstance(provenance, dict) and provenance, f"{context}: provenance is required")
        counts[backend] += len(vectors)
        results.append({"backend": backend, "family": family, "accepted_saved_cases": len(vectors),
                        "case_keys": vectors, "receipt": receipt_id, "receipt_acceptance": accepted[receipt_id],
                        "records": copy.deepcopy(records), "provenance": copy.deepcopy(provenance)})
    require(seen == {(b, f) for b in BACKENDS for f in FAMILIES}, "manifest: missing catalogue cells")
    metadata = manifest.get("metadata", {})
    require(isinstance(metadata, dict), "manifest: metadata must be a mapping")
    return {
        "version": 1, "status": "RECONCILED_ACCEPTED_SAVED_COVERAGE", "gate_result": "NOT_QUALIFIED",
        "accepted_saved_cases": dict(counts, total=sum(counts.values())), "cells": results,
        "input_bindings": copy.deepcopy(manifest["inputs"]), "receipts": copy.deepcopy(receipts),
        "metadata": copy.deepcopy(metadata), "full_row_qualified": False, "current_paired_qualified": False,
        "required_row_promotions": 0, "new_runtime_executions": 0, "readiness": "L0", "product_qualified": False,
        "limitations": ["Accepted saved observations retain their original source, identity and profile bindings.",
                        "Reference server-native read extents, parser state and internal accounting remain unsupported.",
                        "Reconciliation creates no runtime evidence or required-row qualification."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = parse_json(args.manifest.read_text(encoding="utf-8"), "manifest")
        report = reconcile(args.root, manifest)
    except (ValueError, OSError) as error:
        print(f"PRO01 reconciliation failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
