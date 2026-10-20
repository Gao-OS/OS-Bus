"""Aggregate source-bound native phases; this does not run a reference backend."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

PHASES = {
    "res01": ("uid_connections", "global_connections", "uid_authenticating",
              "global_authenticating", "peer_names", "global_names", "peer_matches", "global_matches"),
    "uid": ("uid_names", "uid_matches"),
}
DIRECTORIES = {"res01": "res01", "uid": "uid-authorities"}
RESULTS = {"res01": "passed_selected_scope", "uid": "passed_selected_standalone_scope"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def counts(number):
    return dict(selected=number, executed=number, passed=number, failed=0, blocked=0, skipped=0)


def validate_common(report, phase, bindings):
    assert report["selected"] == list(PHASES[phase])
    assert report["counts"] == counts(len(PHASES[phase]))
    assert set(report["outcomes"]) == set(PHASES[phase])
    assert all(row["status"] == "passed" for row in report["outcomes"].values())
    assert report["result"] == RESULTS[phase]
    assert "failure" not in report and "acceptance_failure" not in report
    assert report["candidate_manifest_sha256"] == bindings["candidate_manifest_sha256"]
    assert report["candidate"] == bindings["candidate_manifest"]
    assert report["candidate"]["source_sha256"] == bindings["candidate_source_sha256"]
    expected = {name.split("/", 1)[1]: row["sha256"]
                for name, row in bindings["fixture_files"].items() if name.startswith(phase + "/")}
    assert report["fixture_pins"] == expected
    assert report["quit_flushed"] is report["socket_removed"] is True
    assert not report["shutdown_errors"]
    assert 0 < report["authority_elapsed_ms"] <= 60_000


def validate_uid_teardown(report):
    assert len(report["actors_shutdown"]) == len(report["actors"]) > 0
    for shutdown in report["actors_shutdown"] + [report["daemon_shutdown"]]:
        assert shutdown["method"] == "eof" and shutdown["returncode"] == 0
        assert shutdown["pid_absent"] is shutdown["actor_pid_absent"] is shutdown["group_absent"] is True
        before = shutdown["before_containment"]
        assert before["stdin_closed"] is before["wrapper_waited"] is True
        assert before["wrapper_returncode"] == 0
        assert before["pid_absent"] is before["actor_pid_absent"] is before["group_absent"] is True
        assert before["timed_out"] is False and not before["errors"]


def validate_phase(report, phase, bindings, adapter):
    validate_common(report, phase, bindings)
    if phase == "res01":
        # Reuse every original boundary/identity/cleanup predicate, including the
        # single exact recorded pidfd victim exception, after checking its bytes.
        spec = importlib.util.spec_from_file_location("resources_res01", adapter / "res01/run.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        runner.complete(report)
    else:
        validate_uid_teardown(report)
        assert report["controls"] == dict(max_names_per_uid=2, max_matches_per_uid=2,
                                         max_names_per_peer=4, max_matches_per_peer=4,
                                         max_name_entries=16, max_match_entries=16)
        assert report["bounds"] == dict(authority_seconds=60, guest_seconds=120, host_seconds=900,
                                       request_ms=1000, settled_phase_ms=1000, healthy_probe_ms=1000)
        assert report["probes"] and all(0 <= probe["elapsed_ms"] <= 1000 for probe in report["probes"])
    return dict(candidate_manifest_sha256=report["candidate_manifest_sha256"],
                qualification_counts=report["counts"], daemon_pid=int(report["ready" if phase == "res01" else "daemon"]["pid"]),
                authority_elapsed_ms=report["authority_elapsed_ms"])


def persist(path, report):
    statuses = [row["status"] for row in report["outcomes"].values()]
    report["counts"] = dict(selected=10, executed=sum(s in ("passed", "failed") for s in statuses),
                            passed=statuses.count("passed"), failed=statuses.count("failed"),
                            blocked=statuses.count("blocked"), skipped=0)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main(action, adapter, candidate, evidence, phase=None, status=None):
    assert sys.dont_write_bytecode and sys.flags.optimize == 0
    bindings = json.loads((adapter / "bindings.json").read_text())
    assert digest(candidate / "candidate.json") == bindings["candidate_manifest_sha256"]
    for name, pin in bindings["fixture_files"].items():
        assert digest(adapter / name) == pin["sha256"], name
    path = evidence / "qualification.json"
    if action == "init":
        assert not path.exists()
        report = dict(version=1, requirement="RES-01", backend="gao_bus", result="blocked",
                      candidate_manifest_sha256=bindings["candidate_manifest_sha256"],
                      candidate_source_sha256=bindings["candidate_source_sha256"],
                      selected=[name for names in PHASES.values() for name in names],
                      outcomes={name: dict(status="blocked", reason="not_executed")
                                for names in PHASES.values() for name in names}, phases={},
                      reference_executed=False, full_RES01_qualified=False,
                      product_qualified=False, readiness="L0",
                      limitations="Native ten-dimension coverage only; paired reference/profile catalogue remains blocked")
        persist(path, report)
        return
    report = json.loads(path.read_text())
    if action == "record":
        assert phase in PHASES and phase not in report["phases"]
        qualification = evidence.parent / DIRECTORIES[phase] / "qualification.json"
        result = dict(returncode=int(status), qualification_path=str(qualification), status="failed")
        try:
            assert int(status) == 0, ("controller exit", status)
            raw = json.loads(qualification.read_text())
            result.update(validate_phase(raw, phase, bindings, adapter))
            result.update(status="passed", qualification_sha256=digest(qualification))
        except Exception as error:
            result["failure"] = repr(error)
        report["phases"][phase] = result
        for name in PHASES[phase]:
            report["outcomes"][name] = dict(status=result["status"], phase=phase,
                                            reason=result.get("failure", "source_bound_phase_passed"))
        persist(path, report)
        assert result["status"] == "passed", result
        return
    assert action == "final"
    assert set(report["phases"]) == set(PHASES)
    assert report["counts"] == counts(10)
    assert all(result["status"] == "passed" for result in report["phases"].values())
    assert len({result["daemon_pid"] for result in report["phases"].values()}) == 2
    report["result"] = "passed_native_ten_dimensions"
    persist(path, report)


if __name__ == "__main__":
    main(sys.argv[1], *(Path(value) for value in sys.argv[2:5]), *sys.argv[5:])
