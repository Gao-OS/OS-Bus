"""Inert rejection controls; synthetic reports never supply runtime evidence."""
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import contract


class CommonContractTest(unittest.TestCase):
    def setUp(self):
        self.bindings = dict(candidate_manifest_sha256="current-manifest",
                             candidate_source_sha256="current-source",
                             candidate_manifest=dict(source_sha256="current-source"),
                             fixture_files={"uid/run.py": dict(sha256="accepted-controller"),
                                            "uid/launcher.exs": dict(sha256="accepted-launcher")})
        self.report = dict(selected=list(contract.PHASES["uid"]), counts=contract.counts(2),
                           outcomes={name: dict(status="passed") for name in contract.PHASES["uid"]},
                           result=contract.RESULTS["uid"], candidate_manifest_sha256="current-manifest",
                           candidate=dict(source_sha256="current-source"),
                           fixture_pins={"run.py": "accepted-controller", "launcher.exs": "accepted-launcher"},
                           quit_flushed=True, socket_removed=True, shutdown_errors=[], authority_elapsed_ms=100)

    def validate(self, report):
        contract.validate_common(report, "uid", self.bindings)

    def test_complete_source_bound_selection_is_accepted(self):
        self.validate(self.report)

    def test_res01_controller_ready_record_supplies_its_daemon_pid(self):
        report = copy.deepcopy(self.report)
        names = contract.PHASES['res01']
        report.update(selected=list(names), counts=contract.counts(len(names)),
                      outcomes={name: dict(status='passed') for name in names},
                      result=contract.RESULTS['res01'], fixture_pins={},
                      ready=dict(pid='1000', identity=dict(pid=1000, uid=0, gid=0)))
        bindings = copy.deepcopy(self.bindings)
        bindings['fixture_files'] = {}
        runner = SimpleNamespace(complete=Mock())
        loader = SimpleNamespace(exec_module=Mock())
        with patch.object(contract.importlib.util, 'spec_from_file_location',
                          return_value=SimpleNamespace(loader=loader)), \
             patch.object(contract.importlib.util, 'module_from_spec', return_value=runner):
            summary = contract.validate_phase(report, 'res01', bindings, Path('/unused'))
        runner.complete.assert_called_once_with(report)
        self.assertEqual(summary['daemon_pid'], 1000)
        self.assertEqual(summary['qualification_counts'], contract.counts(8))

    def test_missing_unexecuted_or_extra_dimension_is_rejected(self):
        for mutation in (
            lambda row: row["selected"].pop(),
            lambda row: row["selected"].append("unrequested"),
            lambda row: row["counts"].update(executed=0),
            lambda row: row["counts"].update(blocked=1),
            lambda row: row["outcomes"]["uid_matches"].update(status="blocked"),
            lambda row: row["outcomes"].pop("uid_matches"),
        ):
            changed = copy.deepcopy(self.report)
            mutation(changed)
            with self.assertRaises((AssertionError, KeyError)):
                self.validate(changed)

    def test_stale_candidate_fixture_failure_or_deadline_is_rejected(self):
        for mutation in (
            lambda row: row.update(candidate_manifest_sha256="old-manifest"),
            lambda row: row["candidate"].update(source_sha256="old-source"),
            lambda row: row["fixture_pins"].update({"run.py": "stale-controller"}),
            lambda row: row.update(failure="retained controller failure"),
            lambda row: row.update(acceptance_failure="retained assertion failure"),
            lambda row: row.update(authority_elapsed_ms=60001),
            lambda row: row.update(socket_removed=False),
        ):
            changed = copy.deepcopy(self.report)
            mutation(changed)
            with self.assertRaises(AssertionError):
                self.validate(changed)


def shutdown():
    return dict(method="eof", returncode=0, pid_absent=True, actor_pid_absent=True, group_absent=True,
                before_containment=dict(stdin_closed=True, wrapper_waited=True, wrapper_returncode=0,
                                        pid_absent=True, actor_pid_absent=True, group_absent=True,
                                        timed_out=False, errors=[]))


class UidCleanupTest(unittest.TestCase):
    def setUp(self):
        self.report = dict(actors=[dict(identity=dict(pid=101))], actors_shutdown=[shutdown()],
                           daemon_shutdown=shutdown())

    def test_natural_retirement_is_required_for_every_actor_and_daemon(self):
        contract.validate_uid_teardown(self.report)
        for target in ("actor", "daemon"):
            for field in ("pid_absent", "actor_pid_absent", "group_absent", "stdin_closed",
                          "wrapper_waited", "timed_out", "errors", "wrapper_returncode"):
                changed = copy.deepcopy(self.report)
                row = changed["actors_shutdown"][0] if target == "actor" else changed["daemon_shutdown"]
                before = row["before_containment"]
                before[field] = {"timed_out": True, "errors": ["failure"], "wrapper_returncode": 137}.get(field, False)
                with self.subTest(target=target, field=field), self.assertRaises(AssertionError):
                    contract.validate_uid_teardown(changed)

    def test_containment_success_and_nonzero_exit_cannot_replace_natural_retirement(self):
        for mutation in (
            lambda row: row["actors_shutdown"][0].update(returncode=137),
            lambda row: row["daemon_shutdown"].update(method="terminate"),
            lambda row: row["actors_shutdown"].clear(),
            lambda row: row["actors_shutdown"][0].update(actor_pid_absent=False),
        ):
            changed = copy.deepcopy(self.report)
            mutation(changed)
            with self.assertRaises(AssertionError):
                contract.validate_uid_teardown(changed)


if __name__ == "__main__":
    unittest.main()
