# Source-prepared P05/M1 UID abrupt-Peer rows

This is an unexecuted fixture, not new qualification evidence. Root owns
ordered specification then quality review, offline execution, the frozen
post-NO_AUTO_START candidate, host containment and one serialized disposable VM.
No approval, capture, build, test or runtime pass is supplied here.

The two explicit selections reuse the accepted UID VM2 sequence:

| Selection | Required additional events | Existing quota and identity checks retained |
| --- | --- | --- |
| `uid_names` | `owner_down_promotes`, `queued_down_reclaims` | Shared UID N/N+1, repeat accounting, other UID independence, queue promotion, exactly one credit reused then N+1 denied |
| `uid_matches` | `match_down_reclaims` | Shared UID N/N+1, duplicate-rule accounting/removal/delivery, other UID independence, exactly one credit reused then N+1 denied |
| `all` | Both rows in that order; three distinct DOWN witnesses | Final full observer baseline equals the original baseline |

Names kill the actual owning Peer and later the actual queued Peer. Matches
kill the actual subscribed Peer. The original actor remains alive during the
automatic-cleanup readback: actor UID/GID/PID from real `/proc` joins the
unchanged accepted credentials, unique name, active Limits admission, children,
Router and local UID-ledger monitor/incarnation. The daemon resolves that unique
name, records credentials, monitors the Peer, calls `Process.exit(peer, :kill)`
and observes the corresponding `DOWN :killed`. This is BEAM Peer termination
bypassing its normal callback, not an OS SIGKILL test of the external actor.

The new command has no `unregister_peer`, `peer_disconnected`, credit-release or
capability-cleanup calls. Its raw event is retained. The inherited state validator
checks the settled full state before any actor stdin closure. The additional
contract independently derives the exact name owner/queue transition, match
removal, UID credit delta, admission/child removal and unchanged survivor caches,
limits and authority identity. The real healthy observer sends wire calls while
the daemon command is outstanding, keeps its original identity/name/admission,
and continues before and after every phase. Each dead actor must separately
observe socket closure and retire with natural EOF/exit0.

`run.py` is a narrow adaptation of the frozen accepted UID runner. `launcher.exs`
reuses its read-only snapshot transformation and replaces only the security
fixture's kill-command arm. Independent wire encoding, actors, Channel, policy,
state oracle and candidate contract remain inherited. `INHERITED_INPUTS.json`
binds 15 byte-identical inherited copies, including the pinned devenv lock,
historical baseline sample and original security workload read during import.
Original files and earlier evidence are untouched.
The original finite UID policy is retained, plus only the already accepted
UID1100/1101 `org.foundation.Uid` ownership overlay; no allow-all rule is added.

All numeric limits remain inherited: UID names/matches2, peer4/global16; global
connections6/authenticating3; UID connections4/authenticating2. Authority60s,
guest120s and host/global900s stay fixed. Wire health/request/settled checks are
1000ms. The kill witness plus automatic settled readback shares one 1000ms
deadline; this does not extend it. The daemon's DOWN wait is also1000ms.
Natural shutdown retains the inherited5s wrapper wait and1s absence probes,
within the overall authority60s. Fallback containment can preserve safety but
cannot qualify the run: pre-containment PID/group absence, EOF/exit0 and no
timeout/probe errors are mandatory. Guest export and VMoff are necessary;
root must independently prove host driver/VLAN/QEMU retirement.

The future invocation requires both exact candidate manifest and source hashes.
It rejects candidate17's old manifest/source hashes rather than reusing that
receipt as proof for changed production. Root must first qualify the correction,
capture the new source-to-BEAM/artifact binding and review the exact new fixture
closure. Candidate-source aggregation and all Nix-store artifact bytes/modes are
checked before launch. Missing required executable tools produce explicit
blocked selected outcomes. No empty or ad hoc skipped selection qualifies.

## Prepared regression controls — all NOT RUN

`test_contract.py` was authored before its implementation. Independent synthetic
before/after examples reject wrong/missing DOWN identity, normal/EOF closure,
explicit cleanup, credential drift, owner/queue/match leakage, over-release,
survivor or authority drift, changed deadline, wrong/old candidate binding and
missing/duplicate/wrong selected events. These are checker controls, not actual
kernel/daemon evidence. `test_driver.py` extracts the actual helper's AST into an
inert model to check command/health/readback/closure ordering and failure
preservation before actor cleanup. It invokes no real process or signal.
Its package controls import the actual retained security runner from disposable
complete and workload-omitted copies under process/socket/signal guards. The
complete copy must expose WORKLOAD/SELECTED from the genuine pinned JSON; the
omitted copy must fail with FileNotFoundError naming that sibling file. These
three additional controls are source-prepared only, pending fresh root reviews.

Frozen predecessor `test_snapshot.py` and `test_cleanup.py` retain the accepted
baseline/reference, full identity/cache/ledger and natural-retirement/persistence
controls. Their Python-path/source overrides below target this new runner.
Neither test discovery nor imports were performed during preparation. Root must
record actual outcomes and meaningful failing-predicate controls under its
existing bounded offline recorder; no RED/GREEN evidence is claimed here.

Future commands, from repository root, after root's ordered reviews:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/foundation/m1_uid_abrupt_peer/test_contract.py
PYTHONDONTWRITEBYTECODE=1 python3 scripts/foundation/m1_uid_abrupt_peer/test_driver.py
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$PWD/scripts/foundation/m1_uid_abrupt_peer" UID_SNAPSHOT_SOURCE="$PWD/scripts/foundation/m1_uid_abrupt_peer/run.py" python3 scripts/foundation/m1_uid_abrupt_peer/inherited/uid/test_snapshot.py
PYTHONDONTWRITEBYTECODE=1 UID_CLEANUP_SOURCE="$PWD/scripts/foundation/m1_uid_abrupt_peer/run.py" python3 scripts/foundation/m1_uid_abrupt_peer/inherited/uid/test_cleanup.py
```

Root must additionally parse/compile the launcher, check Nix evaluation and
candidate binding, and run the VM through its existing900s host recorder:

```sh
nix-build scripts/foundation/m1_uid_abrupt_peer/test.nix \
  --argstr candidatePath '<new-frozen-post-correction-candidate>' \
  --argstr candidateManifestSha256 '<exact-new-candidate-json-sha256>' \
  --argstr candidateSourceSha256 '<exact-new-source-aggregate-sha256>' \
  --argstr selection all --no-out-link --keep-failed --max-jobs 2 --cores 4
```

These are intended commands, all NOT RUN. The build command is not itself a
host safety recorder or proof of independent host process retirement.

## Parent runtime reconciliation

Use the existing UID VM2 reconciliation approach, not another backend/oracle.
Read complete raw actor receipts and daemon FIXTURE events. Each saved
`abrupt_kills` event must exactly equal one raw daemon event; match its peer,
kernel credentials, unique name, monitor and reason. Re-run the inherited
snapshot/UID joins with saved historical `/proc` witnesses, replay
`contract.validate_kill_selection(report)` and each automatic-state transition,
and reconcile quota/reuse/error/delivery outcomes to the actual raw serials.
Verify exact fixture/candidate/hash/mode/runtime/config bindings and the inherited
cleanup predicates before adopting any scoped result. Confirm actor and daemon
EOF/exit0/PID/group absence, socket removal, no fallback, all original bounds,
guest VMoff and independent host driver/VLAN/QEMU retirement. Missing facts
remain failed or blocked. A valid `all` run selects2/executes2/passes2 with
zero failed/blocked/skipped, and exactly three distinct killed-Peer witnesses.

Router-absent cleanup, FD/egress/capability matrices, original eight-case RES01,
XML/reference conflicts, helper activation, packaged600s, P12 and rollback are
outside this fixture. Current L0/productfalse/accepted-index totals are untouched.
