# Source-prepared Gao core listener transfer-failure subcase

This fixture is SOURCE_ONLY_NOT_EXECUTED. It prepares only
FAIL-02/transfer-failure, one genuine wrong-owner accepted-socket procedure.
No production defect is asserted. Full FAIL-02 (transfer/startup/occupied-path)
and SYS-02, leak/soak, packaged replacement and readiness remain unqualified.
Historical startup-ceiling and occupied-path evidence is preserved separately.

The independent client is UID/GID1101 and the registered healthy observer is
UID/GID1100. Both use the immutable vm_security independent actor transport.
The only client extension adds a strict one-byte42 transfer operation with
recv()==b'' EOF; reset/timeout/data are failures. The observer retains the exact
inherited actor.py and makes actual GetNameOwner/GetId wire calls before, while
the root fault response is outstanding, and after the transfer. No ExDBus actor
or second host harness is introduced.

The root-only VM channel creates a separate /run/osbus-security/listener-transfer/
transfer socket, leaving the incumbent bus socket untouched. A monitored holder
owns the real accepted socket and confirms byte42 plus kernel SO_PEERCRED.
The controller starts an actual incomplete GaoBus.Peer and verifies waiting_socket,
nil credentials/native socket/unique, empty registry and absent Router/Limits
admission, then calls the compiled GaoBus.Listener.transfer_ownership/2 from a
non-owner. The actual return must be {:error,{:invalid,:not_owner}}, the monitored
Peer must terminate with :shutdown, and both OTP closed-socket readback and
/proc/daemon/fd/<native-fd> ENOENT must occur before holder/listener fixture cleanup.
The external client independently requires actual EOF, before its actor stdin closes.

The command emits the actual error and matching monitored Peer/holder references,
marker/accepted credentials, native FD link/removal, incomplete guards and exact
before/after snapshot. The snapshot includes core process identities/children,
peer registry identity, authority/cached name/match/capability tables, accounting,
policy and native FD inventory. It also captures the incumbent socket's inode and
device. It must recover the exact warmed baseline within the existing1s transfer
bound, with no explicit unregister/peer-disconnect/credit-release operation.
Only fixture holder/listener/path resources are explicitly retired after the
production branch has already closed the accepted socket.

launcher.exs pin-checks and transforms the original immutable daemon in memory:
one read-only snapshot extension and two new fault command arms inserted before
quit. Original security commands and sources remain byte-identical. Before-image
procedure apps/gao_bus/test/listener_transfer_failure_test.exs is the genuine
source at67-104; production ownership branch is Listener.transfer_ownership/2 at15-24
and normal handoff at180-190. Original security FAIL-02 tested the256child ceiling
and explicitly excluded this kernel ownership branch; this fixture closes only
that distinct observation gap after actual root qualification.

INHERITED_INPUTS.json binds8exact original/copy inputs: complete security package
run.py/actor.py/workload.json/daemon.exs/state.ex/policy.exs/capture.py, plus immutable
Nix lock. Genuine WORKLOAD JSON is present because retained run.py reads it at
module import. The runner imports that actual module with its actual sibling
actor on sys.path. The client imports the actual immutable actor.Client; independent
wire code is not copied/reimplemented in the wrapper. Capture input is preserved
but never executed: candidate18 is already root-frozen.

cleanup.py contains the byte-exact, dedented accepted guest stop_channel function
from m1_uid_abrupt_peer/run.py with only required module imports added. It records
stdin closure, wrapper exit0, actual actor/wrapper/group absence before final
containment and preserves raw logs. Any fallback, timeout or probe error fails
natural-retirement acceptance. It is a guest helper, not another host backend.
Root reuses the existing FD07 recorder/lifecycle adapter/host observer/alias helper
for all future parent execution, with fresh source binding and reconciliation.

Candidate18 is mandatory: manifest372899cfffc08e6ccf98669add5d6b81b5d549fdf5277241ff7ac11465baa4b7,
sourceefe7af5c1f8f7750fb6a3391d39398131c3139e8e422d79e8e70f99962f29de9,
71source/57source-to-BEAM/80artifact entries. Runner and Nix reject other bindings;
all artifacts/modes are checked before launch. Genuine finite original policy is
copied unchanged, without an ownership overlay or blanket permission exemption.

Bounds remain authority60s/guest120s/host900s/hostcleanup5s; health/request/fault/
EOF1s; accepted guest natural-wrapper wait5s and absence probes1s. Initial daemon
ready reads retain inherited Channel.read10s, bounded by authority60s. Deterministic
socket marker and monitored DOWN messages replace arbitrary test sleeps. Whole
root-command transfer/readback is independently bounded1s; probe calls are real
wire calls while response is outstanding, not a physical timestamp proof of
scheduling overlap with the precise native call.

## Prepared pure controls — all NOT RUN

12test methods were authored before the checker implementation. They include
positive synthetic shape and negative exact-error/DOWN/incomplete-admission/
real-holder/native-FD/kernel-identity/separate-observer/authority/inode/baseline/
deadline/exact-EOF/wire-probe/selection/teardown predicates. Synthetic witness()
values are solely checker inputs, not saved daemon/kernel/runtime evidence.
The preserved before/contract.py is an explicit no-validation pre-implementation
checker. Root's meaningful RED selects only wrong-owner-error rejection against
that before source; GREEN uses current full scoped controls. Expected outcomes
are specifications until recorded, not execution results.

After root's ordered source SPEC then QUALITY review of the exact entire package,
root may invoke through its existing bounded60s/cleanup5s recorder:

- RED: LISTENER_CONTRACT_SOURCE=<E>/before/contract.py python3 -B <F>/test_contract.py
  TransferControls.test_reject_wrong_owner_error. Expected Ran1test/failure1/exit1:
  invalid transfer error is accepted by the not-yet-implemented checker.
- GREEN: python3 -B <F>/test_contract.py. Expected Ran12tests/errors0/failures0/
  skipped0/exit0. Every before/after input hash and natural host retirement must
  be independently verified; no recording wrapper/receipt is supplied here.
- Import closure/activity guards, current launcher and prepared transformed-daemon
  Elixir parsing, Nix parsing/evaluation and exact candidate/source freeze remain
  root prerequisites. Static Python compile does not qualify those imports or syntax.

No review marker, candidate binding, approval, control receipt, runtime receipt,
freeze/build tree or VM launch is created by this worker. Suggested fresh review
paths are E/SPEC_REVIEW1.md then E/QUALITY_REVIEW1.md; root assigns acceptance tokens.

## Future root runtime — NOT RUN

Only after reviewed controls and fresh root source approval, reuse existing finite
host lifecycle and realized-artifact inspection. The prepared Nix invocation is:

nix-build -A driver <F>/test.nix --argstr candidatePath <candidate18>
--argstr candidateManifestSha256 <exactmanifestabove>
--argstr candidateSourceSha256 <exactsourceabove> --argstr selection transfer_failure
--no-out-link --keep-failed --max-jobs 2 --cores 4

This text is not a new host recorder. Root separately authorizes one disposable
VM, independently observes live driver/VLAN/QEMU identity/executable/credentials,
then reconciles complete raw logs and its own recorder retirement. One scoped
passing report selects1/executes1/passes1 with failed0/blocked0/skipped0. The whole
FAIL-02 index row stays unmapped until all separate required subcases are accepted.

Raw reconciliation must join both /proc actor witnesses to actual kernel credentials,
the observer's unchanged Peer/name/admission and every request/reply serial,
three healthy phases/bus-ID continuity, real wrong-owner error and monitored
Peer DOWN:shutdown, holder ownership/marker/native FD readbacks, exact before/
after/full driver baseline/inode equality and EOF-before-stdin ordering. Replay
pure contract predicates against the exact raw daemon/actor events and verify
candidate/artifact/fixture/provenance/policy bytes and realized Nix commands.
Guest natural actor/daemon retirement, private bus/fault-path removal and VMoff
are necessary; independently proven host recorder/driver/VLAN/QEMU retirement
is additionally mandatory. Missing facts remain failed/blocked.

Reports/source hashes/static checks in E/m1-listener-transfer1 bind this prepared
closure and preserved originals. No ledger/index/adoption edit follows preparation.
ReadinessL0/productfalse/full foundation goal incomplete persists.
