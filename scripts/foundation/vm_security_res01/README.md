# Native RES-01 fixture sources

Eight independently selected dimensions: UID/global connections (4/6), UID/global
authenticating (2/3), peer/global name associations (2/4), and peer/global match
entries (2/3). Names include queue associations; duplicate matches retain distinct
references. There are no native per-UID name/match controls.

Only `/run/osbus-security/res01/bus` in a marked disposable guest is permitted.
Actors run as actual UID/GID1100 or1101. The observer remains UID1100 throughout.
The unchanged vm_security Client/packet and Channel/Actor transport are reused;
candidate capture remains the unchanged vm_security/capture.py contract.
Original source modes remain in provenance; regular nonsymlink Nix candidate
leaves must have exact readonly0444/0555 modes preserving the trusted executable
bit, and their bytes must still match the frozen manifest.

The launcher verifies the historical daemon pin and exact two defaults sites
plus one command-loop anchor. It evaluates two substituted defaults expressions
and one read-only snapshot extension in memory, preserving the original startup,
policy loading, snapshot fields and command loop. This is transformed fixture
execution, recorded with original/transformed pins, effective Limits and actual
initialized name/match controls. The only policy addition is UID1100 ownership
under `org.foundation.Res01A`, in a root-owned overlay. Production sources and
all original vm_security sources remain unchanged.

The runner persists all outcomes, wire receipts, OS/trusted identity joins,
full authority/table/accounting snapshots, short-phase timings, quota headroom,
successful release/removal, socket close, real actor death and reallocation.
Settled snapshots reconcile every metric and reject retained ingress tombstones.
Each auth-held phase includes probes and completion within400ms, preserving
absolute1500ms and idle500ms. Timing failure is failed evidence.

Root owns tests, source reviews, candidate binding and serialized execution.
For root validation only: `python3 -m unittest discover -s
scripts/foundation/vm_security_res01 -p test_fixture.py`. The regressions use
synthetic observations to exercise the acceptance checker; they never qualify
the eight VM cases. Guest execution uses `test.nix` with an explicitly frozen
candidatePath. Fixed authority60s/guest120s/host900s apply. Daemon cleanup sends
quit+flush before the byte-exact accepted guest stop_channel helper. Each natural
retirement requires stdin closure, waited/reaped exit0 wrapper, actual actor PID,
wrapper PID and owned group absence before inherited containment, plus final
absence and raw-log drains. Fallback cannot qualify natural retirement. Only the
recorded boundary victim may have a SIGKILL exit: its launch /proc starttime,
wrapper/group incarnation, pre-death snapshot, pidfd-bound death operation and
retirement must join. The death boundary freshly reads all four kernel UID/GID
fields and actor/wrapper/group incarnations before signalling; unavailable or
drifting evidence refuses the signal and closes the pidfd. Snapshots retain
already acquired launch incarnation fields without extra held-phase reads.
Native socket removal and a separate guest VMoff record remain mandatory.

The teardown correction has pure Python checker and inert process controls;
those synthetic witnesses do not supply guest/Linux runtime evidence.
No runtime success is claimed. Existing failed evidence and reference, FD,
helper, packaged600s/missing37 and P12 blockers remain; readiness stays L0,
product qualification false and the full P00-P12/M0-M4 goal incomplete.
