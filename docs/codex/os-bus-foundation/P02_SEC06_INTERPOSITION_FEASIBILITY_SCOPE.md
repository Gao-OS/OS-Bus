# P02 SEC06: accepted-socket fault-injection feasibility

The accepted closed/unconnected-socket partial does not exercise credential
failure on a real externally accepted stream. No production failure seam is
authorized or needed for this investigation. TEST_PLAN SEC06 explicitly permits
real/simulated adapter failure. Root's read-only ELF check of the pinned OTP27
beam.smp found an undefined getsockopt@GLIBC_2.2.5 symbol (tool chunk224591).
That makes fixture-only libc interposition a technical candidate, not verified
capability. It avoids designing a new production credential API.

Prepare only fresh `environment/m1-sec06-interposition-feasibility1/source1/**`.
Use a marked disposable Linux VM, private Unix socket, pinned OTP/Elixir and
candidate18 Credentials module. A test-only LD_PRELOAD shared object may wrap
getsockopt only in the owned guest BEAM process. It must call the real function
to identify each accepted socket's kernel SO_PEERCRED, select exactly the
predeclared external actor PID/starttime and option17or59, and leave all other
processes/sockets/options unchanged. The shim must never propagate to an actor,
supervisor, guest service or host environment. Do not interpose the host runtime.

Keep one established independent nonfaulted stream serviceable before, during
and after arming, on the same BEAM. Demonstrate a normal new accepted connection,
required-ucred errno, unexpected optional-groups errno, documented unsupported
groups errno, and a disarmed fresh admission. Fixed malformed/truncated return
length may be explored as a separately labeled simulated adapter-result case;
do not describe it as a kernel-generated malformed credential. Record original
real ucred, chosen error/result, target fd/socket inode, caller thread and actor
PID identity, all calls in sequence and the actual OTP/Credentials result.
No asserted UID, zero identity, stale PID or returned bytes may stand in for the
kernel identity. No arbitrary writable global credential hook in production.

Build the shim only inside pinned Nix. Validate fail-closed target selection,
pass-through behavior, complete original ucred and all-thread symbol binding.
Arming state must be root-owned/no-symlink/atomic and finite. A lost/corrupt
fixture record or unidentifiable target is a failed experiment, not a permitted
fallback. Keep fixture error distinct from expected injected credential error.
Use bounded request/cleanup/guest/host deadlines fixed before execution, exact
command receipts, native socket/FD cleanup, natural process retirement and VMoff.

This is feasibility only: no SEC06 complete row, policy-denial qualification,
product/readiness promotion or runtime acceptance of a later full fixture.
The follow-on full-core test, if feasible, must use actual accepted GaoBus Peer
admission and group-policy authorization, whole authority/credit/resource
recovery and independent observer effects. Preserve the existing partial.

Prepare source-derived negative controls, immutable source/runtime/tool pins,
guarded handoff and seals using file-data/AST only. Root SPEC and distinct QUALITY
precede serialized actual compiler/parser/control/build/realization and once-only
VM execution. A substantive failure stops that stage; preserve raw evidence.
No target execution during preparation. Other workers are active; preserve all
occupied outputs/old sources. Root owns adoption/ledger. No production/candidate18,
map/consumer mutation, host bus/account action, Git/remote/publication or memory
write. L0/product_qualified=false.
