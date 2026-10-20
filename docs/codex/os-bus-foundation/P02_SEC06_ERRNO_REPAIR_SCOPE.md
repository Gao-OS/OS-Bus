# P02 SEC06: preserve caller errno before fixture bookkeeping

Preserve stopped source1 and source2 with all drafts, failures and readback pins.
No target from either ran. Source1's log consulted fatal starttime for unrelated
exited peers; source2 additionally identified caller errno captured only after
selection(), whose starttime parser explicitly sets errno=0. That second defect
can change successful unrelated getsockopt errno. It is an observed static path,
not executed libc evidence. No production injection seam is authorized.

Prepare only fresh environment/m1-sec06-interposition-feasibility1/source3/**.
Retain the prior authorized non-target incarnation correction and also capture
incoming errno as the first operation of the getsockopt wrapper, before once/
lock/selection/identity inspection. Restore that saved value before the real
requested getsockopt, and return the real resulting errno after all logging and
unlock on non-injected paths. Preserve return value, buffer, length and exact
selected kernel PID/starttime/UID/GID semantics. Whole-file reverse isolates the
two known corrections; preserve every old source1/source2 file mode/hash.

Prepare actual Linux-native old RED/corrected GREEN sources covering a live
unrelated successful socket option with nonzero errno sentinel while another
target is armed, exited non-target peer, other socket/option, matching/mismatched
selected incarnation, target identity failures and real result/buffer/length/
errno preservation. Test the compiled actual shim/native calls in the marked
disposable VM; a Python state model cannot establish libc behavior. No native
compile or target execution during preparation.

Complete the still-missing bounded experiment/controller/guest/Nix sources only
within the original feasibility scope. All original failure cases, healthy
same-BEAM stream, exact logs/thread/socket evidence, atomic root arming, bounded
deadlines, no preload leakage and natural retirement remain required. Stop the
first further substantive defect; no additional repair under this scope.
Preparation is stdlib/file-data/AST only. Root SPEC, distinct QUALITY and fresh
pin recheck precede separate actual controls/import/parsers/build/realization/
paired VM and observer; distinct raw review follows. Feasibility alone cannot
qualify complete SEC06. All required missing stages stay blocked/NOT RUN.

Other workers are active; preserve their edits. No production/candidate18/map/
consumer/ledger/old evidence/host bus/account/Git/remote/publication/memory
mutation. L0/product_qualified=false; no prior runtime repair rounds consumed.
