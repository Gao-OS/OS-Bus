# P04 fixed-header native regression in a separate Linux process

Advance R-05/R-06/P04 with the existing two fixed-header cases. CODEX_GOAL's
working procedure permits separate daemon processes or disposable containers/VMs
for identity/resource-sensitive tests; AGENTS requires private sockets and VMs
for cutover. The prior fixed-header scope's VM-only workflow was ours. This
scope permits one separate-process Linux RED and one GREEN for this regression,
without substituting local evidence for any VM/profile-replacement gate.

The behavior uses ordinary AF_UNIX sockets, real SO_PEERCRED, and the existing
native adapter. It needs no service manager, UID transition, privileged helper,
namespace, system account change, or VM-specific facility. Root independently
records actual non-root real/effective UID/GID before execution. Parameterize
only fixture UID/GID expectations via OS_BUS_FIXED_HEADER_UID/GID, defaulting to
the original VM identity 1101/1101. Match actual kernel credentials and actor
PID as before. Derive expected EXTERNAL bytes and auth byte count from the
expected UID; the unchanged NormalClient already authenticates with os.getuid.
Keep all frame/control bytes, permissions, policy actions, accounting/observer
assertions, limits and deadlines. Refuse root identities. This is fixture
configuration, never a production identity override or authentication bypass.

Test author owns only peer_fixed_header_lengths_test.exs and its dedicated
Python actor. The imported Hello/transport fixtures stay unchanged; completed
AUTH/BEGIN/Hello/GetId targets are not rerun. Independent reviewer reads source
only. Root owns scope, snapshots, checks, artifacts, execution and ledgers.
All agents preserve others' edits. No optional audit, exploit/penetration work,
broad fuzzing, external API probe, host bus/system/account change, publication
or memory write is included.

Preserve frozen candidate6077a50d, all prior VM attempts and their unobserved
native RED. Use that unchanged candidate for the fresh local RED. For GREEN,
prepare a separate app-directory artifact with current Message, Peer and Runtime
compiled from source, other dependencies/native library pinned unchanged, and
verified :code.priv_dir(:gao_bus) resolution. Do not use stale edited BEAMs or
suppress diagnostics. Run only these two cases; no umbrella application startup.
Use explicit owned mode0700 temporary directories and mode0600 private sockets.
The actor uses only the supplied absolute private address and standard library.

Reuse the existing host_lifecycle.py containment wrapper; retain original
socket/reply/exit3s, state/DOWN1500ms, actor alarm30s, ExUnit60s, outer900s and
cleanup5s bounds. Root checks source syntax/format/compiler diagnostics before
runtime. Preserve raw failures; diagnose before any changed retry, with no
unchanged automatic rerun or deadline increase. A tool/policy access denial
must not trigger an alternate route. Nix source-download failure is an
environment blocker, not permission to contact another download route; this
route needs no Nix build, fetch or network operation.

Success proves this native functional regression for the recorded local Linux
runtime/account only: valid maximum held; invalid prefix automatic normal Peer
DOWN/EOF; real accounting and observer health restored. It does not restore the
pinned VM closure, complete full PRO04/05/M1, qualify a packaged release or
replace the frozen required-evidence index. Required VM cases remain blocked,
L0/product_qualified=false. SEC03/06/08 restrictions, SEC09-12 pause and FD04
exclusion persist.
