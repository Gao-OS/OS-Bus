# P04 compiled XML frame deadline on a private Linux socket

Verify the existing Runtime frame-timeout correction through the actual
Config.load -> Runtime.compile -> Application.start -> Listener -> Peer path.
This is one required PRO-04 eventual-deadline regression for R-05/R-06/R-09,
using a valid ordinary call whose tail is withheld. It adds no production
behavior, optional security audit, exploit test, generated corpus, broad
fuzzing, external API probe or network operation.

Use a separate headless Elixir daemon process, the pinned native adapter and
an independent standard-library Python actor. Start the core with
start_supervised! and an explicit private XML configuration/system profile.
Bind expected credentials to actual nonroot real/effective UID/GID and actor
PID. Create a fresh owned mode0700 directory and narrow only its newly created
socket to mode0600 before starting the actor. No default/live bus address,
service manager, account change or host cutover is involved.

One observer and one source register normally. Check the Listener and real
Peers received the compiled frame_timeout_ms: 5000 unchanged. Send the first
byte and then grow the incomplete ordinary GetId call to its valid16-byte
fixed header. Command/state barriers must show an actual timer, exact retained
bytes, no FDs, and preservation of its reference/token/absolute deadline on
growth. Observer health calls run during the hold. The actor keeps the source
socket open until normal monitored Peer DOWN is observed, then independently
requires exact EOF. Verify restored accounting/registry state, stable authority
and observer processes/names/bus-ID, post-close health, actor exit0 and final
core/listener/socket cleanup. Authentication/Hello/GetId are setup or health;
completed split targets, fixed-header targets and PRO03 are not rerun.

Bounds: state polling1500ms; actor/socket/reply3000ms; natural unchanged5000ms
deadline observed within6500ms; actor alarm30s; ExUnit60s. Reuse the unchanged
host_lifecycle.py outer900s/cleanup5s wrapper. Success requires child exit0 and
graceful_success=true. Never inject expiry, renew the timer, raise a deadline,
silently retry, suppress diagnostics or change a negative assertion to pass.
Preserve raw failures and diagnose them before a changed retry.

The source worker owns only peer_xml_frame_deadline_test.exs and its dedicated
Python actor. Other actors and production sources remain unchanged. Source
reviewers do not execute anything. Root owns checks, artifact/source binding,
execution and ledgers. All agents preserve other edits. Use the frozen artifact
for a distinct native RED and the current source-bound artifact for GREEN;
retain existing unit evidence and never manufacture a production mutation.

This local functional route is authorized by CODEX_GOAL/AGENTS and supersedes
only the earlier unit scope's self-imposed future-VM-only workflow. It does not
replace any required VM/profile gate, qualify full PRO04/05 or promote the
frozen evidence index. VM closure/download blockers and SEC03/06/08,
SEC09-12/FD04 restrictions remain. No Nix build/fetch, alternate download route,
host live-bus/system/account change, Git publication or memory write. M1 stays
unpassed, readiness L0/product_qualified=false until required gates pass.
