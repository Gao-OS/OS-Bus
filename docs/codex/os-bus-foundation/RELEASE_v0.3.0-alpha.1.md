# OS-Bus Foundation v0.3.0-alpha.1

This GitHub source prerelease records the foundation implementation checkpoint.
Highest verified readiness is **L0**, `product_qualified=false`. P00–P12 and
M0–M4 remain incomplete; the earliest unaccepted package is M1/P02. This source
has not qualified as a replacement for a live system or session bus.

The checkpoint includes bounded routing/fan-out and activation accounting,
systemd/helper activation implementation, guarded offline packaging and
disposable-VM drivers, stronger source-cleanup/zero-quota regressions, and the
supplementary P07 ownership recorder and transcript oracle. AGENTS.md and
README.md now describe the actual implementation and verification boundaries.

Recorded verification covers scoped test/production compilation and explicit
formatting, 53 distinct ordinary ExUnit cases across 63 executions with zero
failures, and 19 ordinary offline Python cases. These are scoped results against
their recorded sources, not full-suite or replacement qualification. Of 40 added
ExUnit declarations, 32 passed and eight remain UNRUN/BLOCKED. Historical failures
are preserved in [STATUS.md](STATUS.md).

The three original P07 reference comparisons remain BLOCKED_DESIGN; the new
offline oracle does not pass them, and its actual collector/observer has not run.
Complete locked dependency and Hex inputs, assembled/installed package behavior,
helper/native/FD and strict-gate qualification remain incomplete. All 11 canonical
VM rows remain UNRUN/BLOCKED_USER_DEFERRED. Security tests are prohibited and VM
acceptance is deferred under the current instructions. Source completeness is
UNPROVED and the original foundation goal remains blocked.

Automatic push checks are limited to ordinary offline checks. Existing Mix,
full-test and acceptance jobs remain intact behind explicit manual inputs;
input prerequisites and separate authorization must be satisfied before use.
Reporting/skipped jobs provide no passing evidence for held gates.

GitHub's source archives are the release deliverables. There is no qualified
binary/installation package, Hex publication, host deployment or bus cutover
in this release. The umbrella checkpoint version is 0.3.0-alpha.1; independently
versioned component packages retain their existing versions. The existing
v0.2.1 stable release is not replaced as GitHub's latest release.
