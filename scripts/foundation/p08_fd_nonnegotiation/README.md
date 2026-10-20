# Independent FD-05 core fixture

This selected fixture tests the disposition of a real descriptor sent to an
unnegotiated recipient. It runs unicast rejection and mixed-negotiation
broadcast assertions against sequential private Gao and reference brokers in a
disposable Linux VM. It does not replace a bus or qualify an installed profile.

The independent Python actor reuses the existing raw socket/SCM_RIGHTS framing
fixture. The root controller observes actual actor/broker process identities
and numeric Linux FD inventories. Clients in one actor share that actor's real
OS PID. The Gao backend reuses the unchanged guest-only quota daemon solely for
bounded authority/credit/pending/negotiation inspection; this workload stays
below its fixed limits. Candidate16 is a frozen development capture, not a
release. Reference uses an explicit EXTERNAL-only private core configuration.

Run offline controls from the repository root:

```sh
python3 -B -m unittest discover -s scripts/foundation/p08_fd_nonnegotiation -p '*_test.py' -v
```

After reviewed controls and immutable input checks, run only in the pinned
Linux development environment, with inherited DBUS_* selectors removed:

```sh
nix-build scripts/foundation/p08_fd_nonnegotiation/test.nix \
  --argstr candidatePath /absolute/path/to/frozen/candidate16 \
  --argstr scopePath /absolute/path/to/reviewed/FD05/SCOPE.md \
  --no-out-link --keep-failed --max-jobs 2 --cores 4
```

The controller rejects execution without the disposable-guest sentinel and
exact private guest path. The Nix wrapper exports raw reports/configuration/
actor/broker logs on failures and shuts the guest down. Guest poweroff is not
a substitute for measured successful workload cleanup. Missing inputs, failed
assertions, reference disagreements or incomplete teardown remain failures or
blockers. FD-05 network, other FD/resource rows and full P08/M1–M4 acceptance
remain separate required evidence.

The scope and actual execution ledger are in
docs/codex/os-bus-foundation/STATUS.md and the dedicated
test/reports/foundation/continuation-20261011-full-goal/environment/
fd05-independent-core1 evidence directory. Preserve earlier failed receipts.
