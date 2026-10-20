# P10 Stage A installed-helper prerequisite

This gate runs the packaged bridge and HelperWorker against the ordinary
reference daemon on the canonical **disposable guest** system socket. It does
not start GaoBus.Application, enable production activation, qualify ACT01–07,
replace the canonical daemon, or promote readiness.

The parent must provide a fresh immutable P11 capture whose ordinary bridge is
package-time bound to `/run/wrappers/bin/dbus-daemon-launch-helper`, plus the exact
SHA256 of `release.json`. Neither environment helper/config/address selection
nor an unbound prior capture is accepted. Capture/package files are read-only
inputs. Imported package modes follow the existing P11 strict Nix normalization
(0555 executable/directories,0444 other regular files); bytes,links and paths
remain exact. Runtime closure roots from the manifest are anchored in the guest.

Offline checks from the worktree root:

```
python3 -B -m unittest discover -s scripts/foundation/p10_activation -p '*_test.py' -v
nix-instantiate --parse nix/tests/activation.nix
nix-instantiate --eval --strict --read-write-mode nix/tests/activation.nix \
  --argstr releasePath "$P10_FROZEN" --argstr manifestSha256 "$P10_MANIFEST_SHA" -A drvPath
```

Strict C compilation uses the pinned GLib/gio-unix development flags and
`-std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong` plus
`-Wl,-z,relro,-z,now`. Nix builds the same ordinary actor.

Only the parent schedules the heavy build and VM slot. After independent review:

```
nix-build nix/tests/activation.nix --no-out-link \
  --argstr releasePath "$P10_FROZEN" --argstr manifestSha256 "$P10_MANIFEST_SHA"
```

A0 preserves the recorded profile, all original service/policy occurrences and
absent aliases, allowing only the declared immutable fixture directories and
configuration-content restart triggers. Fixture templates/policy bytes are
checked exactly. The reference process, kernel socket owner/listener, bus ID,
installed wrapper permissions and mount semantics must agree before launch.
A1–A7 retain exact selected/executed/pass/fail/block counts with no skips.
A1 contains separate direct-bridge and packaged-Worker subprobes; A3 contains
separate helper exit7/root identity and exec EACCES/ordinary caller subprobes.
All service calls use NO_AUTO_START and owner probes use GetNameOwner.

The C witness is collected at libc main entry after ELF loading and before
explicit GLib APIs or bus opening; it makes no assertion about loader
constructors. It records real/effective/saved identities, groups, complete
bounded environment, process start-time and inherited FDs. Successful clients
check real descriptor contents; the raw actor also verifies dev/inode identity.
The Live fixture separately publishes readiness after installing its graceful
termination handler; the controller pins it with pidfd and rechecks start-time.

One live launch charge is allowed. Every owned transient unit has a fixed
cgroup path, finite runtime/stop bounds, control-group cleanup and retained
metadata on fast exit. Exact GHB record/EOF and normal observer exit are required.
The controller releases its charge only after observed exit and empty cgroup;
these are Stage A containment facts, not production coordinator credit proof.

The Nix runner exports `/run/osbus-p10/evidence` and shuts down the VM in finally.
Reports include raw witnesses/observer outputs even after failure. Required
missing facilities are BLOCKED before dependent rows execute. Preserve every failed VM attempt
in a distinct parent-owned log/output path; never overwrite old evidence.
