# P10 systemd runtime connection

This source slice connects the existing systemd activation implementation to
production configuration. It does not qualify P09, P10, P11 or the installed
profile. Compilation, formatter checks, unit tests, packaged execution and VM
acceptance are deferred by the current assignment.

The release selects `OS_BUS_ACTIVATION=systemd` or `systemd-helper` explicitly.
An absent value or `disabled` keeps activation disabled; other values are
rejected. Embedded invocations use `runtime_invocation: %{activation: :systemd}`
or `:systemd_helper`. Both enabled modes
require the system profile and retain the existing real/effective daemon
identity and configuration validation. It neither starts PID1 nor waits for
PID1 to own a name before the bus sends readiness.

Runtime passes XML `service_start_timeout` and `max_pending_service_starts` to
the coordinator, the timeout to Router, and the complete XML limits to Limits.
Zero remains zero: it is neither replaced by a default nor converted to an
unbounded activation allowance. The existing finite native safety ceilings
remain additional bounds.

The production backend allowlist is exactly `[:systemd, :wait]`. Every selected
service must have a unit accepted by the existing systemd request encoder,
except `org.freedesktop.systemd1`, which is a bounded wait for normal authorized
ownership. Normal policy, name acquisition and current-owner checks still
apply. Missing systemd aliases remain discoverable activation failures; their
Exec fields are never fallback launch commands in this mode.

Traditional entries fail configuration validation with their Exec/User origins;
invalid systemd units carry SystemdService provenance. An explicit servicehelper
directive remains in the captured configuration as dormant metadata. Its path
must be absolute, valid UTF-8, NUL-free and at most 4096 bytes; invalid paths
retain the XML origin. This mode never uses the path to launch a helper and does
not claim to validate the installed helper. Policy repeats backend validation
after its initial file reread and before every reload publication. A changed
service under an unchanged servicedir therefore cannot introduce a helper into
the selected mode. Router also filters definitions by the explicit allowlist.
Failed reload keeps the previous complete generation.

The explicit `systemd-helper` mode adds `:helper` to the allowlist only after
installed-package validation succeeds. It has no caller-selected executable,
configuration root, UID, environment or approval flag. Missing, malformed or
untrusted package bindings refuse startup before readiness. The systemd-only
mode remains usable without a helper manifest.

Systemd-backed services in either enabled mode use the same ActivationFailure
handler. Mixed mode retains current-owner, UID/incarnation, receive-policy and
wire validation before propagating the backend error and draining its waiters.
The added mixed-mode Router fixture regression remains UNRUN and does not
exercise helper installation or bypass its binding requirement.

## Fixed package manifest

The only manifest location is `priv/helper_binding.json` in the running
`gao_bus` application. Version 1 has exactly these fields:

| Field | Binding |
| --- | --- |
| `version` | Integer `1` |
| `bridge` | Artifact record with path exactly `gao_helper_bridge`, resolved only against the running application's `priv` directory |
| `helper` | Absolute underlying helper artifact record |
| `wrapper_source` | Absolute generated standard-wrapper artifact record |
| `entrypoint` | Installed absolute wrapper artifact record; root owner, daemon GID, exact installed mode `04550` or `04750`, same bytes as wrapper source |
| `compiled_helper_path` | Exact NUL-terminated `.gao_helper_binding` ELF section contents, equal to XML servicehelper and entrypoint path |
| `configuration_root` | Exact first XML source path, obtained from this helper build's generated `DBUS_SYSTEM_CONFIG_FILE` definition |
| `endpoint` | Exactly `unix:path=/run/dbus/system_bus_socket`; XML listen and actual listener must agree |
| `daemon` | Object with `name`, non-root `uid`, `gid`; matches real/effective runtime IDs and captured account record |
| `servicedirs` | Ordered effective XML servicedirs |
| `files` | Every captured configuration/account/service file path mapped to its lowercase SHA256, or null for a captured missing file |
| `directories` | Every captured directory path mapped to its sorted complete names, or null for a captured missing directory |
| `accounts` | Daemon and selected service account names mapped to exact `uid`, `gid` and sorted `groups` |

Each artifact record has exactly `path`, lowercase `sha256`, `uid`, `gid` and
`mode` (integer permission bits). All artifacts require root ownership and no
group/world write bits. The bridge path is package-relative to permit release
relocation and immutable capture without circular store-path references. It is
not a path override. Other artifact and configuration paths remain absolute.

`HelperBinding` bounds the manifest to 1 MiB, each of four artifacts to 32 MiB,
and captured files to 1 MiB each/16 MiB total. Captures are limited to 1024 files,
64 directories and 8192 directory entries. ELF32/ELF64, both byte orders, use a
bounded section-table parser; missing, duplicate, extended-index, stripped or
malformed binding sections refuse the profile. An incidental path substring is
not binding evidence.

Every existing ancestor and symlink must be root-owned and protected against
non-root replacement. Root-owned sticky directories may allow group creation
without permitting replacement of existing root-owned children (the Nix store
case); world-write is refused. Symlink resolution is bounded to 32 hops and
paths to 4096 bytes/128 components. Symlink targets containing dot/parent
components are unsupported, preventing lexical normalization from differing
from kernel traversal through intermediate symlinks. File reads compare descriptor metadata and
pathname/ancestor/symlink observations before and after the bounded read. No
external program is invoked to validate the installation. These metadata
checks detect observations of change; they do not create a filesystem-wide
transaction or revoke the root publisher's authority.

Startup validates the captured generation and installation. Policy's initial
reread and every reload candidate repeat validation before publication, bound
to the original package-manifest digest. A mismatched candidate retains the
previous generation and returns XML/source provenance. Changed captured bytes
require a corresponding trusted package generation and restart; helper mode
does not silently approve a mutable service-tree update.

The coordinator passes its validated binding context to each worker. Immediately
before `Port.open`, the worker rechecks real/effective identity, the fixed
manifest digest, all artifacts, all captured files (including account databases)
and all directory memberships. This reread runs off Router after launch credit
reservation. Missing/invalid context refuses before a Port exists. There is no
implicit test-environment or five-option worker bypass. The bridge still
receives exactly one well-known name argument and an empty environment.

## Reproducible production and acceptance boundary

`scripts/foundation/helper_binding_manifest.exs` is source for the package-build
producer. It must run inside the isolated deployment-image builder with the
exact intended absolute-path configuration/account tree, built application,
helper, generated helper `config.h`, and generated standard-wrapper binary.
The helper header and artifacts must be inputs from the same reproducible Nix
helper/wrapper derivations. The producer extracts the helper's fixed root from
`DBUS_SYSTEM_CONFIG_FILE`, parses the actual bridge ELF binding, captures the
configuration through the production loader and compares the generated
candidate through the pure pairing validator. It requires the supported
wrapper binary to retain its fixed helper target; a generic wrapper without
that evidence is unsupported. It records exact artifact bytes and final root
installation metadata, emits the fixed manifest once, and writes a provenance
sidecar with producer/header/manifest hashes and the helper derivation path (an input derivation, not a self-reference to
the output containing this manifest).

The checked-in enclosing entrypoint is `nix/tests/helper_package.nix`, with the
VM-local stdlib installer in `scripts/foundation/p10_package/assemble.py` and
its complete invocation/input contract in that directory's README. It accepts
explicit hash-bound clean source, unpacked dependency and real Hex archive
inputs. Its helper derivation retains the actual generated configuration header
and post-fixup helper/header receipt in a second output. The assembly image
selects that same helper for the NixOS-generated configuration and standard
wrapper, preserving the complete installed policies/service/account tree.
The assembly retains the timesync account and installed alias required by those
policies even though QEMU disables timesyncd startup, and provides Git for Mix's
offline SCM checks against complete locked dependency checkouts.
Only this offline image masks its D-Bus service/socket before boot; it never
stops or replaces a live bus and makes no compatibility-profile claim.

The installer guards QEMU/image/kernel identity and absence of the canonical
socket before any subprocess or mutation. All Mix/Elixir commands drop real,
effective and saved UID/GID to the fixed non-root builder with no supplementary
groups; the child trampoline records actual IDs before exec, and the producer
also records its native IDs. Builds use the existing real Makefile/Mix release
surface and fixed bridge binding, in a private network namespace with explicit
offline inputs. The producer operates against the actual packaged release's
priv directory and reads installed wrapper metadata, including the exact
`04550`/`04750` mode, rather than accepting caller mode/UID approvals.

Staging remains builder-owned while compilation/manifest generation runs. The
root stdlib installer then relocates the release, installs root-owned read-only
package metadata/artifacts, and inventories the generated bindings against
installed files. That source inventory is not a runtime-validator success
claim. Package-relative bridge identity avoids a circular/stale release path.
The driver exports logs, producer provenance and the unqualified package from
the bounded disposable VM and shuts down in `finally`. Caller-written metadata,
an unrelated build header, or an operator approval boolean is not accepted as
package production. The manifest attests the trusted package publisher's exact
build/deployment inputs; actual privilege behavior remains acceptance work.

No manifest or installation was produced here. The producer, compiler,
formatter, focused tests and all installed/VM acceptance remain UNRUN. Required
later acceptance includes actual setuid behavior, helper reread equivalence,
canonical endpoint, environment/FD isolation and ADR-006 cgroup shutdown. No new
privileged helper or root BEAM is introduced.

Focused unexecuted regressions are in `runtime_activation_test.exs`,
`activation_reload_test.exs` and `helper_binding_test.exs` under
`apps/gao_bus/test/config/`. The existing Python worker fixtures still preserve
all their real fork/exit/FD/protocol assertions. They currently build a bound
bridge in an unprivileged temporary package without an installed binding, so
the new worker must refuse that launch. Their status is
**UNRUN / BLOCKED_TEST_FIXTURE** until acceptance supplies an isolated trusted
root-owned package/manifest fixture; neither a bypass nor weakened assertions
is provided by this source slice.
