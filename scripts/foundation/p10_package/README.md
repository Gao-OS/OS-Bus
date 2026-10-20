# Offline P10 helper package assembly (source only)

This is a checked-in assembly route for a disposable QEMU image. It does not
start a bus, run the helper, qualify activation, or change the declared
systemd-only core profile. All execution, Nix evaluation/build, installation
validation and VM acceptance are **UNRUN**.

`nix/tests/helper_package.nix` takes six explicit real inputs:

- `sourcePath` and `sourceNarHash`: clean source-only snapshot containing the
  complete current implementation, Makefile and producer; no `.git`, `.trees`,
  `_build` or `deps` directory.
- `depsPath` and `depsNarHash`: complete unpacked dependency source tree for
  that snapshot's `mix.lock`, including required Hex SCM metadata and complete
  Git SCM checkouts with their repository metadata at the locked revisions
  (including the production `heroicons` dependency). This is a real build input;
  the assembly never uses prepared BEAM artifacts.
- `hexArchivePath` and `hexArchiveSha256`: actual locally provided Hex archive,
  verified by content SHA256 before import and again inside the guest.

The two directory hashes are NAR hashes accepted by `builtins.path.sha256`;
they are not an approval field. The expression imports both toolchain pins from
the checked-in `devenv.lock`. Its derived helper retains its own generated
`config.h` and a helper/header SHA256 receipt after fixup. The VM selects this
same helper derivation for D-Bus configuration and its generated standard
setuid wrapper. No new privileged helper is built.

Later explicit invocation, after review (not executed here):

```sh
nix-build nix/tests/helper_package.nix --no-out-link \
  --argstr sourcePath /nix/store/<clean-source-input> \
  --argstr sourceNarHash '<source-NAR-hash>' \
  --argstr depsPath /nix/store/<unpacked-dependency-input> \
  --argstr depsNarHash '<dependencies-NAR-hash>' \
  --argstr hexArchivePath /nix/store/<real-hex-archive>.ez \
  --argstr hexArchiveSha256 '<archive-content-SHA256>'
```

The image retains all generated D-Bus policies, services and accounts, including
the `systemd-timesync` account and installed alias even though QEMU disables
timesyncd startup. Only
this assembly image masks the generated `dbus.service` and `dbus.socket` before
boot, preventing their automatic start. This masking is an offline assembly
condition, not a compatibility profile or permission to stop a live bus.

Before any subprocess or mutation, `assemble.py` requires root for its stdlib
installer, the dedicated protected image marker, dedicated kernel command-line
marker, QEMU DMI identity, and absence of the canonical pathname and registered
Unix socket. Ordinary host invocation refuses. The child trampoline repeats
isolation checks and requires real/effective/saved UID/GID 1900 with no
supplementary groups before recording those actual IDs and replacing itself
with the pinned non-privileged Mix/Elixir executable. No BEAM runs as root.

The installer checks the helper/header build receipt, the exact NixOS-generated
configuration root, the generated wrapper script's unique wrapper artifact,
the wrapper's fixed helper target, installed wrapper bytes/mode/owner, and local
daemon accounts. It preserves the installed root-owned `04550` or `04750`
standard wrapper and matching daemon GID. It never substitutes a caller mode,
UID, configuration root, executable or approval boolean.

The builder enters a private network namespace, copies the explicit immutable
source/dependencies into its own staging area, installs the verified local Hex
archive offline, then runs `mix compile` and `mix release os_bus`. The fixed
build PATH includes Git for Mix's offline SCM lock checks. The existing
`apps/gao_bus/Makefile` builds the actual bridge with fixed
`GAO_HELPER_PATH=/run/wrappers/bin/dbus-daemon-launch-helper`. The pinned Elixir
then loads the actual packaged release modules (without starting applications)
and runs the producer directly against that release's `priv` directory. The
producer is itself image-only, refuses root identity, records its actual
non-root IDs, and derives the entrypoint metadata from the installed wrapper.

Staging is builder-owned and writable while compilation/production runs. The
root stdlib installer subsequently relocates the release, sets root ownership,
removes builder write bits, and inventories the generated manifest against
the installed artifacts/files/directories. That inventory is explicitly not a
claim that the Elixir runtime validator has run. The manifest's bridge identity
is package-relative, so relocation does not embed a stale or circular path.

Every build subprocess has a finite deadline within an 1800-second aggregate
budget and receives a private process group; every exit path kills that owned
process group and reaps its direct child. The VM driver bounds assembly to 1900 seconds, exports
`/var/lib/osbus-p10-package`, and shuts down in `finally`. Existing output is
never reset. Failure preserves logs and staging for diagnosis. On success the
export contains the root-owned release, generated manifest and provenance,
actual successful child IDs, build logs and input/installation inventory in
`assembly.json`. Immutable helper/toolchain/configuration closure paths remain
explicit inputs for any later capture of this image.

Required later evidence includes successful real source build, actual generated
header/profile compatibility, production startup/reload/prelaunch validation,
root-owned worker fixtures, setuid/FD/environment behavior and cgroup cleanup.
`nix/tests/activation.nix` remains the older installed-helper prerequisite; it
does not consume or qualify this new package automatically. No whole-P10
completion claim follows from adding this assembly source.
