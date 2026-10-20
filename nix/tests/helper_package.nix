# Offline disposable image assembly, not a bus/activation qualification gate.
# All caller inputs are real immutable source/dependency/archive artifacts.
{ sourcePath, sourceNarHash, depsPath, depsNarHash, hexArchivePath, hexArchiveSha256 }:
let
  lock = builtins.fromJSON (builtins.readFile ../../devenv.lock);
  pinned = lock.nodes.nixpkgs-src.locked;
  stablePinned = lock.nodes.nixpkgs-stable.locked;
  fetch = pin: builtins.fetchTree {
    type = "github"; inherit (pin) owner repo rev narHash;
  };
  pkgs = import (fetch pinned).outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  stable = import (fetch stablePinned).outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  source = builtins.path {
    path = builtins.toPath sourcePath; name = "osbus-p10-package-source"; sha256 = sourceNarHash;
  };
  dependencies = builtins.path {
    path = builtins.toPath depsPath; name = "osbus-p10-package-dependencies"; sha256 = depsNarHash;
  };
  hexArchive = builtins.path {
    path = builtins.toPath hexArchivePath; name = "osbus-p10-hex.ez";
  };
  assembly = ../../scripts/foundation/p10_package/assemble.py;
  # Retain the actual generated header from the SAME helper build. No separate
  # hand-authored description of its compiled configuration is accepted.
  helper = pkgs.dbus.overrideAttrs (old: {
    outputs = (old.outputs or [ "out" ]) ++ [ "gaoHelperMetadata" ];
    postInstall = (old.postInstall or "") + ''
      selected=""
      for candidate in config.h build/config.h; do
        if [ -f "$candidate" ] && grep -q '^#define[[:space:]]*DBUS_SYSTEM_CONFIG_FILE[[:space:]]*"' "$candidate"; then
          test -z "$selected" || { echo "ambiguous generated helper config.h" >&2; exit 1; }
          selected="$candidate"
        fi
      done
      test -n "$selected" || { echo "supported generated helper config.h missing" >&2; exit 1; }
      test -f "$out/libexec/dbus-daemon-launch-helper"
      mkdir -p "$gaoHelperMetadata"
      install -m 0444 "$selected" "$gaoHelperMetadata/config.h"
    '';
    postFixup = (old.postFixup or "") + ''
      test -f "$out/libexec/dbus-daemon-launch-helper"
      test -f "$gaoHelperMetadata/config.h"
      helperHash=$(sha256sum "$out/libexec/dbus-daemon-launch-helper" | cut -d ' ' -f 1)
      headerHash=$(sha256sum "$gaoHelperMetadata/config.h" | cut -d ' ' -f 1)
      cat > "$gaoHelperMetadata/build-receipt.json" <<EOF
      {"helper":"$out/libexec/dbus-daemon-launch-helper","helper_sha256":"$helperHash","config_header":"$gaoHelperMetadata/config.h","config_header_sha256":"$headerHash"}
      EOF
      chmod 0444 "$gaoHelperMetadata/build-receipt.json"
    '';
  });
in
assert builtins.hashFile "sha256" hexArchive == hexArchiveSha256;
pkgs.testers.nixosTest {
  name = "osbus-p10-offline-helper-package";
  nodes.machine = { config, lib, ... }: {
    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 12288;
    virtualisation.cores = 2;
    virtualisation.vlans = [];
    boot.kernelParams = [ "osbus.p10-package-builder=1" ];
    services.dbus.enable = true;
    services.dbus.implementation = "dbus";
    services.dbus.dbusPackage = helper;
    # Retain generated configuration, policies, accounts and standard wrapper.
    # Only this assembly image masks its bus units; no canonical bus is started.
    systemd.services.dbus.enable = lib.mkForce false;
    systemd.sockets.dbus.enable = lib.mkForce false;
    # QEMU disables timesyncd startup; its installed D-Bus policy still names
    # this account. Retain the existing profile's account and service alias.
    users.users.systemd-timesync = {
      uid = config.ids.uids.systemd-timesync;
      group = "systemd-timesync";
    };
    users.groups.systemd-timesync.gid = config.ids.gids.systemd-timesync;
    systemd.additionalUpstreamSystemUnits = [ "systemd-timesyncd.service" ];
    systemd.services.systemd-timesyncd.aliases = [ "dbus-org.freedesktop.timesync1.service" ];
    users.groups.osbusBuilder.gid = 1900;
    users.users.osbusBuilder = {
      isSystemUser = true; uid = 1900; group = "osbusBuilder"; extraGroups = [];
    };
    environment.etc."osbus-p10-package-builder".text = "offline-disposable-image-v1\n";
    environment.etc."osbus-p10-package-profile.json".text = builtins.toJSON {
      schema = 1;
      inherit pinned stablePinned sourceNarHash depsNarHash hexArchiveSha256;
      source = toString source;
      dependencies = toString dependencies;
      hex_archive = toString hexArchive;
      helper = "${helper}/libexec/dbus-daemon-launch-helper";
      helper_derivation = helper.drvPath;
      helper_config_header = "${helper.gaoHelperMetadata}/config.h";
      helper_build_receipt = "${helper.gaoHelperMetadata}/build-receipt.json";
      installed_helper_source = config.security.wrappers.dbus-daemon-launch-helper.source;
      wrapper_script = config.systemd.services.suid-sgid-wrappers.script;
      daemon = "messagebus";
      daemon_uid = config.users.users.messagebus.uid;
      daemon_gid = config.users.groups.messagebus.gid;
      builder_uid = 1900;
      builder_gid = 1900;
      configuration_directory = toString config.environment.etc."dbus-1".source;
      elixir = "${stable.beam28Packages.elixir_1_18}/bin/elixir";
      mix = "${stable.beam28Packages.elixir_1_18}/bin/mix";
      rebar3 = "${stable.beam28Packages.rebar3}/bin/rebar3";
      build_path = lib.makeBinPath [ stable.beam28Packages.elixir_1_18 stable.erlang_28
        stable.beam28Packages.rebar3 pkgs.gitMinimal pkgs.gnumake pkgs.stdenv.cc pkgs.coreutils ];
    };
    environment.systemPackages = [ pkgs.python3 pkgs.coreutils ];
    system.stateVersion = "25.11";
  };
  testScript = ''
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("suid-sgid-wrappers.service")
        print(machine.succeed("python3 -B ${assembly}", timeout=1900))
    finally:
        try:
            machine.copy_from_vm("/var/lib/osbus-p10-package", "p10-offline-package")
        finally:
            machine.shutdown()
  '';
}
