# Real installed-helper ABI only. Reference remains the canonical guest bus.
{ releasePath ? null, manifestSha256 ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if releasePath == null then throw "A new immutable bound releasePath is required"
    else builtins.path { path = builtins.toPath releasePath; name = "osbus-p10-installed-helper-release"; };
  manifestText = builtins.readFile (frozen + "/release.json");
  manifest = builtins.fromJSON manifestText;
  roots = map builtins.storePath (manifest.runtime.store_roots ++ [
    (builtins.dirOf (builtins.dirOf manifest.inspection_elixir.path))
  ]);
  anchors = pkgs.writeText "osbus-p10-runtime-roots" (builtins.concatStringsSep "\n" roots);
  fixture = builtins.path { path = ../../scripts/foundation/p10_activation; name = "osbus-p10-activation-fixture"; };
  transport = builtins.path { path = ../../scripts/foundation/p08_sustained; name = "osbus-p10-independent-transport"; };
  capture = builtins.path { path = ../../scripts/foundation/vm_security; name = "osbus-p10-binding-inspection"; };
  recorded = builtins.path { path = ../../test/reports/foundation/p09-profile; name = "osbus-p10-recorded-profile"; };
  package = pkgs.runCommand "osbus-p10-activation-services" {
    nativeBuildInputs = [ pkgs.stdenv.cc pkgs.pkg-config ];
    buildInputs = [ pkgs.glib ];
  } ''
    mkdir -p $out/bin $out/share/dbus-1/system-services $out/share/dbus-1/system.d
    cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong \
      ${fixture}/actor.c $(pkg-config --cflags --libs gio-2.0 gio-unix-2.0) \
      -Wl,-z,relro,-z,now -o $out/bin/p10-actor
    for mode in Echo Flood Exit0 Live BadExec; do
      command="$out/bin/p10-actor $mode"
      if [ "$mode" = BadExec ]; then command=/nonexistent/osbus-p10-executable; fi
      sed -e "s|@NAME@|org.foundation.Activation.$mode|g" -e "s|@EXEC@|$command|g" \
        ${fixture}/service.template > $out/share/dbus-1/system-services/org.foundation.Activation.$mode.service
    done
    cp ${fixture}/policy.conf $out/share/dbus-1/system.d/org.foundation.Activation.conf
  '';
in
assert manifestSha256 != null && builtins.hashString "sha256" manifestText == manifestSha256;
assert manifest.schema == 1 && manifest.not_a_release == false;
assert manifest.nixpkgs == pinned;
assert manifest.helper_binding.configured && manifest.helper_binding.path == "/run/wrappers/bin/dbus-daemon-launch-helper";
assert manifest.helper_binding.runtime_overrides == false;
pkgs.testers.nixosTest {
  name = "osbus-p10-installed-helper-abi";
  nodes.machine = { config, pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    services.dbus.enable = true;
    services.dbus.implementation = "dbus";
    security.polkit.enable = true;
    services.dbus.packages = [ package ];
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    # QEMU disables timesyncd; retain its recorded baseline account declarations.
    users.users.systemd-timesync = {
      uid = config.ids.uids.systemd-timesync;
      group = "systemd-timesync";
    };
    users.groups.systemd-timesync.gid = config.ids.gids.systemd-timesync;
    # Preserve the installed unit/alias without the timesync module's startup link.
    systemd.additionalUpstreamSystemUnits = [ "systemd-timesyncd.service" ];
    systemd.services.systemd-timesyncd.aliases = [ "dbus-org.freedesktop.timesync1.service" ];
    users.groups.foundationSvc.gid = 1102;
    users.groups.foundationExtra.gid = 1103;
    users.users.foundationSvc = { isSystemUser = true; uid = 1102; group = "foundationSvc"; extraGroups = [ "foundationExtra" ]; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils ];
    environment.etc."osbus-p10-runtime-roots".source = anchors;
    environment.etc."osbus-p10-guest".text = "isolated-vm\n";
    environment.etc."osbus-p10-profile.json".text = builtins.toJSON {
      config = toString config.environment.etc."dbus-1".source;
      dbus = toString config.services.dbus.dbusPackage;
      helperSource = config.security.wrappers.dbus-daemon-launch-helper.source;
      wrapperScript = config.systemd.services.suid-sgid-wrappers.script;
      users = builtins.mapAttrs (_: u: { inherit (u) uid group isSystemUser; }) config.users.users;
      groups = builtins.mapAttrs (_: g: { inherit (g) gid; }) config.users.groups;
      fixturePackage = toString package;
      directories = map toString config.services.dbus.packages;
      inherit pinned;
      apparmorEnabled = config.security.apparmor.enable;
      networkManagerEnabled = config.networking.networkmanager.enable;
      stateVersion = config.system.stateVersion;
      implementation = config.services.dbus.implementation;
      apparmor = config.services.dbus.apparmor;
      systemdVersion = config.systemd.package.version;
      kernelVersion = config.boot.kernelPackages.kernel.version;
      polkitVersion = config.security.polkit.package.version;
      wrapper = config.security.wrappers.dbus-daemon-launch-helper;
      units = builtins.mapAttrs (_: unit: { inherit (unit) text overrideStrategy; })
        (builtins.intersectAttrs { "dbus.service" = null; "polkit.service" = null; "systemd-logind.service" = null; } config.systemd.units);
    };
    systemd.tmpfiles.rules = [ "d /run/osbus-p10 0755 root root -" "d /run/osbus-p10/witness 0700 foundationSvc foundationSvc -" ];
    system.stateVersion = "25.11";
  };
  testScript = ''
    status = None
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("dbus.service")
        status, output = machine.execute("python3 -B ${fixture}/guest.py ${frozen} ${package} ${recorded} ${manifestSha256} ${transport} ${capture}", timeout=180)
        print(output)
    finally:
        try:
            machine.copy_from_vm("/run/osbus-p10/evidence", "p10-installed-helper-evidence")
        finally:
            machine.shutdown()
    assert status == 0, "installed-helper ABI gate failed/blocked"
  '';
}
