# Disposable-VM identity transitions before packaged exec; ordinary guest bus intact.
{ releasePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if releasePath == null then throw "An immutable releasePath is required"
    else builtins.path { path = builtins.toPath releasePath; name = "os-bus-p11-identity-release"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/release.json"));
  roots = map builtins.storePath manifest.runtime.store_roots;
  anchors = pkgs.writeText "os-bus-p11-identity-runtime-roots" (builtins.concatStringsSep "\n" roots);
  fixture = builtins.path { path = ../../scripts/foundation/p11_identity; name = "os-bus-p11-identity-fixture"; };
  lifecycle = builtins.path { path = ../../scripts/foundation/p11_lifecycle; name = "os-bus-p11-identity-shared-lifecycle"; };
  transport = builtins.path { path = ../../scripts/foundation/p08_sustained; name = "os-bus-p11-identity-transport"; };
in
assert manifest.schema == 1 && manifest.fixture == "p11-packaged-lifecycle" && manifest.not_a_release == false;
assert manifest.nixpkgs == pinned;
pkgs.testers.nixosTest {
  name = "os-bus-p11-identity";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    services.dbus.enable = true;
    environment.systemPackages = [ pkgs.python3 pkgs.coreutils pkgs.gnugrep pkgs.gnused pkgs.gawk ];
    environment.etc."osbus-p11-identity-runtime-roots".source = anchors;
    environment.etc."osbus-p11-identity-guest".text = "isolated-vm\n";
    system.stateVersion = "25.11";
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("dbus.service")
    try:
        status, output = machine.execute("python3 ${fixture}/guest.py ${frozen} --lifecycle ${lifecycle} --transport ${transport}", timeout=90)
        print(output)
        machine.succeed("systemctl is-active dbus.service")
    finally:
        try:
            machine.copy_from_vm("/run/osbus-p11-identity/evidence", "p11-identity-evidence")
        finally:
            machine.shutdown()
    assert status == 0, "packaged identity rejection regression failed"
  '';
}
