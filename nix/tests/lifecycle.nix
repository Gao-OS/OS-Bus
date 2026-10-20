# Private manager units only: never replace the normal guest D-Bus service/socket.
{ releasePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if releasePath == null then throw "Freeze a fresh production release; releasePath is required"
    else builtins.path { path = builtins.toPath releasePath; name = "os-bus-p11-release"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/release.json"));
  roots = map builtins.storePath manifest.runtime.store_roots;
  anchors = pkgs.writeText "os-bus-p11-runtime-roots" (builtins.concatStringsSep "\n" roots);
  fixtures = builtins.path { path = ../../scripts/foundation/p11_lifecycle; name = "os-bus-p11-fixtures"; };
  transport = builtins.path { path = ../../scripts/foundation/p08_sustained; name = "os-bus-p11-independent-transport"; };
in
assert manifest.schema == 1 && manifest.fixture == "p11-packaged-lifecycle" && manifest.not_a_release == false;
assert manifest.nixpkgs == pinned;
pkgs.testers.nixosTest {
  name = "os-bus-p11-packaged-lifecycle";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    services.dbus.enable = true;
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.systemd pkgs.dbus pkgs.coreutils pkgs.gnugrep pkgs.gnused pkgs.gawk ];
    environment.etc."osbus-p11-runtime-roots".source = anchors;
    environment.etc."osbus-p11-guest".text = "isolated-vm\n";
    system.stateVersion = "25.11";
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("dbus.service")
    machine.succeed("install -d -m 0755 /run/osbus-p11")
    try:
        print(machine.succeed("python3 ${fixtures}/guest.py ${frozen} --transport ${transport}"))
    finally:
        try:
            machine.copy_from_vm("/run/osbus-p11/evidence", "p11-lifecycle-evidence")
        finally:
            machine.shutdown()
  '';
}
