# Immutable headless package on private units/sockets; the guest normal bus remains.
{ packagedPath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if packagedPath == null then throw "packagedPath must identify a pre-VM schema2 capture"
    else builtins.path { path = builtins.toPath packagedPath; name = "osbus-p08-packaged-capture"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/packaged.json"));
  package = manifest.package.manifest;
  roots = map builtins.storePath package.runtime.store_roots;
  anchors = pkgs.writeText "osbus-p08-packaged-runtime-roots" (builtins.concatStringsSep "\n" roots);
  fixtures = builtins.path {
    path = ./.; name = "osbus-p08-packaged-fixtures";
    filter = path: type: builtins.baseNameOf path != "__pycache__";
  };
  bound = if manifest.mode == "soak" then 1000 else 240;
in
assert manifest.schema == 2 && manifest.fixture == "packaged-local-console-soak";
assert package.schema == 1 && package.not_a_release == false && package.nixpkgs == pinned;
assert (manifest.mode == "soak" && manifest.duration_seconds == 600 && manifest.qualifying == true)
  || (manifest.mode == "preflight" && manifest.duration_seconds == 10 && manifest.qualifying == false);
pkgs.testers.nixosTest {
  name = "osbus-p08-packaged-" + manifest.mode;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.diskSize = 4096;
    virtualisation.cores = 2;
    services.dbus.enable = true;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    environment.systemPackages = [
      pkgs.python3 pkgs.util-linux pkgs.systemd pkgs.dbus pkgs.coreutils
      pkgs.gnugrep pkgs.gnused pkgs.gawk pkgs.iproute2
    ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-p08-runtime-roots".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.wait_for_unit("dbus.service")
        machine.succeed("install -d -m 0755 /run/osbus-p08")
        machine.succeed("install -d -m 0700 /var/lib/osbus-p08-evidence")
        machine.succeed("ln -s /var/lib/osbus-p08-evidence /run/osbus-p08/evidence")
        print(machine.succeed("PYTHONDONTWRITEBYTECODE=1 python3 ${fixtures}/packaged_qualify.py ${frozen} ${frozen}", timeout=${toString bound}))
    finally:
        try:
            # Preserve the entire disk-backed bundle even after a controller fail.
            machine.copy_from_vm("/var/lib/osbus-p08-evidence", "p08-packaged-evidence")
            print(machine.succeed("systemctl show osbus-p08-plain.service osbus-p08-console.service --property=MainPID,ActiveState,SubState,Result,ControlGroup || true"))
        finally:
            machine.shutdown()
  '';
}
