# Explicit frozen artifacts only; this is qualification, not a P11 release.
{ candidatePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "Freeze and capture a compiled candidate; candidatePath is required"
    else builtins.path { path = builtins.toPath candidatePath; name = "os-bus-security-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-candidate-runtime" (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  fixtures = builtins.path { path = ../../scripts/foundation/vm_security; name = "os-bus-security-fixtures"; };
in
pkgs.testers.nixosTest {
  name = "os-bus-foundation-security";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.glib pkgs.systemd pkgs.dbus ];
    environment.etc."osbus-candidate-runtime".source = anchors;
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    system.stateVersion = "25.11";
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0755 /run/osbus-security")
    try:
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH python3 ${fixtures}/run.py ${frozen} ${fixtures} /run/osbus-security"))
    finally:
        try:
            # Native socket inodes are not portable evidence files.
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-security\"); target=Path(\"/run/osbus-security-export\"); target.mkdir(); [shutil.copyfile(path, target/path.name) for path in source.iterdir() if path.is_file()]'")
            machine.copy_from_vm("/run/osbus-security-export", "security-evidence")
        finally:
            machine.shutdown()
  '';
}
