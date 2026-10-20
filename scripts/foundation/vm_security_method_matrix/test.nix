# Explicit frozen artifacts only; this adds scoped SEC-14 evidence, not a release.
{ candidatePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "Freeze and capture a compiled candidate; candidatePath is required"
    else builtins.path { path = builtins.toPath candidatePath; name = "os-bus-method-matrix-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-candidate-runtime" (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  sharedFixtures = builtins.path { path = ../vm_security; name = "os-bus-security-shared-fixtures"; };
  matrixFixtures = builtins.path { path = ./.; name = "os-bus-method-matrix-fixtures"; };
  # Real copies retain the sibling layout required by Path(__file__).resolve().
  fixtures = pkgs.runCommand "os-bus-method-matrix-fixture-tree" {} ''
    mkdir -p "$out/vm_security" "$out/vm_security_method_matrix"
    cp -R ${sharedFixtures}/. "$out/vm_security/"
    cp -R ${matrixFixtures}/. "$out/vm_security_method_matrix/"
  '';
in
pkgs.testers.nixosTest {
  name = "os-bus-foundation-method-matrix";
  globalTimeout = 900;
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
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-security /run/osbus-security/method-matrix")
        print(machine.succeed("timeout --signal=KILL 120s env PYTHONDONTWRITEBYTECODE=1 PATH=${elixir}/bin:${otp}/bin:$PATH python3 ${fixtures}/vm_security_method_matrix/run.py ${frozen} /run/osbus-security/method-matrix", timeout=120))
    finally:
        try:
            # Export regular files only; the native socket is not portable evidence.
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-security/method-matrix\"); target=Path(\"/run/osbus-method-matrix-export\"); target.mkdir(); [shutil.copyfile(path, target/path.name) for path in source.iterdir() if path.is_file() and not path.is_symlink()]'")
            machine.copy_from_vm("/run/osbus-method-matrix-export", "method-matrix-evidence")
        finally:
            machine.shutdown()
  '';
}
