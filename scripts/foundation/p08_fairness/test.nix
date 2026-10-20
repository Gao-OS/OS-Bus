# Explicit immutable development artifacts. Packaged RES-06 remains separate.
{ candidatePath ? null, diagnosticNoTrace ? false, timingObserver ? false }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "candidatePath must identify a frozen capture"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-p08-fairness-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-p08-fairness-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath manifest.runtime.native_store_roots));
  fixtures = builtins.path { path = ./.; name = "osbus-p08-fairness-fixtures"; };
  diagnosticArg = if timingObserver then " --diagnostic-timing" else if diagnosticNoTrace then " --diagnostic-no-trace" else "";
  helpers = builtins.path { path = ../p08_sustained; name = "osbus-p08-readonly-helpers"; };
in pkgs.testers.nixosTest {
  name = if timingObserver then "osbus-p08-fairness-diagnostic-timing" else if diagnosticNoTrace then "osbus-p08-fairness-diagnostic-no-trace" else "osbus-p08-fairness-development-fairness";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-p08-fairness-runtime".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("install -d -m 0755 /run/osbus-fairness")
    try:
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} python3 ${fixtures}/qualify.py ${frozen} /run/osbus-fairness${diagnosticArg}", timeout=360))
    finally:
        try:
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fairness\"); target=Path(\"/run/osbus-fairness-export\"); target.mkdir(); [shutil.copyfile(p, target/p.name) for p in source.iterdir() if p.is_file()]'")
            machine.copy_from_vm("/run/osbus-fairness-export", "p08-fairness-evidence")
        finally:
            machine.shutdown()
  '';
}
