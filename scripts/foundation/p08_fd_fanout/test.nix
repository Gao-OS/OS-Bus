# Selected development FD09 only; activation and release qualification are separate.
{ candidatePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "candidatePath must identify frozen candidate07"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-p08-fd-fanout-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-p08-fd-fanout-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath manifest.runtime.native_store_roots));
  fixtures = builtins.path { path = ./.; name = "osbus-p08-fd-fanout-fixtures"; };
  helpers = builtins.path { path = ../p08_sustained; name = "osbus-p08-fd-fanout-readonly-helpers"; };
  quota = builtins.path { path = ../p08_fd_quotas; name = "osbus-p08-fd-fanout-unchanged-quota"; };
  fairness = builtins.path { path = ../p08_fairness; name = "osbus-p08-fd-fanout-readonly-collector"; };
in pkgs.testers.nixosTest {
  name = "osbus-p08-development-independent-memfd-fanout";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    users.users.foundationB = { isNormalUser = true; uid = 1101; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-p08-fd-fanout-runtime".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-fd-quotas")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} python3 -B ${fixtures}/qualify.py ${frozen} /run/osbus-fd-quotas ${helpers} ${quota} ${fairness}/collector.ex", timeout=120))
    finally:
        try:
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fd-quotas\"); target=Path(\"/run/osbus-fd-fanout-export\"); target.mkdir(); [shutil.copyfile(p, target/p.name) for p in source.iterdir() if p.is_file()]'")
            machine.copy_from_vm("/run/osbus-fd-fanout-export", "p08-fd-fanout-evidence")
        finally:
            machine.shutdown()
  '';
}
