# Bind reviewed repo/candidate/scope explicitly before build.
{ repoPath ? null, candidatePath ? null, scopePath ? null }:
let
  repo = if repoPath == null then throw "explicit frozen repoPath required" else builtins.toPath repoPath;
  pinned = (builtins.fromJSON (builtins.readFile (repo + "/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "explicit frozen candidate17 required"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-fd03-mixed-candidate17"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  scope = if scopePath == null then throw "explicit reviewed FD03 mixed scope required"
    else builtins.path { path = builtins.toPath scopePath; name = "osbus-fd03-mixed-scope"; };
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-fd03-mixed-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath manifest.runtime.native_store_roots));
  names = [ "actor.py" "actor_test.py" "qualify.py" "oracle_test.py" "workload.json" "test.nix" "README.md" ];
  onlyFiles = allowed: path: type: type == "directory" || builtins.elem (builtins.baseNameOf path) allowed;
  fixtures = builtins.path { path = ./.; name = "osbus-fd03-mixed-fixtures"; filter = onlyFiles names; };
  shared = builtins.path { path = repo + "/scripts/foundation/p08_fd01_singleton_resources";
    name = "osbus-fd03-mixed-readonly-singleton"; filter = onlyFiles names; };
  bundles = builtins.path { path = repo + "/scripts/foundation/p08_fd03_different_bundles";
    name = "osbus-fd03-mixed-readonly-bundles"; filter = onlyFiles names; };
  wire = builtins.path { path = repo + "/apps/gao_bus/test/fixtures";
    name = "osbus-fd03-mixed-wire"; filter = onlyFiles [ "transport_actor.py" "broadcast_delivery_actor.py" ]; };
  helpers = builtins.path { path = repo + "/scripts/foundation/p08_sustained";
    name = "osbus-fd03-mixed-channel"; filter = onlyFiles [ "channel.py" ]; };
  quota = builtins.path { path = repo + "/scripts/foundation/p08_fd_quotas";
    name = "osbus-fd03-mixed-daemon"; filter = onlyFiles [ "daemon.exs" ]; };
  collector = builtins.path { path = repo + "/scripts/foundation/p08_fairness/collector.ex";
    name = "osbus-fd03-mixed-collector"; };
in pkgs.testers.nixosTest {
  name = "osbus-fd03-mixed";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.dbus ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-fd03-mixed-runtime".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    shutdown = {"VMoff": False, "socket_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-fd-quotas")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} timeout --signal=TERM --kill-after=3s 120s python3 -B ${fixtures}/qualify.py --candidate ${frozen} --evidence /run/osbus-fd-quotas --fixtures ${fixtures} --wire-dir ${wire} --helpers ${helpers} --quota-daemon ${quota}/daemon.exs --collector ${collector} --reference-executable ${pkgs.dbus}/bin/dbus-daemon --scope ${scope} --shared ${shared} --bundles ${bundles}"))
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-fd-quotas/bus")[0] == 0
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fd-quotas\"); target=Path(\"/run/osbus-fd03-mixed-export\"); shutil.copytree(source,target,ignore=lambda folder,names:[name for name in names if (Path(folder)/name).is_socket()])'")
            machine.copy_from_vm("/run/osbus-fd03-mixed-export", "fd03-mixed-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "fd03-mixed-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
