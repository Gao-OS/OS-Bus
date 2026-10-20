# One normal valid incomplete-frame ownership cleanup; unchanged quota policy and runtime harness.
let
  candidatePath = "/data/development/Gao-OS/OS-Bus/.trees/os-bus-foundation/test/reports/foundation/resume-20261019/sec17-xml-preparation1/normalized/candidate";
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "candidatePath must identify the frozen current candidate"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-p08-fd-fanout-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-p08-fd-fanout-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath manifest.runtime.native_store_roots));
  fixtureSources = ./.;
  fixtures = pkgs.runCommand "osbus-current-frame-cleanup-correction2-fixtures" {
    oraclePython = "${pkgs.python3}/bin/python3";
    oracleHelpers = toString helpers;
  } ''
    mkdir -p "$out"
    cp ${fixtureSources}/actor.py ${fixtureSources}/contract.py ${fixtureSources}/qualify.py ${fixtureSources}/oracle_test.py ${fixtureSources}/daemon.exs "$out/"
    cp ${./workload.json} "$out/workload.json"
  '';
  helpers = builtins.path { path = ../p08_sustained; name = "osbus-p08-fd-fanout-readonly-helpers"; };
  quota = builtins.path { path = ../p08_fd_quotas; name = "osbus-p08-fd-fanout-unchanged-quota"; };
  fairness = builtins.path { path = ../p08_fairness; name = "osbus-p08-fd-fanout-readonly-collector"; };
in
assert builtins.hashFile "sha256" (frozen + "/candidate.json") == "fdcb882fe302d12a42ba079db1a714b4c62b29eb482a60d2ebb18333d1cc0d82";
assert manifest.source_sha256 == "f1f945acad6e704cbfae7545f01457e18ac503d972e39582e475f4352313544c";
pkgs.testers.nixosTest {
  name = "osbus-sec17-current-frame-cleanup-correction2";
  globalTimeout = 900;
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
    import json
    import os
    from pathlib import Path
    shutdown = {"VMoff": False, "socket_removed": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-fd-quotas")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} python3 -B ${fixtures}/qualify.py ${frozen} /run/osbus-fd-quotas ${helpers} ${quota} ${fairness}/collector.ex", timeout=120))
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-fd-quotas/bus")[0] == 0
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fd-quotas\"); target=Path(\"/run/osbus-sec17-frame-cleanup-export\"); target.mkdir(); [shutil.copyfile(p, target/p.name) for p in source.iterdir() if p.is_file()]'")
            machine.copy_from_vm("/run/osbus-sec17-frame-cleanup-export", "sec17-frame-cleanup-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "frame-cleanup-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
