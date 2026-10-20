# Bind the new reviewed scope/candidate explicitly; build driver-only first.
{ repoPath ? null, candidatePath ? null, scopePath ? null, candidateManifestSha256 ? null, candidateSourceSha256 ? null }:
let
  repo = if repoPath == null then throw "explicit repoPath required" else builtins.toPath repoPath;
  pinned = (builtins.fromJSON (builtins.readFile (repo + "/devenv.lock"))).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "explicit corrected candidate required"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-fd07-missing-corrected-candidate"; };
  manifestBytes = builtins.readFile (frozen + "/candidate.json");
  manifest = builtins.fromJSON manifestBytes;
  boundManifest = if candidateManifestSha256 == null || candidateSourceSha256 == null then
    throw "explicit root-supplied candidate manifest/source SHA256 required"
    else if builtins.match "[0-9a-f]{64}" candidateManifestSha256 == null || builtins.match "[0-9a-f]{64}" candidateSourceSha256 == null then
      throw "exact lowercase SHA256 required"
    else if candidateManifestSha256 == "a27888106012b209b8941a4c7e5b9611764c7ceaa3ff2e27ebe9c753783a6c77" || candidateSourceSha256 == "f5dfe03ced34c9b24e69b780588156330a74d2ee025a07dcf2dd0e5d395eab92" then
      throw "candidate17 cannot qualify corrected fixture"
    else if builtins.hashString "sha256" manifestBytes != candidateManifestSha256 || manifest.source_sha256 != candidateSourceSha256 then
      throw "candidate manifest/source binding mismatch"
    else manifest;
  scope = if scopePath == null then throw "explicit reviewed FD07 scope required"
    else builtins.path { path = builtins.toPath scopePath; name = "osbus-fd07-missing-scope"; };
  elixir = builtins.storePath boundManifest.runtime.elixir_store;
  otp = builtins.storePath boundManifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-fd07-missing-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath boundManifest.runtime.native_store_roots));
  names = [ "actor.py" "actor_test.py" "qualify.py" "oracle_test.py" "workload.json" "test.nix" "README.md" ];
  onlyFiles = allowed: path: type: type == "directory" || builtins.elem (builtins.baseNameOf path) allowed;
  fixture = name: path: builtins.path { inherit path; name = "osbus-fd07-" + name; filter = onlyFiles names; };
  fixtures = fixture "missing-corrected-fixtures" ./.;
  fd05 = fixture "readonly-fd05" (repo + "/scripts/foundation/p08_fd_nonnegotiation");
  shared = fixture "readonly-singleton" (repo + "/scripts/foundation/p08_fd01_singleton_resources");
  mixed = fixture "readonly-mixed" (repo + "/scripts/foundation/p08_fd03_mixed_bundles");
  bundles = fixture "readonly-bundles" (repo + "/scripts/foundation/p08_fd03_different_bundles");
  wire = builtins.path { path = repo + "/apps/gao_bus/test/fixtures"; name = "osbus-fd07-wire";
    filter = onlyFiles [ "transport_actor.py" "broadcast_delivery_actor.py" ]; };
  helpers = builtins.path { path = repo + "/scripts/foundation/p08_sustained"; name = "osbus-fd07-channel";
    filter = onlyFiles [ "channel.py" ]; };
  quota = builtins.path { path = repo + "/scripts/foundation/p08_fd_quotas"; name = "osbus-fd07-daemon";
    filter = onlyFiles [ "daemon.exs" ]; };
  collector = builtins.path { path = repo + "/scripts/foundation/p08_fairness/collector.ex"; name = "osbus-fd07-collector"; };
in pkgs.testers.nixosTest {
  name = "osbus-fd07-missing-corrected";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.dbus ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-fd07-missing-runtime".source = anchors;
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
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} timeout --signal=TERM --kill-after=3s 120s python3 -B ${fixtures}/qualify.py --candidate ${frozen} --candidate-manifest-sha256 ${candidateManifestSha256} --candidate-source-sha256 ${candidateSourceSha256} --evidence /run/osbus-fd-quotas --fixtures ${fixtures} --wire-dir ${wire} --helpers ${helpers} --quota-daemon ${quota}/daemon.exs --collector ${collector} --reference-executable ${pkgs.dbus}/bin/dbus-daemon --scope ${scope} --fd05 ${fd05} --shared ${shared} --mixed ${mixed} --bundles ${bundles}"))
    finally:
        try:
            shutdown["socket_removed"] = machine.execute("test ! -e /run/osbus-fd-quotas/bus")[0] == 0
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fd-quotas\"); target=Path(\"/run/osbus-fd07-missing-corrected-export\"); shutil.copytree(source,target,ignore=lambda folder,names:[name for name in names if (Path(folder)/name).is_socket()])'")
            machine.copy_from_vm("/run/osbus-fd07-missing-corrected-export", "fd07-missing-corrected-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "fd07-missing-corrected-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "socket_removed": True}
  '';
}
