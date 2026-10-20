# H01 feasibility only: ordinary Hex discovery and bounded offline Mix inspection.
{ snapshotPath, runtimeManifestPath, hexPath }:
let
  root = ../../..;
  lock = root + "/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec01-complete1/source4/fixture1/inherited/devenv.lock";
  pinned = (builtins.fromJSON (builtins.readFile lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  snapshot = builtins.path { path = builtins.toPath snapshotPath; name = "osbus-h01-snapshot"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-h01-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  hex = builtins.storePath hexPath;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "osbus-h01-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp hex] ++ nativeRoots));
  bindings = pkgs.writeText "osbus-h01-bindings.json" (builtins.toJSON {
    snapshot = toString snapshot;
    runtime_manifest = toString runtime;
    elixir = toString elixir;
    otp = toString otp;
    hex = toString hex;
    path = "${elixir}/bin:${otp}/bin:${pkgs.coreutils}/bin";
    project = "/run/osbus-h01/project";
    evidence = "/run/osbus-h01/evidence";
  });
in
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert toString elixir == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert toString otp == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
assert toString hex == "/nix/store/fqlqhhvbzrar4nv359anxvdbszmnzi1j-hex-2.5.1";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-h01-environment";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.groups.foundationB.gid = 1101;
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils ];
    environment.etc."osbus-h01-runtime-roots".source = anchors;
    environment.etc."osbus-h01-guest".text = "isolated-vm\n";
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-h01/evidence"
    shutdown = {"VMoff": False, "evidence_copied": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0700 -o 1101 -g 1101 /run/osbus-h01 " + evidence)
        machine.succeed("cp -R ${snapshot}/project /run/osbus-h01/project && chmod -R u+w /run/osbus-h01/project && chown -R 1101:1101 /run/osbus-h01/project")
        machine.succeed("${pkgs.coreutils}/bin/readlink /proc/1/ns/net > " + evidence + "/init-netns")
        command = "${pkgs.util-linux}/bin/unshare --net -- ${pkgs.util-linux}/bin/runuser -u foundationB -- ${pkgs.coreutils}/bin/env -i PATH=${pkgs.python3}/bin:${pkgs.coreutils}/bin PYTHONDONTWRITEBYTECODE=1 ${pkgs.python3}/bin/python3 -B ${./guest.py} ${bindings} > " + evidence + "/guest.stdout 2> " + evidence + "/guest.stderr"
        status, output = machine.execute(command, timeout=650)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/guest.exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/guest.stderr")
    finally:
        try:
            machine.copy_from_vm(evidence, "h01-environment-evidence")
            shutdown["evidence_copied"] = True
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "h01-environment-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "evidence_copied": True}
  '';
}
