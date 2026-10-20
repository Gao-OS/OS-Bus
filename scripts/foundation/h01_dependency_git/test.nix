# H01 feasibility only: ordinary Hex discovery and bounded offline Mix inspection.
{ snapshotPath, runtimeManifestPath, hexPath }:
let
  root = ../../..;
  lock = root + "/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec01-complete1/source4/fixture1/inherited/devenv.lock";
  pinned = (builtins.fromJSON (builtins.readFile lock)).nodes.nixpkgs-src.locked;
  source = builtins.storePath "/nix/store/p4l9q189cgldga9f1051fhfllfzmk4c5-source";
  pkgs = import source { system = "x86_64-linux"; config = {}; overlays = []; };
  snapshot = builtins.path { path = builtins.toPath snapshotPath; name = "osbus-h01-snapshot"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-h01-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile runtime);
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  hex = builtins.storePath hexPath;
  hexProvenance = builtins.fromJSON (builtins.unsafeDiscardStringContext (builtins.readFile (hex + "/osbus-build.json")));
  git = pkgs.gitMinimal;
  nativeRoots = map builtins.storePath manifest.runtime.native_store_roots;
  anchors = pkgs.writeText "osbus-h01-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp hex git] ++ nativeRoots));
  bindings = pkgs.writeText "osbus-h01-bindings.json" (builtins.toJSON {
    snapshot = toString snapshot;
    runtime_manifest = toString runtime;
    elixir = toString elixir;
    otp = toString otp;
    hex = toString hex;
    path = "${elixir}/bin:${otp}/bin:${git}/bin:${pkgs.coreutils}/bin";
    project = "/run/osbus-h01/project";
    evidence = "/run/osbus-h01/evidence";
  });
in
assert builtins.hashFile "sha256" runtime == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
assert toString elixir == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert toString otp == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
assert builtins.hashFile "sha256" lock == "643e47587097d532fa630260a8b30d727800c6344ff96d6c68a421fc7c3bbb55";
assert pinned.rev == "207d15f1a6603226e1e223dc79ac29c7846da32e";
assert pinned.narHash == "sha256-H3AfG4ObMDTkTJYkd8cz1/RbY9LatN5Mk4UF48VuSXc=";
assert toString git == "/nix/store/a8mapvrhrzw6ahgb7iv72h3jbm5ghwdy-git-minimal-2.52.0";
assert hexProvenance.package == "hex" && hexProvenance.version == "2.5.1";
assert hexProvenance.source.store_path == "/nix/store/4cxbmdd32vsqcw8gd9i0z0h0hxzijiya-source";
assert hexProvenance.source.hash == "sha256-1xiv8FWX8fk9WBoJXCUfgFN9lo7ClMVUBYb1mmr6u9U=";
assert hexProvenance.runtime.elixir_store == toString elixir;
assert hexProvenance.runtime.otp_store == toString otp;
assert hexProvenance.runtime.manifest_sha256 == "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
pkgs.testers.nixosTest {
  name = "os-bus-foundation-h01-dependency-cached-git";
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
