# Exact PRO01 Peer regressions, using frozen product and separate test-only Jason.
{ artifactPath, runtimeManifestPath, testDependencyPath }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  artifact = builtins.path { path = builtins.toPath artifactPath; name = "os-bus-peer-artifact"; };
  runtime = builtins.path { path = builtins.toPath runtimeManifestPath; name = "os-bus-peer-runtime.json"; };
  manifest = builtins.fromJSON (builtins.readFile (artifact + "/artifact.json"));
  runtimeManifest = builtins.fromJSON (builtins.readFile runtime);
  runtimeSha256 = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
  elixir = builtins.storePath runtimeManifest.runtime.elixir_store;
  otp = builtins.storePath runtimeManifest.runtime.otp_store;
  nativeRoots = map builtins.storePath runtimeManifest.runtime.native_store_roots;
  anchors = pkgs.writeText "os-bus-peer-runtime-roots"
    (builtins.concatStringsSep "\n" ([elixir otp] ++ nativeRoots));
  tests = map (name: "apps/gao_bus/test/peer_${name}_test.exs") [
    "coalesced_read" "auth_begin_split_boundaries" "hello_split_boundaries"
    "get_id_split_boundaries" "fd_split_boundaries" "auth_read_boundaries"
  ];
  helpers = map (name: "apps/gao_bus/test/fixtures/${name}.py") [
    "peer_coalesced_read_actor" "peer_auth_begin_split_boundaries_actor"
    "peer_hello_split_boundaries_actor" "peer_get_id_split_boundaries_actor"
    "peer_fd_split_boundaries_actor" "peer_auth_read_boundaries_actor" "transport_actor"
  ];
  root = toString ../..;
  paths = tests ++ helpers;
  fullPaths = map (name: root + "/" + name) paths;
  prefix = start: value: builtins.substring 0 (builtins.stringLength start) value == start;
  fixtures = builtins.path {
    path = ../..;
    name = "os-bus-peer-fixtures";
    filter = path: type: builtins.elem path fullPaths ||
      (type == "directory" && builtins.any (name: prefix (path + "/") name) fullPaths);
  };
  dependency = builtins.path {
    path = builtins.toPath (testDependencyPath + "/ebin");
    name = "os-bus-peer-test-jason-ebin";
  };
  dependencyEntries = builtins.readDir dependency;
  hashFiles = base: names: builtins.listToAttrs (map (name: {
    inherit name;
    value = builtins.hashFile "sha256" (base + "/${name}");
  }) names);
  runner = builtins.path {
    path = ../../scripts/foundation/peer_regression_runner.exs;
    name = "os-bus-peer-regression-runner.exs";
  };
  bindings = pkgs.writeText "os-bus-peer-bindings.json" (builtins.toJSON {
    selection = "pro01";
    expected_tests = 12;
    artifact_store = toString artifact;
    artifact_sha256 = builtins.hashFile "sha256" (artifact + "/artifact.json");
    runtime_sha256 = runtimeSha256;
    runtime_store = toString runtime;
    nixpkgs_lock_sha256 = builtins.hashFile "sha256" ../../devenv.lock;
    fixtures_store = toString fixtures;
    fixture_hashes = hashFiles fixtures paths;
    tests = tests;
    dependency_store = toString dependency;
    dependency_hashes = hashFiles dependency (builtins.attrNames dependencyEntries);
    runner_sha256 = builtins.hashFile "sha256" runner;
    not_a_release = true;
  });
in
assert builtins.hashFile "sha256" runtime == runtimeSha256;
assert manifest.not_a_release && runtimeManifest.not_a_release;
assert manifest.origin_pin.sha256 == runtimeSha256;
assert builtins.length (builtins.attrNames manifest.files) == 80;
assert builtins.length (builtins.attrNames manifest.sources) == 71;
assert runtimeManifest.runtime.elixir_store == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert runtimeManifest.runtime.otp_store == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
assert builtins.hasAttr "Elixir.Jason.beam" dependencyEntries && builtins.hasAttr "jason.app" dependencyEntries;
assert builtins.all (kind: kind == "regular") (builtins.attrValues dependencyEntries);
pkgs.testers.nixosTest {
  name = "os-bus-foundation-peer-pro01";
  globalTimeout = 900;
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.groups.foundationB.gid = 1101;
    users.users.foundationB = { isNormalUser = true; uid = 1101; group = "foundationB"; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.coreutils ];
    environment.etc."osbus-peer-runtime-roots".source = anchors;
    environment.etc."osbus-peer-regression-guest" = { text = "isolated-vm\n"; mode = "0444"; };
    system.stateVersion = "25.11";
  };
  testScript = ''
    import json
    import os
    from pathlib import Path
    evidence = "/run/osbus-peer-regression"
    shutdown = {"VMoff": False, "private_directory_empty": False}
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 -o 1101 -g 1101 " + evidence)
        machine.succeed("install -d -m 0700 -o 1101 -g 1101 " + evidence + "/private")
        machine.succeed("cp ${bindings} " + evidence + "/bindings.json")
        command = "timeout --signal=TERM --kill-after=3s 240s runuser -u foundationB -- env PATH=${elixir}/bin:${otp}/bin:$PATH TMPDIR=" + evidence + "/private PYTHONDONTWRITEBYTECODE=1 DBUS_SYSTEM_BUS_ADDRESS=unix:path=" + evidence + "/private/unused-system DBUS_SESSION_BUS_ADDRESS=unix:path=" + evidence + "/private/unused-session ${elixir}/bin/elixir --erl '+S 2:2' -pa ${artifact}/lib/ex_d_bus/ebin -pa ${artifact}/lib/gao_bus/ebin -pa ${artifact}/lib/phoenix_pubsub/ebin -pa ${dependency} ${runner} ${bindings} " + evidence + " > " + evidence + "/output.log 2>&1"
        status, output = machine.execute(command, timeout=250)
        machine.succeed("printf '%s\\n' " + str(status) + " > " + evidence + "/exit-status")
        assert status == 0, machine.succeed("cat " + evidence + "/output.log")
    finally:
        try:
            shutdown["private_directory_empty"] = machine.execute("test -d " + evidence + "/private && test -z \"$(find " + evidence + "/private -mindepth 1 -print -quit)\"")[0] == 0
            machine.copy_from_vm(evidence, "peer-regression-evidence")
        finally:
            machine.shutdown()
            machine.wait_for_shutdown()
            shutdown["VMoff"] = True
            (Path(os.environ["out"]) / "peer-regression-vmoff.json").write_text(json.dumps(shutdown, sort_keys=True) + "\n")
    assert shutdown == {"VMoff": True, "private_directory_empty": True}
  '';
}
