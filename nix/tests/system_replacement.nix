# Source entrypoint for deferred P11/P12 qualification; never run on the host bus.
{ releasePath ? null, manifestSha256 ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if releasePath == null then throw "A freshly captured releasePath is required"
    else builtins.path { path = builtins.toPath releasePath; name = "osbus-system-release"; };
  manifestText = builtins.readFile (frozen + "/release.json");
  manifest = builtins.fromJSON manifestText;
  sourceFiles = directory:
    let entries = builtins.readDir (../../. + "/${directory}");
    in builtins.concatLists (map (name:
      let path = "${directory}/${name}";
      in if entries.${name} == "directory" then sourceFiles path
         else if entries.${name} == "regular" then [ path ]
         else throw "Unsupported source input type: ${path}"
    ) (builtins.attrNames entries));
  requiredSources = [
    "mix.exs" "mix.lock" "devenv.lock" "devenv.nix"
    "apps/gao_bus/Makefile" "apps/gao_bus/mix.exs" "apps/ex_d_bus/mix.exs"
  ] ++ builtins.filter (path: builtins.match ".*\\.ex" path != null)
    (sourceFiles "apps/gao_bus/lib" ++ sourceFiles "apps/ex_d_bus/lib")
    ++ sourceFiles "apps/gao_bus/c_src" ++ sourceFiles "config" ++ sourceFiles "rel/os_bus";
  sourceHashes = builtins.listToAttrs (map (path: {
    name = path;
    value = builtins.hashFile "sha256" (../../. + "/${path}");
  }) requiredSources);
  roots = map builtins.storePath manifest.runtime.store_roots;
  anchors = pkgs.writeText "osbus-system-runtime-roots" (builtins.concatStringsSep "\n" roots);
  workload = builtins.path { path = ../../scripts/foundation/p12_system; name = "osbus-system-workload"; };
  common = { config, ... }: {
    imports = [ ../modules/foundation-system-bus.nix ];
    osBusFoundation.release = frozen + "/release";
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    environment.etc."osbus-system-runtime-roots".source = anchors;
    environment.etc."osbus-system-inputs.json".text = builtins.toJSON {
      schema = 1;
      profile = "foundation-core-canonical-v1";
      inherit pinned manifestSha256;
      release = toString (frozen + "/release");
      releaseManifest = toString (frozen + "/release.json");
      releaseImport = "nix-nar-readonly-v1";
      inherit sourceHashes;
      workload = toString workload;
      workloadSha256 = builtins.hashFile "sha256" ../../scripts/foundation/p12_system/workload.py;
      vm05Sha256 = builtins.hashFile "sha256" ../../scripts/foundation/p12_system/vm05.py;
      moduleSha256 = builtins.hashFile "sha256" ../modules/foundation-system-bus.nix;
      apparmorEnabled = config.security.apparmor.enable;
      networkManagerEnabled = config.networking.networkmanager.enable;
      versions = {
        kernel = config.boot.kernelPackages.kernel.version;
        systemd = config.systemd.package.version;
        referenceDbus = config.services.dbus.dbusPackage.version;
        polkit = config.security.polkit.package.version;
        erts = manifest.metadata.erts;
      };
    };
  };
in
assert manifestSha256 != null && builtins.hashString "sha256" manifestText == manifestSha256;
assert manifest.schema == 1 && manifest.not_a_release == false;
assert manifest.nixpkgs == pinned;
assert builtins.all (path: (manifest.sources.${path} or null) == sourceHashes.${path}) requiredSources;
pkgs.testers.nixosTest {
  name = "osbus-canonical-system-replacement";
  nodes.reference = { ... }: {
    imports = [ common ];
    osBusFoundation.backend = "reference";
  };
  nodes.candidate = { lib, ... }: {
    imports = [ common ];
    osBusFoundation.backend = "candidate";
    # Bootloader state on the disposable disk is the out-of-band restore path.
    virtualisation.useBootLoader = true;
    boot.loader.grub.enable = true;
    boot.loader.grub.device = "/dev/vda";
    specialisation.reference.configuration = {
      osBusFoundation.backend = lib.mkForce "reference";
    };
  };
  testScript = ''
    import json
    import re
    try:
        start_all()
        for node in (reference, candidate):
            node.wait_for_unit("multi-user.target", timeout=90)
            node.wait_for_unit("dbus.service", timeout=90)
        reference.succeed("python3 -B ${workload}/workload.py suite --backend reference --output /run/osbus-system/reference.json", timeout=300)
        candidate.succeed("python3 -B ${workload}/workload.py suite --backend candidate --output /run/osbus-system/candidate.json", timeout=300)
        baseline = json.loads(reference.succeed("cat /run/osbus-system/reference.json"))
        current = json.loads(candidate.succeed("cat /run/osbus-system/candidate.json"))
        assert baseline["configuration"] == current["configuration"], "effective policy/service inputs differ"
        assert baseline["inputs"] == current["inputs"], "qualification inputs differ"
        assert baseline["selected"] == current["selected"]
        for result in (baseline, current):
            assert result["counts"] == {"selected": 11, "executed": 11, "passed": 11, "failed": 0, "unrun": 0}
            assert result["configuration_restored"] == result["configuration"]

        # Exercise coherent release restart; clients reconnect after the epoch.
        old_id = current["bus"]["id"]
        old_pid = current["bus"]["pid"]
        candidate.succeed("kill -KILL " + str(old_pid))
        candidate.wait_until_succeeds("test $(systemctl show dbus.service --property=MainPID --value) != " + str(old_pid) + " && systemctl is-active dbus.service", timeout=90)
        candidate.succeed("python3 -B ${workload}/workload.py suite --backend candidate --output /run/osbus-system/restarted.json", timeout=300)
        restarted = json.loads(candidate.succeed("cat /run/osbus-system/restarted.json"))
        assert restarted["bus"]["id"] != old_id, "bus epoch did not change"
        candidate.succeed("journalctl -b --no-pager -u dbus.service -u systemd-logind.service -u polkit.service > /run/osbus-system/candidate-journal.log")
        candidate.copy_from_vm("/run/osbus-system", "candidate-before-rollback")

        # Serial console command + disk boot selection need no candidate bus.
        saved = candidate.succeed("readlink -f /run/current-system/specialisation/reference").strip()
        assert re.fullmatch(r"/nix/store/[a-z0-9]{32}-[A-Za-z0-9+_.-]+", saved)
        candidate.succeed("kill -STOP " + str(restarted["bus"]["pid"]))
        candidate.succeed(saved + "/bin/switch-to-configuration boot")
        candidate.crash()
        candidate.start()
        candidate.wait_for_unit("multi-user.target", timeout=90)
        candidate.wait_for_unit("dbus.service", timeout=90)
        candidate.succeed("python3 -B ${workload}/workload.py suite --backend reference --output /run/osbus-system/rollback.json", timeout=300)
        restored = json.loads(candidate.succeed("cat /run/osbus-system/rollback.json"))
        assert restored["configuration"] == baseline["configuration"]
        assert restored["inputs"] == baseline["inputs"]
        assert restored["selected"] == baseline["selected"]
        candidate.succeed("test $(readlink -f /run/current-system) = " + saved)
    finally:
        cleanup_errors = []
        for node in (reference, candidate):
            try:
                node.succeed("journalctl -b --no-pager -u dbus.service -u systemd-logind.service -u polkit.service > /run/osbus-system/journal.log")
                node.copy_from_vm("/run/osbus-system", node.name + "-system-evidence")
            except Exception as error:
                cleanup_errors.append(str(error))
            finally:
                try:
                    node.shutdown()
                except Exception as error:
                    cleanup_errors.append(str(error))
        assert not cleanup_errors, cleanup_errors
  '';
}
