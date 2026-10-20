# Two singleton bundles; development candidate only, not coalesced-read evidence.
{ candidatePath ? null, scopePath ? null }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "candidatePath must identify frozen candidate16"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-fd03-different-bundles-core-candidate16"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  scope = if scopePath == null then throw "scopePath must identify the reviewed FD03 SCOPE.md"
    else builtins.path { path = builtins.toPath scopePath; name = "osbus-fd03-different-bundles-core-scope.md"; };
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-fd03-different-bundles-core-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath manifest.runtime.native_store_roots));
  onlyFiles = names: path: type:
    type == "directory" || builtins.elem (builtins.baseNameOf path) names;
  names = [ "actor.py" "actor_test.py" "qualify.py" "oracle_test.py" "workload.json" "test.nix" "README.md" ];
  fixtures = builtins.path { path = ./.; name = "osbus-fd03-different-bundles-core-fixtures"; filter = onlyFiles names; };
  shared = builtins.path { path = ../p08_fd01_singleton_resources; name = "osbus-fd03-readonly-singleton-pipe"; filter = onlyFiles names; };
  wire = builtins.path { path = ../../../apps/gao_bus/test/fixtures; name = "osbus-fd03-different-bundles-core-wire";
    filter = onlyFiles [ "transport_actor.py" "broadcast_delivery_actor.py" ]; };
  helpers = builtins.path { path = ../p08_sustained; name = "osbus-fd03-different-bundles-core-channel"; filter = onlyFiles [ "channel.py" ]; };
  quota = builtins.path { path = ../p08_fd_quotas; name = "osbus-fd03-different-bundles-core-readonly-daemon"; filter = onlyFiles [ "daemon.exs" ]; };
  collector = builtins.path { path = ../p08_fairness/collector.ex; name = "osbus-fd03-different-bundles-core-readonly-collector.ex"; };
in pkgs.testers.nixosTest {
  name = "osbus-fd03-different-bundles-core";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.dbus ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-fd03-different-bundles-core-runtime".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -m 0755 /run/osbus-fd-quotas")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} python3 -B ${fixtures}/qualify.py --candidate ${frozen} --evidence /run/osbus-fd-quotas --fixtures ${fixtures} --wire-dir ${wire} --helpers ${helpers} --quota-daemon ${quota}/daemon.exs --collector ${collector} --reference-executable ${pkgs.dbus}/bin/dbus-daemon --scope ${scope} --shared ${shared}", timeout=120))
    finally:
        try:
            machine.succeed("python3 -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fd-quotas\"); target=Path(\"/run/osbus-fd03-different-bundles-export\"); shutil.copytree(source, target, ignore=lambda folder,names:[name for name in names if (Path(folder)/name).is_socket()])'")
            machine.copy_from_vm("/run/osbus-fd03-different-bundles-export", "fd03-different-bundles-evidence")
        finally:
            machine.shutdown()
  '';
}
