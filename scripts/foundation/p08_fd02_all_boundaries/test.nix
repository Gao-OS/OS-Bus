# FD02 each-relevant-boundary/core: one bounded batch per disposable VM.
{ candidatePath ? null, scopePath ? null, freezePath ? null, first ? 1, count ? 8 }:
let
  pinned = (builtins.fromJSON (builtins.readFile ../../../devenv.lock)).nodes.nixpkgs-src.locked;
  source = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import source.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  frozen = if candidatePath == null then throw "candidatePath must identify the frozen candidate"
    else builtins.path { path = builtins.toPath candidatePath; name = "osbus-fd02-all-boundaries-core-candidate"; };
  manifest = builtins.fromJSON (builtins.readFile (frozen + "/candidate.json"));
  scope = if scopePath == null then throw "scopePath must identify the reviewed FD02 SCOPE.md"
    else builtins.path { path = builtins.toPath scopePath; name = "osbus-fd02-all-boundaries-core-scope.md"; };
  freeze = if freezePath == null then throw "freezePath must identify the parent guest-input freeze"
    else builtins.path { path = builtins.toPath freezePath; name = "osbus-fd02-all-boundaries-core-freeze.json"; };
  validBatch = builtins.isInt first && builtins.isInt count && first >= 1 && count >= 1 && count <= 8;
  elixir = builtins.storePath manifest.runtime.elixir_store;
  otp = builtins.storePath manifest.runtime.otp_store;
  anchors = pkgs.writeText "osbus-fd02-all-boundaries-core-runtime" (builtins.concatStringsSep "\n"
    ([elixir otp] ++ map builtins.storePath manifest.runtime.native_store_roots));
  onlyFiles = names: path: type: type == "directory" || builtins.elem (builtins.baseNameOf path) names;
  fixtures = builtins.path { path = ./.; name = "osbus-fd02-all-boundaries-core-fixtures";
    filter = onlyFiles [ "actor.py" "actor_test.py" "qualify.py" "oracle_test.py" "workload.json" "test.nix" "README.md" "batch.py" "plan.py" ]; };
  reused = builtins.path { path = ../p08_fd01_singleton_resources; name = "osbus-fd02-all-boundaries-readonly-pipe-fixtures";
    filter = onlyFiles [ "actor.py" "actor_test.py" "qualify.py" "oracle_test.py" "workload.json" "test.nix" "README.md" ]; };
  wire = builtins.path { path = ../../../apps/gao_bus/test/fixtures; name = "osbus-fd02-all-boundaries-core-wire";
    filter = onlyFiles [ "transport_actor.py" "broadcast_delivery_actor.py" ]; };
  helpers = builtins.path { path = ../p08_sustained; name = "osbus-fd02-all-boundaries-core-channel"; filter = onlyFiles [ "channel.py" ]; };
  quota = builtins.path { path = ../p08_fd_quotas; name = "osbus-fd02-all-boundaries-core-readonly-daemon"; filter = onlyFiles [ "daemon.exs" ]; };
  collector = builtins.path { path = ../p08_fairness/collector.ex; name = "osbus-fd02-all-boundaries-core-readonly-collector.ex"; };
in assert validBatch; pkgs.testers.nixosTest {
  name = "osbus-fd02-all-boundaries-core-${toString first}-${toString count}";
  nodes.machine = { pkgs, ... }: {
    virtualisation.memorySize = 1536;
    virtualisation.cores = 2;
    users.users.foundationA = { isNormalUser = true; uid = 1100; };
    environment.systemPackages = [ pkgs.python3 pkgs.util-linux pkgs.dbus ];
    environment.etc."osbus-security-guest".text = "isolated-vm\n";
    environment.etc."osbus-fd02-all-boundaries-core-runtime".source = anchors;
    system.stateVersion = "25.11";
  };
  testScript = ''
    try:
        start_all()
        machine.wait_for_unit("multi-user.target")
        print(machine.succeed("PATH=${elixir}/bin:${otp}/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=${helpers} FD02_PIPE_FIXTURES=${reused} ${pkgs.python3}/bin/python3 -B ${fixtures}/batch.py --candidate ${frozen} --fixtures ${fixtures} --wire-dir ${wire} --helpers ${helpers} --quota-daemon ${quota}/daemon.exs --collector ${collector} --reference-executable ${pkgs.dbus}/bin/dbus-daemon --scope ${scope} --reuse-fixtures ${reused} --freeze ${freeze} --first ${toString first} --count ${toString count}", timeout=120))
    finally:
        try:
            machine.succeed("${pkgs.python3}/bin/python3 -B -c 'from pathlib import Path; import shutil; source=Path(\"/run/osbus-fd02-all-boundaries\"); target=Path(\"/run/osbus-fd02-all-boundaries-export\"); shutil.copytree(source, target, ignore=lambda folder,names:[name for name in names if (Path(folder)/name).is_socket()])'")
            machine.copy_from_vm("/run/osbus-fd02-all-boundaries-export", "fd02-all-boundaries-${toString first}-evidence")
        finally:
            machine.shutdown()
  '';
}
