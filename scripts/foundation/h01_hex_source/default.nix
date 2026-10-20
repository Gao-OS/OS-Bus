# Separate H01 prerequisite: build official Hex source with the pinned OTP 27 runtime.
{ runtimeManifestPath ? toString (../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1/candidate1/candidate.json) }:
let
  root = ../../..;
  lock = root + "/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec01-complete1/source4/fixture1/inherited/devenv.lock";
  pinned = (builtins.fromJSON (builtins.readFile lock)).nodes.nixpkgs-src.locked;
  nixpkgs = builtins.fetchTree { type = "github"; inherit (pinned) owner repo rev narHash; };
  pkgs = import nixpkgs.outPath { system = "x86_64-linux"; config = {}; overlays = []; };
  runtimeFile = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-h01-hex-runtime.json"; };
  runtime = (builtins.fromJSON (builtins.readFile runtimeFile)).runtime;
  runtimeSha256 = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
  elixir = builtins.storePath runtime.elixir_store;
  otp = builtins.storePath runtime.otp_store;
  version = "2.5.1";
  sourceHash = "sha256-1xiv8FWX8fk9WBoJXCUfgFN9lo7ClMVUBYb1mmr6u9U=";
  source = pkgs.fetchFromGitHub {
    owner = "hexpm";
    repo = "hex";
    rev = "v${version}";
    hash = sourceHash;
  };
  provenance = pkgs.writeText "osbus-h01-hex-build.json" (builtins.toJSON {
    schema_version = 1;
    package = "hex";
    inherit version;
    source = {
      owner = "hexpm";
      repo = "hex";
      rev = "v${version}";
      hash = sourceHash;
      store_path = toString source;
    };
    runtime = {
      elixir_store = toString elixir;
      otp_store = toString otp;
      manifest_sha256 = runtimeSha256;
    };
    build = { command = [ "mix" "compile" ]; mix_env = "prod"; hex_offline = true; };
  });
  hex = pkgs.stdenvNoCC.mkDerivation {
    pname = "osbus-h01-hex-otp27";
    inherit version;
    src = source;
    nativeBuildInputs = [ elixir otp ];
    strictDeps = true;
    dontStrip = true;
    setupHook = pkgs.writeText "hex-setup-hook.sh" ''
      addToSearchPath ERL_LIBS "$1/lib/erlang/lib/"
    '';
    buildPhase = ''
      runHook preBuild
      export PATH=${elixir}/bin:${otp}/bin:$PATH
      osbusHexHome="$TMPDIR/osbus-h01-hex-home"
      osbusHexMixHome="$TMPDIR/osbus-h01-hex-mix-home"
      mkdir -p -m 0700 "$osbusHexHome" "$osbusHexMixHome"
      # The unpacked source directory is private to this build sandbox.
      env HOME="$osbusHexHome" MIX_HOME="$osbusHexMixHome" \
        HEX_HOME=./ HEX_OFFLINE=1 MIX_ENV=prod \
        ERL_FLAGS='+S 2:2 +SDcpu 1 +SDio 1' mix compile
      runHook postBuild
    '';
    installPhase = ''
      runHook preInstall
      mkdir -p "$out/lib/erlang/lib"
      cp -r ./_build/prod/lib/hex "$out/lib/erlang/lib/"
      cp ${provenance} "$out/osbus-build.json"
      runHook postInstall
    '';
  };
in
assert builtins.hashFile "sha256" runtimeFile == runtimeSha256;
assert toString elixir == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert toString otp == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
{ inherit source hex; }
