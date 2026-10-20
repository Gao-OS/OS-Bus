# Separate H01 prerequisite using the already cached pinned fetcher toolchain.
{ runtimeManifestPath ? toString (../../../test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec16-complete1/candidate1/candidate.json) }:
let
  root = ../../..;
  lock = root + "/test/reports/foundation/continuation-20261011-full-goal/environment/m1-sec01-complete1/source4/fixture1/inherited/devenv.lock";
  pinned = (builtins.fromJSON (builtins.readFile lock)).nodes.nixpkgs-src.locked;
  lockSha256 = "643e47587097d532fa630260a8b30d727800c6344ff96d6c68a421fc7c3bbb55";
  # Captured with local nix path-info; the phase runner rechecks this registration.
  identityFile = root + "/test/reports/foundation/resume-20261019/h01-cached-source-build1/nixpkgs-identity.json";
  identity = builtins.fromJSON (builtins.readFile identityFile);
  nixpkgs = builtins.storePath identity.store_path;
  pkgs = import nixpkgs { system = "x86_64-linux"; config = {}; overlays = []; };
  runtimeFile = builtins.path { path = builtins.toPath runtimeManifestPath; name = "osbus-h01-hex-runtime.json"; };
  runtime = (builtins.fromJSON (builtins.readFile runtimeFile)).runtime;
  runtimeSha256 = "6077a50d35887b5ee287034d89aad77ecffefb027dd3fcb0e6ece23ed1872de5";
  elixir = builtins.storePath runtime.elixir_store;
  otp = builtins.storePath runtime.otp_store;
  version = "2.5.1";
  sourceHash = "sha256-1xiv8FWX8fk9WBoJXCUfgFN9lo7ClMVUBYb1mmr6u9U=";
  cachedFetchzip = pkgs.fetchzip.override {
    fetchurl = pkgs.fetchurl.override { curl = pkgs.curl.bin; };
    withUnzip = false;
  };
  source = cachedFetchzip {
    url = "https://github.com/hexpm/hex/archive/v${version}.tar.gz";
    name = "source";
    hash = sourceHash;
    stripRoot = true;
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
    nixpkgs = { inherit (pinned) rev narHash; store_path = toString nixpkgs; };
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
assert builtins.hashFile "sha256" lock == lockSha256;
assert pinned.owner == "NixOS" && pinned.repo == "nixpkgs";
assert pinned.rev == "207d15f1a6603226e1e223dc79ac29c7846da32e";
assert pinned.narHash == "sha256-H3AfG4ObMDTkTJYkd8cz1/RbY9LatN5Mk4UF48VuSXc=";
assert builtins.hashFile "sha256" identityFile == "cae16a7c64d66725f3946cfa7d3d1929a01eadc568ca87da4198e6e36b289b44";
assert identity.store_path == "/nix/store/p4l9q189cgldga9f1051fhfllfzmk4c5-source";
assert identity.nar_hash == pinned.narHash;
assert identity.content_address == "fixed:r:sha256:0xs9dv2y61c5jd6dxd6ss9impx6p6g3pf94n9kj38c4vhcdiyw0z";
assert toString pkgs.stdenvNoCC == "/nix/store/lajqvvaxn87hc409wkxlzfq89ycf0pw4-stdenv-linux";
assert toString pkgs.curl.bin == "/nix/store/jqfr3p49g3lch84y45jfzw9fshlv8jyp-curl-8.17.0-bin";
assert toString source == "/nix/store/4cxbmdd32vsqcw8gd9i0z0h0hxzijiya-source";
assert builtins.hashFile "sha256" runtimeFile == runtimeSha256;
assert toString elixir == "/nix/store/qain5kcksm31fhhyxlmxa7db5fyffchj-elixir-1.17.3";
assert toString otp == "/nix/store/4b6y6sl4i7b93b8ffhz5yh99hb7rp69r-erlang-27.3.4.6";
{ inherit source hex; }
