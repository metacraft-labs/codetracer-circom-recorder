{
  pkgs,
  craneLib,
  rustPlatform,
  source,
}:
let
  # Same locked crane/fenix builder and build-only package contract as owning
  # nix-blockchain-development's primary Circom package; no fork-suite claim.
  common = {
    pname = "circom-bus-compiler";
    version = "2.2.3";
    src = source;
    nativeBuildInputs = [ rustPlatform.bindgenHook ];
  };
  compiler = craneLib.buildPackage (
    common
    // {
      cargoArtifacts = craneLib.buildDepsOnly common;
      doCheck = false;
    }
  );
in
pkgs.writeShellScriptBin "circom-bus" ''
  exec ${compiler}/bin/circom "$@"
''
