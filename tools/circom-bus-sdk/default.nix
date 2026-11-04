{
  system ? builtins.currentSystem,
}:
let
  root = ../..;
  source = builtins.path {
    path = root;
    name = "circom-owning-bus-flake-source";
    filter =
      path: type:
      builtins.elem path (
        map (relative: toString root + relative) [
          ""
          "/tools"
          "/tools/circom-bus-sdk"
          "/flake.nix"
          "/flake.lock"
          "/tools/circom-bus-sdk/package.nix"
        ]
      );
  };
  owner = builtins.getFlake (builtins.unsafeDiscardStringContext ("path:" + toString source));
in
assert builtins.elem system [
  "x86_64-linux"
  "aarch64-linux"
  "x86_64-darwin"
  "aarch64-darwin"
];
owner.packages.${system}.circom-bus
