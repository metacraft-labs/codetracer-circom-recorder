## Owning compiler provisioning: unchanged primary 2.1.5 and adapted bus 2.2.3.
import blake3
import repro_project_dsl

const sourceBytes = staticRead("tools/circom-bus-sdk/default.nix") & "\0" &
  staticRead("tools/circom-bus-sdk/package.nix") & "\0" &
  staticRead("flake.nix") & "\0" & staticRead("flake.lock")
let sourceIdentity = blake3.toHex(blake3.digest(sourceBytes))

package `circom-bus`:
  provisioning:
    nixPackage "circom-bus", executablePath = "bin/circom-bus",
      expressionFile = "tools/circom-bus-sdk/default.nix",
      lockIdentity = "owning-circom-bus-flake:" & sourceIdentity

const primarySourceBytes = staticRead("tools/circom-primary-sdk/default.nix") & "\0" &
  staticRead("tools/circom-bus-sdk/package.nix") & "\0" &
  staticRead("flake.nix") & "\0" & staticRead("flake.lock")
let primarySourceIdentity = blake3.toHex(blake3.digest(primarySourceBytes))

package circom:
  provisioning:
    nixPackage "circom", executablePath = "bin/circom",
      expressionFile = "tools/circom-primary-sdk/default.nix",
      lockIdentity = "owning-primary-circom-flake:" & primarySourceIdentity
