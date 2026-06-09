## Reprobuild dev env for codetracer-circom-recorder.
##
## Mirrors the dev shell declared in ``flake.nix`` (Linux/macOS) and
## the Windows DIY env declared in ``env.ps1``. ``repro exec just
## <target>`` then reproduces CI on any supported host -- the same
## CI workflow re-plays this env via the shared ``setup-dev-env``
## composite action defined in
## ``metacraft-labs/metacraft-github-actions``. See
## ``metacraft-dev-guidelines/policies/ci-shared-dev-env.md`` for
## the rollout shape.
##
## Status: Phase 1 (additive). The Nix flake and ``env.ps1`` remain
## the supported dev-shell entry points; reprobuild joins them as a
## third env-flavor candidate on the CI matrix once this file is
## wired into ``.github/workflows/ci.yml``.
##
## Circom-specific note: the test corpus compiles ``.circom``
## sources through the upstream ``circom`` binary at test time, so
## the compiler is declared in ``uses:``. ``circom`` is pinned to
## 2.1.5 -- matching ``mcl-blockchain``'s pin and the recorder's
## default. A subset of fixtures (``bus_type``) needs circom 2.2.3
## via ``CIRCOM_2_2_BIN``; that secondary binary is a per-test
## runtime input and the recorder provisions it itself.

import repro_project_dsl

package codetracer_circom_recorder:
  uses:
    # Rust toolchain: driver, build, formatter, linter.
    "rustc >=1.85"
    "cargo >=1.85"
    "rustfmt"
    "clippy"

    # Nim toolchain -- codetracer_trace_writer_nim's build.rs
    # compiles a static library at cargo build time.
    "nim >=2.2 <3.0"
    "nimble"

    # Cap'n Proto schema compiler used by the recorder's build.rs.
    "capnp"

    # ``just`` runs the existing build/test/lint entry points.
    "just"

    # libzstd headers + library, needed when linking the Nim FFI
    # static library into the cargo build.
    "zstd"

    # pkg-config + OpenSSL -- openssl-sys consults pkg-config to
    # find OpenSSL on Linux/macOS.
    "pkg-config"
    "openssl"

    # Circom compiler -- compiles ``.circom`` source to witness for
    # the test corpus.
    "circom"

  devEnv:
    activity "default"
