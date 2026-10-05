{
  description = "CodeTracer Circom Recorder";

  inputs = {
    mcl-blockchain.url = "github:metacraft-labs/nix-blockchain-development";
    circom-bus-source = {
      url = "github:metacraft-labs/circom/4a6c82e8fdeb18523cad60f816f578bcb8629878";
      flake = false;
    };
    nixpkgs.follows = "mcl-blockchain/nixpkgs";
    flake-utils.follows = "mcl-blockchain/flake-utils";
    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      mcl-blockchain,
      circom-bus-source,
      git-hooks,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        busCompiler = import ./tools/circom-bus-sdk/package.nix {
          inherit pkgs;
          source = circom-bus-source;
          rustPlatform = mcl-blockchain.legacyPackages.${system}.rustPlatformStable;
          craneLib = mcl-blockchain.legacyPackages.${system}.craneLib-fenix-stable;
        };
        # Committed portable rules are installed only in the owning checkout.
        # git-hooks.nix installs `.pre-commit-config.yaml` and git hooks into
        # `git rev-parse --show-toplevel` of the directory the shell is entered
        # from, so `nix develop /path/to/this-repo` run inside another checkout
        # would plant this repository's hooks there. `ownRepoOnly` runs a snippet
        # only when that toplevel is this repository, recognised by a `flake.nix`
        # identical to the one this shell was evaluated from; anything it cannot
        # establish counts as another repository, so it fails safe.
        # tests/test_dev_shell_writes_nothing_elsewhere.sh
        ownRepoOnly = script: ''
          _own_repo_root="$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || true)"
          if [ -n "$_own_repo_root" ] && [ -f "$_own_repo_root/flake.nix" ] \
            && [ "$(${pkgs.coreutils}/bin/sha256sum "$_own_repo_root/flake.nix" | ${pkgs.coreutils}/bin/cut -d' ' -f1)" \
              = "${builtins.hashFile "sha256" ./flake.nix}" ]; then
          ${script}
          # git-hooks.nix's installer leaves core.hooksPath as the RELATIVE
          # `.git/hooks`, in the config every worktree shares. A linked worktree
          # cannot resolve it (there `.git` is a file), so git silently runs no
          # hooks there. Point it at the common hooks directory instead.
          if [ "$(${pkgs.git}/bin/git config --local --get core.hooksPath 2>/dev/null)" = .git/hooks ]; then
            ${pkgs.git}/bin/git config --local core.hooksPath "$(${pkgs.git}/bin/git rev-parse --path-format=absolute --git-common-dir)/hooks"
          fi
          fi
          unset _own_repo_root
        '';
      in
      {
        packages.circom = mcl-blockchain.packages.${system}.circom;
        packages.circom-bus = busCompiler;
        devShells.default = pkgs.mkShell {
          inputsFrom = [ mcl-blockchain.devShells.${system}.circom-recorder ];
          packages = [
            pkgs.prek
            pkgs.uv
            pkgs.python3
            pkgs.editorconfig-checker
            pkgs.nixfmt-rfc-style
            pkgs.opentofu
            pkgs.nodePackages.prettier
            busCompiler # Published adapted 2.2.3; primary Circom 2.1.5 is unchanged.
            pkgs.zstd # required by libcodetracer_trace_writer (Nim FFI)
            # Declare the toolchain explicitly so CI's dev shell
            # mirrors local dev exactly.  Cached mcl-blockchain
            # devShells from Attic sometimes drop nim/nimble from
            # PATH on resolution; declaring them here keeps the
            # contract visible in flake.nix.
            pkgs.nim
            pkgs.nimble
            # `git` from nixpkgs, ahead of the host's. On macOS the host's
            # `/usr/bin/git` is an xcode-select trampoline that runs
            # `$DEVELOPER_DIR/usr/bin/xcrun`; in this shell DEVELOPER_DIR is the
            # nixpkgs apple-sdk, whose xcrun (xcbuild) prints "warning: unhandled
            # Platform key FamilyDisplayName" on every call. nimble reads git's
            # stderr together with its stdout, so with that git `nimble install` would
            # reject `git rev-parse HEAD` as "not a valid sha1 hash value".
            pkgs.git
            pkgs.just
            pkgs.capnproto
            pkgs.rustc
            pkgs.cargo
            pkgs.rustfmt
            pkgs.clippy
            pkgs.pkg-config
          ];

          # `cargo <subcommand>` looks for `cargo-<subcommand>` in
          # `$CARGO_HOME/bin` BEFORE it searches PATH. On any machine with
          # rustup — including the self-hosted macOS runner — that directory
          # holds rustup's proxies, so `cargo fmt` and `cargo clippy` run
          # rustup's `cargo-fmt` / `cargo-clippy` instead of the rustfmt and
          # clippy above, and fail with "'cargo-fmt' is not installed for the
          # toolchain".
          #
          # The shell therefore gets its own CARGO_HOME with an empty `bin/`,
          # so subcommand lookup falls through to PATH. `registry/` and `git/`
          # are symlinks to the real CARGO_HOME, and so are its config and
          # credentials when present: the download cache is shared, and only
          # the proxy directory is left behind.
          shellHook =
            ownRepoOnly ''
              _ct_matching_repro="''${REPROBUILD_REPRO:-$(command -v repro)}"
              ${pkgs.python3}/bin/python3 tools/install-canonical-hooks.py --repro "$_ct_matching_repro" --bootstrap-managed || return $?
              ${pkgs.python3}/bin/python3 tools/install-canonical-hooks.py --repro "$_ct_matching_repro" || return $?
              unset _ct_matching_repro
            ''
            + ''
              export PREK_NO_FAST_PATH=1
              _ct_real_cargo_home="''${CARGO_HOME:-$HOME/.cargo}"
              _ct_cargo_home="''${XDG_CACHE_HOME:-$HOME/.cache}/codetracer-circom-recorder/cargo-home"
              if [ "$_ct_real_cargo_home" != "$_ct_cargo_home" ]; then
                mkdir -p "$_ct_cargo_home" \
                  "$_ct_real_cargo_home/registry" "$_ct_real_cargo_home/git"
                # Re-pointed on every entry, so a changed CARGO_HOME is followed
                # rather than left sharing the previous one's cache. Only a link
                # is ever replaced; a real file placed here is left alone.
                for _ct_entry in registry git config.toml credentials.toml; do
                  if [ -e "$_ct_real_cargo_home/$_ct_entry" ] &&
                    { [ -L "$_ct_cargo_home/$_ct_entry" ] ||
                      [ ! -e "$_ct_cargo_home/$_ct_entry" ]; }; then
                    ln -sfn "$_ct_real_cargo_home/$_ct_entry" "$_ct_cargo_home/$_ct_entry"
                  fi
                done
                export CARGO_HOME="$_ct_cargo_home"
              fi
              unset _ct_real_cargo_home _ct_cargo_home _ct_entry
            '';
        };
      }
    );
}
