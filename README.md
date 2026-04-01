## codetracer-circom-recorder

A recorder for Circom zero-knowledge circuits that produces [CodeTracer](https://github.com/metacraft-labs/CodeTracer) traces.

> **Note:** This project is in early development. APIs and trace formats may change.
> We welcome contributions and discussion!

### Overview

`codetracer-circom-recorder` compiles Circom circuits, generates and
executes the witness (via WASM or C++ backend), and captures
signal-level execution traces in the CodeTracer trace format. Signal
values are recorded with their full hierarchical paths so you can
inspect every intermediate computation in the circuit.

### Building

```bash
cargo build
```

Or enter the Nix dev shell first (provides the `circom` compiler):

```bash
nix develop
cargo build
```

### Usage

#### Record a Circom circuit

```bash
codetracer-circom-recorder record <file.circom> --out-dir <dir> [--format binary|json] [--backend wasm|cpp]
```

Parses the `.circom` source file, evaluates signal assignments, captures
the execution trace, and writes CodeTracer trace files to `--out-dir`.
The `--backend` flag selects the witness generation strategy (WASM by
default, or C++ for native compilation).

### Architecture

The recorder is structured around the following modules in `src/`:

| Module                | Purpose                                                               |
| --------------------- | --------------------------------------------------------------------- |
| `main.rs`             | CLI entry point (clap)                                                |
| `recorder.rs`         | Top-level recording orchestration                                     |
| `tracer.rs`           | Step-level trace capture during witness generation                    |
| `source_map.rs`       | Mapping between witness computation steps and Circom source locations |
| `cpp_witness.rs`      | C++ witness generator integration                                     |
| `signal_hierarchy.rs` | Hierarchical signal path resolution (e.g. `main.a.b[0]`)              |
| `lib.rs`              | Public library API                                                    |

### Testing

```bash
cargo test
```

Test programs live in:

- `test-programs/circom/` -- Circom circuit examples

### Environment variables

| Variable     | Description                                                                                                       |
| ------------ | ----------------------------------------------------------------------------------------------------------------- |
| `CIRCOM_BIN` | Path to the `circom` compiler binary. Defaults to `circom` on `$PATH`. Use `nix develop` to get it automatically. |

### Contributing

We'd be very happy if the community finds this useful, and if anyone wants to:

- Use and test the Circom support or CodeTracer.
- Provide feedback and discuss alternative implementation ideas: in the issue tracker, or in our [discord](https://discord.gg/qSDCAFMP).
- Contribute code to enhance the Circom support of CodeTracer.
- Provide [sponsorship](https://opencollective.com/codetracer), so we can hire dedicated full-time maintainers for this project.

### Legal info

LICENSE: MIT

Copyright (c) 2025 Metacraft Labs Ltd
