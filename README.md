## codetracer-circom-recorder

A recorder for Circom zero-knowledge circuits that produces [CodeTracer](https://github.com/metacraft-labs/CodeTracer) traces.

> **Note:** This project is in early development. APIs and trace formats may change.
> We welcome contributions and discussion!

### Overview

`codetracer-circom-recorder` compiles Circom circuits, generates and
executes the witness (via WASM or C++ backend), and captures
signal-level execution traces in the canonical CodeTracer CTFS
multi-stream format. Signal values are recorded with their full
hierarchical paths so you can inspect every intermediate computation in
the circuit.

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
codetracer-circom-recorder record <file.circom> --out-dir <dir> [--backend wasm|cpp]
```

Compiles the `.circom` source file, runs the generated witness
calculator, captures the execution trace, and writes a CTFS trace
bundle to `--out-dir`. The `--backend` flag selects the witness
generation strategy (WASM by default, or C++ for native compilation).

The recorder always writes traces in the canonical CodeTracer CTFS
multi-stream format (a single `.ct` container plus
`trace_metadata.json` / `trace_paths.json` sidecars). There is no
`--format` flag — see "Converting traces" below for human-readable
output.

#### Converting traces to JSON / text

The recorder is CTFS-only. To convert a recorded `.ct` bundle to a
human-readable form, use `ct print` from
[`codetracer-trace-format-nim`](https://github.com/metacraft-labs/codetracer-trace-format-nim):

```bash
ct-print --json <recording-dir>/<program>.ct
```

`ct-print` accepts `--json`, `--json-events`, `--summary`, and
`--follow` modes; see its `--help` for details. This conversion path
is the canonical way to produce textual oracles for golden-snapshot
tests, debugging, and interop with non-CodeTracer tools — see
`Recorder-CLI-Conventions.md` §4 in the `codetracer-specs` repo.

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
bash tests/verify-cli-convention-no-silent-skip.sh
```

Or via `just`:

```bash
just test
```

Test programs live in:

- `test-programs/circom/` -- Circom circuit examples

### Environment variables

The recorder respects the standard CodeTracer recorder env-var contract
defined in `Recorder-CLI-Conventions.md` §5:

| Variable                               | CLI equivalent | Description                                                                                                                |
| -------------------------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `CODETRACER_CIRCOM_RECORDER_OUT_DIR`   | `--out-dir`    | Fallback output directory when `--out-dir` is omitted. The CLI flag always wins.                                           |
| `CODETRACER_CIRCOM_RECORDER_DISABLED`  | —              | Set to `1` or `true` to run the recorder in pass-through mode (no trace artefacts written).                                |
| `CODETRACER_CIRCOM_RECORDER_LOG_LEVEL` | —              | Recorder log verbosity (advisory; the Circom recorder currently logs to stderr unconditionally).                           |
| `CIRCOM_BIN`                           | —              | Path to the upstream `circom` compiler binary. Defaults to `circom` on `$PATH`. Use `nix develop` to get it automatically. |

### Contributing

We'd be very happy if the community finds this useful, and if anyone wants to:

- Use and test the Circom support or CodeTracer.
- Provide feedback and discuss alternative implementation ideas: in the issue tracker, or in our [discord](https://discord.gg/qSDCAFMP).
- Contribute code to enhance the Circom support of CodeTracer.
- Provide [sponsorship](https://opencollective.com/codetracer), so we can hire dedicated full-time maintainers for this project.

### Legal info

LICENSE: MIT

Copyright (c) 2025 Metacraft Labs Ltd
