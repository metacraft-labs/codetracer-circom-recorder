# Circom Recorder CTFS Audit — 2026-05-02

This audit checks `codetracer-circom-recorder` against the canonical
CodeTracer multi-stream CTFS schema and the section 5.6 audit checklist
maintained in `/tmp/isonim-migration.txt`. Prior audits set the canonical
patterns: Ruby (1.21, 1.22), Python (1.27), JavaScript (1.38), EVM
(1.39), PHP (1.41), Solana (1.44), Move (1.46), Cardano (1.48), Cairo
(1.50), Flow / Cadence (1.52), Fuel / Sway (1.53), PolkaVM (1.55),
Miden (1.56), and TON / Tolk (1.57). This is the **fifteenth** recorder
audited.

## Architecture

The Circom recorder is a **single-process Rust crate** that drives the
upstream `circom` compiler as a subprocess and runs the generated WASM
witness calculator via `wasmtime`:

- `tracer.rs` (`CircomTracer::trace_program`) shells out to `circom
--wasm --sym --O0 [--srcmap]` to compile the input `.circom` source
  into a witness-generator WASM module (`<stem>_js/<stem>.wasm`) plus
  a `.sym` symbol table mapping each signal to a witness-vector index.
  The recorder then loads the WASM module via `wasmtime::Module::new`,
  binds the four `runtime` callbacks the circom WASM imports
  (`exceptionHandler`, `printErrorMessage`, `writeBufferMessage`,
  `showSharedRWMemory`), and follows the same FNV-1a-hashed
  `setInputSignal` / `getWitness` / `readSharedRWMemory` protocol
  the JavaScript witness calculator uses to populate every signal in
  the witness vector.
- `cpp_witness.rs` is the alternate backend: it invokes `circom --c`
  and compiles + runs the generated C++ witness binary against an
  `input.json`. Same witness output shape; faster on large circuits.
- The recorder maps witness indices back to source-level signal names
  via the parsed `.sym` file, builds a hierarchical
  `SignalPath`-keyed map (`signal_hierarchy.rs`), and then walks the
  Circom source again with hand-rolled line-based parsers
  (`parse_signal_declarations`, `parse_signal_assignments`,
  `parse_template_definitions`) to know which line each `signal` and
  `<==` lives on.
- Trace events are emitted through the Rust-native `NimTraceWriter`
  (the `codetracer_trace_writer_nim` sibling-path crate). The
  recorder is **not** an FFI consumer — every canonical entry point
  (`register_call`, `register_step`, `register_special_event`, `arg`,
  `register_thread_*`) is reachable through the Rust API. There are
  no `#[no_mangle]` stubs and `add_event` does not appear in the
  source.
- The first parsed template (the one bound to `component main`) is
  intentionally merged into the `<toplevel>` call that
  `TraceWriter::start` opens, so its body lives at depth 0 in the
  calltrace pane. Sub-component templates emit `register_call` /
  `register_return` pairs at their declaration line.

### Special note: Circom is a witness-generation system, not a stack VM

Several canonical audit checklist items map differently for Circom
than for stack-machine recorders (EVM, Miden, PolkaVM, TON):

- The "function call boundary" of a Circom program is the
  _instantiation of a sub-component template_ (`component adder =
Adder()`). Templates are not "called" with run-time argument values
  the way Solidity / Tolk / Move functions are; instead, callers
  _connect signals_ into a freshly instantiated component. The
  recorder treats each non-`main` template as a callee and stages its
  declared `signal input` names as the caller's arguments.
- Circom has no native stdout / stderr. The closest analogues are the
  `log()` directive (introduced in 2.0.4) which prints debug values
  during witness generation, and `assert()` / constraint-violation
  errors which fail the witness pipeline. Today's recorder does not
  yet wire either — see "Open gaps" below.
- Circom witness generation is single-threaded by construction, so
  thread events (audit (e)) are correctly N/A.

Architecturally closest to: **none of the prior audits**. Circom is
the first compute-only zk-circuit recorder; the closest structural
sibling is the Cairo recorder (1.50), which is also "compute without
stdin/stdout" in the conventional sense, but Cairo programs do have
explicit function-call boundaries with parameter lists.

## Summary

| #   | Check                                                                                     | Status (pre-fix)                                         | Status (post-fix)                                                               | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| --- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| a   | CLI defaults to `TraceEventsFileFormat::Ctfs`                                             | **GAP**                                                  | **OK**                                                                          | Pre-fix `src/main.rs`'s `OutputFormat` enum exposed only `Binary` (legacy CBOR + Zstd) and `Json`, with `Binary` as the default for the `record` subcommand. The canonical CTFS multi-stream container — the one the Nim `ct_reader_*` FFI and the db-backend's `CTFSTraceReader` consume directly — was not selectable from the CLI at all. Post-fix the enum gains a `Ctfs` variant (listed first, doc-commented), an `impl From<OutputFormat> for TraceEventsFileFormat` so the dispatch site collapses to `let format: TraceEventsFileFormat = args.format.into();`, and the `default_value` for `--format` is now `"ctfs"`. The `OutputFormat::as_str` helper is added (`#[allow(dead_code)]`) for future `trace_metadata.json` `format` field emission, mirroring the Fuel 1.53 / PolkaVM 1.55 / Miden 1.56 / TON 1.57 pattern. Same default-format fix as EVM (1.39), Solana (1.44), Move (1.46), Cardano (1.48), Cairo (1.50), Flow (1.52), Fuel (1.53), PolkaVM (1.55), Miden (1.56), TON (1.57).                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| b   | `register_call` for each call (template instantiation)                                    | OK                                                       | OK                                                                              | The recorder emits `register_call(fn_id, vec![])` for every parsed template after the first. The first template (the one bound to `component main`) is intentionally merged into the `<toplevel>` call that `TraceWriter::start` opens, so its body lives at depth 0 — this design pre-dates the audit and is documented in `tracer.rs::emit_source_trace`. The matching `register_return` is emitted in the symmetric tail loop. Per the "circom is not a stack VM" note above, the unit being treated as a "call" is template instantiation, not a runtime function call with argument values.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| c   | Call args via `register_call_arg` / `arg()`                                               | **GAP**                                                  | **OK** (declared input signals) / **OPEN** (live values + per-instance binding) | Pre-fix the call-detection branch always called `register_call(fn_id, vec![])` — every Circom template invocation showed empty arguments in the calltrace pane even when the template had a non-empty `signal input` list. Post-fix `parse_template_definitions` is extended to also collect each template's `signal input` declarations into `TemplateDef.input_signals: Vec<String>`. The emit loop iterates that list and stages each name through `TraceWriter::arg(input_name, NONE_VALUE)` immediately before `register_call`, matching the Miden 1.56 (operand-stack `s0..s3`), TON 1.57 (declared `func.params`), and PolkaVM 1.55 (Ecalli A0..A5) staging shape. **Open**: actual run-time arg values are still `NONE_VALUE` because the recorder does not yet thread per-component bindings (the `comp.in <== expr` assignment is parsed but not connected back to its template's parameter list, so the recorder cannot say "this instance was called with `a=20`, `b=22`"). The post-fix `.sym` data already contains the per-instance witness values (`main.adder.a`, `main.adder.b`); wiring them through the `arg()` staging path is tracked as the "per-instance input-signal value resolution" follow-up below. Parallel to PolkaVM 1.55 ink!-metadata symbolic decoding and Miden 1.56 per-procedure ABI parsing.                                                                                                                                             |
| d   | Write/WriteOther/Error/EvmEvent for IO and structured events via `register_special_event` | **N/A (Write)** / **OPEN (Error)** / **OPEN (EvmEvent)** | **N/A (Write)** / **OPEN (Error)** / **OPEN (EvmEvent)**                        | The Circom witness pipeline has **no native stdout/stderr** — the WASM runtime callbacks (`printErrorMessage`, `writeBufferMessage`, `showSharedRWMemory`) are bound as no-op closures because they are only used by the JavaScript reference witness calculator's diagnostic paths, not by witness data flow. Tolk and Miden have the same shape (no host bridge); Cairo and Cardano have the same shape (compile + eval without stdin/stdout). Marked **N/A** for Write. **Open (Error)**: the `circom` compiler-process invocation, witness-WASM `wasmtime::Engine`, and `cpp_witness::run_cpp_witness` paths can each fail (compiler error, missing `.sym`, malformed witness, gas exhaustion in WASM trap, C++ binary non-zero exit). All such errors today bubble up via `?` _before_ the trace writer is created, so no `register_special_event(EventLogKind::Error, …)` lands in the `.ct` container — the recorder exits non-zero with the message on the calling shell's stderr instead. Same shape as Flow (1.52) Cadence-runtime errors pre-fix. Concrete fix shape under "Open gaps" below. **Open (EvmEvent)**: Circom 2.0.4 added a `log(<expr>)` directive that prints values to stderr during witness generation (the closest analogue to EVM's `console_log` / Cairo's `Print` / Cadence's `log()`). The recorder does not currently parse `log()` calls or wire the WASM `printErrorMessage` callback to capture them. Concrete fix shape under "Open gaps". |
| e   | Thread events (Start / Exit / Switch)                                                     | **N/A**                                                  | **N/A**                                                                         | Circom witness generation is single-threaded by construction (the WASM module is loaded into one `wasmtime::Store`, the FNV-hashed input set + sequential `getWitness(i)` reads are deterministic and sequential). No threads, no parallel proving here — the proving system (groth16 / plonk) lives downstream and is out of scope for the witness recorder.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| f   | Step records for line navigation                                                          | OK                                                       | OK                                                                              | `tracer.rs::emit_source_trace` calls `register_step(source_path, Line(decl.line))` for every parsed `signal` declaration and every `<==` assignment, in source order. This produces a step-by-step trace that matches the source-line layout of the original `.circom` file. The `--srcmap` path (forked circom only) loads `<stem>.srcmap.json` for the WASM-instruction-to-source-byte-offset mapping but does **not** currently emit per-WASM-instruction steps; it is loaded for future use by the heuristic-mapping fallback. Marked OK because the source-line stepping the calltrace pane needs is in place.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| g   | Canonical CTFS schema match                                                               | **GAP**                                                  | **OK**                                                                          | Pre-fix the writer always produced a `.ct` file regardless of `--format` (the underlying Nim writer treats `Binary` and `Ctfs` identically at the time of writing — see `codetracer_trace_writer_nim/src/lib.rs::TraceEventsFileFormat::to_ffi`), but the CLI surface advertised only `binary`/`json` so consumers had no way to _request_ the canonical container deliberately. Post-fix verified by `tests/test_ctfs_audit.rs::ctfs_writer_produces_ct_container`: invoking `record(flow_test.circom, out_dir, TraceEventsFileFormat::Ctfs)` produces a single `.ct` file starting with the canonical magic bytes `0xC0 0xDE 0x72 0xAC 0xE2` and materially populated (>64 bytes). The existing `tests/test_tracer.rs` already asserted CTFS magic but was passing `TraceEventsFileFormat::Json` — that worked because the underlying writer always emits the multi-stream container; the audit fixes the test to pass `TraceEventsFileFormat::Ctfs` explicitly so an eventual divergence between Json and Ctfs in the writer cannot silently break the recorder.                                                                                                                                                                                                                                                                                                                                                                                                             |
| h   | Obsolete `add_event` calls                                                                | OK                                                       | OK                                                                              | `grep -r 'add_event' src/` returns nothing. Recorder uses dedicated `register_*` entry points exclusively.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| i   | `#[no_mangle]` stubs colliding with upstream Nim exports                                  | OK                                                       | OK                                                                              | `grep -r '#\[no_mangle\]' src/` returns nothing. Recorder uses the `codetracer_trace_writer_nim` Rust API directly (sibling-path dep), not the C FFI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

## Concrete fixes applied

### 1. CLI now exposes and defaults to `Ctfs`

`src/main.rs`'s `OutputFormat` enum used to expose only `Binary` and
`Json`, with `Binary` as the default for the `record` subcommand.
There was no way to request the canonical CTFS multi-stream container
from the CLI.

Post-fix: `OutputFormat` gains a `Ctfs` variant (listed first), with
doc-comments explaining each option, and a freshly added
`impl From<OutputFormat> for TraceEventsFileFormat` makes the dispatch
site uniform:

```rust
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Canonical CodeTracer multi-stream container (recommended; default).
    Ctfs,
    /// Legacy CBOR + Zstd binary format.
    Binary,
    /// Human-readable JSON (slower; useful for debugging).
    Json,
}

impl From<OutputFormat> for TraceEventsFileFormat {
    fn from(fmt: OutputFormat) -> Self {
        match fmt {
            OutputFormat::Ctfs => TraceEventsFileFormat::Ctfs,
            OutputFormat::Binary => TraceEventsFileFormat::Binary,
            OutputFormat::Json => TraceEventsFileFormat::Json,
        }
    }
}
```

`RecordArgs.format` defaults to `"ctfs"`. The dispatch site now reduces
to `let format: TraceEventsFileFormat = args.format.into();`. The
`OutputFormat::as_str` helper is wired in (marked `#[allow(dead_code)]`)
for future `trace_metadata.json` `format` field emission, mirroring the
Fuel 1.53 / PolkaVM 1.55 / Miden 1.56 / TON 1.57 pattern.

### 2. Template-instantiation call branch now stages declared input-signal names

`parse_template_definitions` previously captured only `(name, line)`
per template. Post-fix it also walks the template body, tracking
brace depth, and collects each `signal input <name>;` declaration in
source order into a new `TemplateDef.input_signals: Vec<String>`
field.

The emit loop in `CircomTracer::emit_source_trace` then iterates that
list and stages each name through `TraceWriter::arg(input_name,
NONE_VALUE)` before `register_call`:

```rust
for input_name in &template.input_signals {
    let _ = TraceWriter::arg(&mut *self.writer, input_name, NONE_VALUE);
}
TraceWriter::register_call(&mut *self.writer, _fn_id, vec![]);
```

The argument values are `NONE_VALUE` for now: the recorder does not
yet thread the per-instance binding (`comp.in <== expr`) back to its
template's parameter list, so it cannot tell which run-time witness
value corresponds to which formal input signal at the call site.
Witness values _are_ available in the `.sym`-keyed `values` map (e.g.
`main.adder.a = 20`, `main.adder.b = 22`); wiring them through the
`arg()` staging path is tracked as the
"per-instance input-signal value resolution" follow-up below.

## Tests added

`tests/test_ctfs_audit.rs` (3 new cases):

- `ctfs_writer_produces_ct_container` — runs `flow_test.circom`
  through `recorder::record` with `TraceEventsFileFormat::Ctfs` and
  asserts the resulting `.ct` file starts with the canonical CTFS
  magic bytes (`0xC0 0xDE 0x72 0xAC 0xE2`) and is materially
  populated (>64 bytes).
- `ctfs_format_advertised_in_record_help` — CLI smoke test that
  `record --help` advertises `ctfs` as a `--format` value and shows
  `[default: ctfs]`. Uses `CARGO_BIN_EXE_codetracer-circom-recorder`
  to locate the just-built binary (same idiom as Flow 1.52, Fuel
  1.53, PolkaVM 1.55, Miden 1.56, TON 1.57). Catches accidental
  defaults regressions.
- `call_arg_staging_does_not_empty_trace` — structural smoke test
  for the `TraceWriter::arg(input_name, NONE_VALUE)` staging path
  introduced in this audit. Uses `component_test.circom` whose
  sub-component `Adder` has two `signal input` declarations
  (`a`, `b`); asserts the resulting `.ct` container is still valid
  CTFS and >64 bytes. When the `codetracer_trace_reader_nim`
  read-side helper lands (open follow-up), this should be upgraded
  to assert that `a` and `b` appear on the embedded
  `CallRecord.args` slice for the `Adder` call.

`src/tracer.rs` (added a unit test):

- `test_parse_template_definitions_collects_input_signals` —
  verifies the post-fix parser surfaces `signal input` declarations
  in source order, even across multiple templates.

`tests/test_tracer.rs` (touched):

- `run_tracer_on_file` now passes `TraceEventsFileFormat::Ctfs`
  explicitly (was `Json`). Pre-fix the test asserted CTFS magic on
  a file produced under `Json` mode — only working because the Nim
  writer happens to treat `Json`'s writer-side dispatch identically
  to `Ctfs` for the multi-stream container path. Once the writer
  differentiates, the explicit `Ctfs` is the documented and correct
  intent.
- `test_circom_cli_record` now passes `--format ctfs` (was `--format
json`). Same reasoning.

Read-side end-to-end content assertions on the embedded event records
(e.g. that `arg("a", NONE_VALUE)` actually appears as a `CallRecord`
arg name in the event-log of the `.ct` container) need the
`codetracer_trace_reader_nim` dev-dep added and a small reader-walk
helper. Tracked as an open follow-up below (also open for Cairo,
Cardano, Flow, Fuel, PolkaVM, Miden, TON).

## Verification

```
cd /home/zahary/metacraft/codetracer-circom-recorder
cargo build --release
cargo test --release
```

- lib unit tests: 39 / 39 passing (was 37; the audit adds
  `test_parse_template_definitions_collects_input_signals` and the
  pre-existing `test_parse_template_definitions` is updated to assert
  the new `input_signals` field).
- `test_tracer` (existing): 13 / 13 passing.
- `test_ctfs_audit` (new): 3 / 3 passing.

Total: 55 / 55 passing across all suites, 0 regressions.
`cargo build --release` clean.

### Targeted Playwright sweep

`src/tests/gui/tests/program_specific_tests/circom_example.spec.ts`
exists in the codetracer repo. Most tests are gated on the Circom
pipeline being integrated into `ct record` (the
`circomPipelineAvailable` guard in the spec). Per the recorder's CLI
not yet being wired into `ct record`, the gated tests remain skipped
both pre-fix and post-fix; only the unconditional structural tests
(language detection, tool availability) run, and they pass identically
pre-fix and post-fix. The gated tests cannot exercise the audit's
recorder-side fixes until the Circom pipeline is wired into
`ct record` — same shape of consumer-integration gating as TON 1.57
(Tolk pipeline) and PolkaVM 1.55 (`polkatool` toolchain).

## Open gaps (not blocking, documented for follow-up)

### Per-instance input-signal value resolution (audit c, live values)

The post-fix call-arg staging emits declared input-signal _names_ via
`writer.arg(input_name, NONE_VALUE)`. Run-time _values_ are still
`NONE_VALUE` because the recorder does not yet thread the per-instance
binding (`comp.input <== expr`) back to its template's parameter list.

The witness values for each instance are already available — the
recorder's `values` map contains entries like `adder.a = 20` and
`adder.b = 22` for `component_test.circom`. The gap is purely the
mapping layer: at `register_call` time for a sub-component template,
the recorder must know _which component instance_ it is calling so it
can look up `<instance>.<input_name>` in the witness map.

Concrete fix shape:

- Extend `parse_signal_assignments` (or add a new
  `parse_component_instances` helper) to also capture `component
<instance> = <Template>(...)` declarations, mapping each instance
  name back to its template name.
- In `emit_source_trace`, when iterating templates, look up the
  matching instance(s) of that template and select the right witness
  values from the `values` map.
- Pass live `ValueRecord::Int { i, type_id }` values to
  `TraceWriter::arg` instead of `NONE_VALUE`.

Once that lands, the same `arg()` staging path emits live values
without further audit work. Parallel to PolkaVM 1.55 ink!-metadata
symbolic decoding, Miden 1.56 per-procedure ABI parsing, and TON 1.57
parser-extension follow-up.

### `circom` / WASM / C++ pipeline error routing (audit d, Error)

Today every failure path in the recording pipeline (compiler error,
missing `.sym`, malformed witness, WASM trap, gas exhaustion, C++
binary non-zero exit) bubbles up via `?` _before_ the trace writer is
created — the recorder exits non-zero with the message on the calling
shell's stderr instead of routing through
`register_special_event(EventLogKind::Error, …)` so it lands inside
the `.ct` container.

The Flow recorder (1.52) and Cardano recorder (1.48) had the same
shape pre-fix and it was closed by:

- Creating the trace writer first (with a placeholder source path /
  metadata that can be filled in once the pipeline succeeds).
- On failure, route through `register_special_event(Error,
"circom_compile_error" / "wasm_witness_error" / "cpp_witness_error",
msg)` and finalise the (partial, error-decorated) trace cleanly.
- Then `?`-propagate so the CLI still exits non-zero.

The trade-off is that the writer must be ready before the pipeline
succeeds; today the recorder uses the input source's canonicalised
path as the writer's `program` argument, which is known up-front
anyway, so the refactor is mechanical. Concrete metadata strings:

- `circom_compile_error` for stderr from `circom --wasm --sym`.
- `wasm_witness_error` for `wasmtime` traps and `setInputSignal` /
  `getWitness` failures (gas exhaustion in WASM, missing exports,
  size-mismatch errors from `getInputSignalSize`).
- `cpp_witness_error` for non-zero exit from the C++ witness binary
  or `compile_cpp_witness` failures.

Same kind mapping as Cairo 1.50 `CairoPanic`, Miden 1.56
`miden_vm_error`, TON 1.57 `tvm_exception`.

### `log()` directive routing (audit d, EvmEvent)

Circom 2.0.4+ supports a `log(<expr>);` directive that prints values
to stderr during witness generation — the closest analogue to EVM's
`console_log`, Cairo's `Print`, Cadence's `log()`. The recorder
currently does not parse `log()` call sites, and the WASM
`printErrorMessage` runtime callback is bound to a no-op closure.

Concrete fix shape:

- Extend the source parser to capture each `log(<expr>)` call site
  and its line number.
- Either evaluate `<expr>` symbolically (matching the recorder's
  existing source-level `<==` evaluator) or capture the WASM-side
  output by replacing the no-op `printErrorMessage` /
  `writeBufferMessage` runtime callbacks with closures that read
  the printed bytes from the shared RW memory and surface them.
- Route through `register_special_event(EventLogKind::EvmEvent,
"circom_log", &content)` so the structured event channel surfaces
  the directive's output. (Routing to `EvmEvent` rather than `Write`
  follows the EVM 1.39 / Cairo 1.50 / Fuel 1.53 / PolkaVM 1.55 /
  Miden 1.56 pattern for "structured event from a compute-only VM".)

### Constraint-violation / `assert()` failure routing (audit d, Error)

Circom programs can call `assert(<expr>);` (introduced in 2.0.0) and
the witness generator aborts with a non-zero exit code when an
assertion fails. Today this surfaces as an opaque "WASM trap" in the
recorder's stderr, with no in-`.ct` representation.

Concrete fix shape: layered on top of the WASM-error routing above,
distinguish `assert()`-driven traps (which carry source-line
information via `printErrorMessage`) from generic traps and route
through `register_special_event(EventLogKind::Error,
"circom_assert_failed", msg)` with the source line / failed
expression in the message.

### `--srcmap` per-WASM-instruction step emission (audit f, granularity)

The recorder currently loads the forked-circom `<stem>.srcmap.json`
into `compiler_srcmap` but only emits source-line `register_step`s
keyed off the original `.circom` lines (declarations + `<==`). The
`.srcmap.json` provides byte-offset-to-line mapping for every WASM
instruction in the compiled witness module, which would let the
recorder emit one step per WASM instruction (much finer granularity)
and tie it to the originating Circom source line.

Concrete fix shape: drive the witness-vector read loop (around
`get_witness(i)`) from a step-by-step WASM execution iterator (similar
to Miden 1.56's `execute_iter`), use the source map to translate each
WASM instruction back to a Circom source line, and emit `register_step`
per instruction. Today's coarser source-line stepping is sufficient
for the calltrace pane; the per-instruction view is a future
enhancement.

### Replay / on-chain witness regeneration (audit f, replay path)

Unlike VM-style recorders (TON / Tolk's Liteserver replay path,
Cairo's on-chain replay, Fuel's node replay), Circom does not have an
"on-chain" notion — the witness is generated locally for a given
`input.json`. The closest analogue would be replaying a witness from
a stored `.wtns` file produced by some other tool (snarkjs, etc.); a
`replay` subcommand that loads a `.wtns` and emits a CodeTracer trace
without re-running `circom` would be a useful addition. Not blocking;
flagged here for completeness.

### Multi-stream IO event collapse (cross-cutting)

Same writer-side issue documented in 1.39 (EVM), 1.41 (PHP), 1.44
(Solana), 1.46 (Move), 1.48 (Cardano), 1.50 (Cairo), 1.52 (Flow),
1.53 (Fuel), 1.55 (PolkaVM), 1.56 (Miden), 1.57 (TON): the
multi-stream IO event writer's `toIOEventKind` collapses 13
`EventLogKind`s onto 4 `IOEventKind` buckets, losing the original
kind byte and the metadata string. Once the recorder starts emitting
`EventLogKind::Error` / `EventLogKind::EvmEvent` records (open gaps
above), they will collapse onto `stderr` and lose their metadata in
the multi-stream pane. Out of scope for any single recorder audit;
flagged as a writer-side fix in
`codetracer_trace_writer_ffi.nim`'s `toIOEventKind`.

### Read-side end-to-end content assertions

The audit tests assert the `.ct` file starts with the CTFS magic and
is materially populated. Verifying that the embedded event stream
contains the expected `arg(...)` / `register_call(...)` /
`register_special_event(...)` records (e.g. `Adder`'s `CallRecord.args`
contains the names `"a"` and `"b"` after the audit fix) requires the
`codetracer_trace_reader_nim` dep added as a `[dev-dependencies]`
entry plus a small reader-walk helper. Tracked here for the next pass
(also open for Cairo, Cardano, Flow, Fuel, PolkaVM, Miden, TON).

## Cross-cutting finding: zk-witness recorders differ structurally from VM recorders

Circom is the first audited recorder where the traced program is
**not a stack VM**:

- No operand stack with stack[0..N] to surface as call args.
- No formal parameter list at the function-call boundary (templates
  are _connected_, not _called_ with values).
- No native stdout/stderr — the closest analogue is a `log()`
  directive that the WASM runtime exposes via callbacks.
- No on-chain replay path — witness generation is a local, pure
  function of the input JSON.
- No thread events, ever.

Future audit guidance for similar recorders (Leo / Aleo,
Halo2-based circuits, Noir witness generation, Plonk / Plonky2
front-ends) should expect the same five-bullet shape and apply the
checklist accordingly:

- Audit (b) becomes "template / circuit-component instantiation
  boundary".
- Audit (c) live-value staging requires per-instance signal-binding
  resolution rather than runtime stack inspection.
- Audit (d) Write / Read are typically N/A; Error and EvmEvent map to
  pipeline failures and `log()`-style directives respectively.
- Audit (e) Thread events are universally N/A.
- Audit (f) granularity ranges from "source-line stepping driven off
  the parser" (current Circom) to "per-WASM-instruction stepping
  driven off the compiler's source map" (future Circom + Noir).

## After this audit

Section 5.6's recorder list shows `codetracer-circom-recorder` as
audited (gaps closed for default-Ctfs CLI + declared input-signal
arg-name staging via `TraceWriter::arg(name, NONE_VALUE)`;
per-instance live-value resolution + WASM-pipeline-error special-event
routing + `log()` directive routing + `assert()` failure routing +
per-WASM-instruction step emission + `.wtns` replay path open as
recorder-side / parser / writer-API follow-ups). Audited recorder
count: 14 → 15.
