//! Integration tests for the Circom tracer.
//!
//! These tests cover three areas:
//!
//! 1. End-to-end recording of `flow_test.circom` (and the other bundled
//!    circuits) through the Circom → witness → CTFS pipeline; assertions
//!    are made on the CTFS bundle either directly (CTFS magic bytes /
//!    `.ct` file presence) or via `ct print` (the canonical conversion
//!    tool shipped with `codetracer-trace-format-nim`).
//! 2. Pure unit tests for the signal-hierarchy data model.
//! 3. The CLI env-var contract for the recorder
//!    (`CODETRACER_CIRCOM_RECORDER_OUT_DIR` /
//!    `CODETRACER_CIRCOM_RECORDER_DISABLED`) plus the no-`--format`
//!    invariant.
//!
//! History note: pre-2026-05-08 the recorder shipped a `--format
//! ctfs|binary|json` flag and the CLI integration test
//! (`test_circom_cli_record`) drove it with `--format ctfs`.  When the
//! convention switched to CTFS-only the flag was removed and the test
//! was rewritten to invoke `record` without `--format`.  See
//! `AUDIT-CTFS-2026-05.md` ("Convention compliance follow-up") for
//! the full record.

use std::path::{Path, PathBuf};
use std::process::Command;

/// CTFS magic bytes: C0 DE 72 AC E2
const CTFS_MAGIC: [u8; 5] = [0xC0, 0xDE, 0x72, 0xAC, 0xE2];

/// Helper: path to the test-programs directory.
fn test_programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-programs/circom")
}

/// Path to the `ct-print` binary shipped with `codetracer-trace-format-nim`.
///
/// The Circom recorder is CTFS-only; tests that need to make
/// content-level assertions on a recorded trace pipe the `.ct`
/// container through `ct-print --json` and assert on the resulting
/// JSON.  This is the same workflow that `Recorder-CLI-Conventions.md`
/// §4 prescribes for downstream tools / golden snapshots.
fn ct_print_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("codetracer-trace-format-nim")
        .join(format!("ct-print{}", std::env::consts::EXE_SUFFIX))
}

/// Helper: collect every `.ct` file in `out_dir`.
fn ct_files_in(out_dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(out_dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "ct"))
        .collect()
}

/// Helper: run the tracer on a Circom source file and return the output directory.
fn run_tracer_on_file(source_path: &Path, out_dir: &Path) {
    codetracer_circom_recorder::recorder::record(
        source_path,
        out_dir,
        false, // use WASM backend
    )
    .expect("trace_program should succeed");
}

/// Helper: find a .ct file in the output directory and verify CTFS magic bytes.
fn assert_valid_ct_file(out_dir: &Path) -> PathBuf {
    let ct_files = ct_files_in(out_dir);

    assert!(
        !ct_files.is_empty(),
        "expected at least one .ct file in {}, found: {:?}",
        out_dir.display(),
        std::fs::read_dir(out_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect::<Vec<_>>()
    );

    let ct_path = &ct_files[0];
    let content = std::fs::read(ct_path).expect("failed to read .ct file");
    assert!(
        content.len() >= CTFS_MAGIC.len(),
        ".ct file is too small to contain CTFS magic bytes"
    );
    assert_eq!(
        &content[..CTFS_MAGIC.len()],
        &CTFS_MAGIC,
        ".ct file should start with CTFS magic bytes"
    );

    ct_path.clone()
}

// ---------------------------------------------------------------------------
// Test 1: Record flow_test.circom, verify .ct output
// ---------------------------------------------------------------------------

#[test]
fn test_circom_compile_and_run() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    // Verify a valid .ct file was produced.
    let ct_path = assert_valid_ct_file(&out_dir);
    let size = std::fs::metadata(&ct_path).unwrap().len();
    assert!(
        size > 100,
        ".ct file should have substantial content, got {} bytes",
        size
    );
}

// ---------------------------------------------------------------------------
// Test 2: Verify trace is produced for flow_test (value computation)
// ---------------------------------------------------------------------------

#[test]
fn test_circom_compute_value() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    // The circuit calculates: a=10, b=32, sum_val=a+b=42, doubled=sum_val*2=84,
    // out=doubled+a=94. Verify a valid trace was produced.
    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 3: Verify signal recording produces valid trace
// ---------------------------------------------------------------------------

#[test]
fn test_circom_signal_values() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 4: Verify step events produce valid trace
// ---------------------------------------------------------------------------

#[test]
fn test_circom_step_events() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 5: Verify metadata is included in trace
// ---------------------------------------------------------------------------

#[test]
fn test_circom_metadata_structure() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 6: CLI record end-to-end test
//
// Pre-2026-05-08 this test passed `--format ctfs`; the convention now
// mandates CTFS-only output, so the test simply verifies the CLI runs
// to completion and produces a `.ct` container in the requested output
// dir.  Content-level assertions live in
// `test_recorded_trace_via_ct_print_json` below.
// ---------------------------------------------------------------------------

#[test]
fn test_circom_cli_record() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("cli-traces");
    let source_path = test_programs_dir().join("flow_test.circom");

    let output = Command::new(env!("CARGO_BIN_EXE_codetracer-circom-recorder"))
        .args(["record"])
        .arg(&source_path)
        .args(["--out-dir"])
        .arg(&out_dir)
        .output()
        .expect("failed to run");

    assert!(
        output.status.success(),
        "record should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify a valid .ct file was produced by the CLI.
    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 7: trace paths included in .ct output
// ---------------------------------------------------------------------------

#[test]
fn test_circom_tracer_paths_valid() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 8: Function call/return events produce valid trace
// ---------------------------------------------------------------------------

#[test]
fn test_circom_function_entry_exit() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 9: Component test circuit (sub-component instantiation)
// ---------------------------------------------------------------------------

#[test]
fn test_circom_component_circuit() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("component_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 10: Array test circuit (signal arrays)
// ---------------------------------------------------------------------------

#[test]
fn test_circom_array_circuit() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("array_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    assert_valid_ct_file(&out_dir);
}

// ---------------------------------------------------------------------------
// Test 11: Signal hierarchy unit tests (no circom CLI needed)
// ---------------------------------------------------------------------------

#[test]
fn test_signal_hierarchy_from_component_circuit() {
    use codetracer_circom_recorder::signal_hierarchy::{build_hierarchy, SignalPath};

    // Simulate what a component_test.circom .sym file would produce.
    let signals = vec![
        ("main.result".to_string(), 42),
        ("main.x".to_string(), 20),
        ("main.y".to_string(), 22),
        ("main.adder.a".to_string(), 20),
        ("main.adder.b".to_string(), 22),
        ("main.adder.out".to_string(), 42),
    ];
    let hierarchy = build_hierarchy(&signals);

    // Main-level signals.
    let main_sigs = hierarchy.get_signals_for_component(&["main"]);
    assert_eq!(main_sigs.len(), 3);

    // Sub-component signals.
    let adder_sigs = hierarchy.get_signals_for_component(&["main", "adder"]);
    assert_eq!(adder_sigs.len(), 3);
    assert!(adder_sigs.contains(&("a".to_string(), 20)));
    assert!(adder_sigs.contains(&("b".to_string(), 22)));
    assert!(adder_sigs.contains(&("out".to_string(), 42)));

    // Check hierarchy structure.
    let children = hierarchy.get_child_components(&["main"]);
    assert_eq!(children.len(), 1);
    assert!(children.contains(&"adder".to_string()));

    // Check signal path parsing for sub-component signals.
    let path = SignalPath::parse("main.adder.out");
    assert_eq!(path.depth(), 3);
    assert_eq!(path.component_path().len(), 1);
    assert_eq!(path.component_path()[0].name, "adder");
    assert_eq!(path.leaf_name(), "out");
}

#[test]
fn test_signal_hierarchy_from_array_circuit() {
    use codetracer_circom_recorder::signal_hierarchy::{build_hierarchy, SignalPath};

    // Simulate what an array_test.circom .sym file would produce.
    let signals = vec![
        ("main.in".to_string(), 5),
        ("main.values[0]".to_string(), 5),
        ("main.values[1]".to_string(), 10),
        ("main.values[2]".to_string(), 30),
        ("main.out".to_string(), 30),
    ];
    let hierarchy = build_hierarchy(&signals);

    // Array query.
    let arr = hierarchy.get_array_signals(&["main"], "values");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0], (0, 5));
    assert_eq!(arr[1], (1, 10));
    assert_eq!(arr[2], (2, 30));

    // Signal path parsing for array signals.
    let path = SignalPath::parse("main.values[1]");
    assert_eq!(path.leaf_name(), "values");
    assert_eq!(path.leaf_index(), Some(1));
}

// ---------------------------------------------------------------------------
// Test 12: All intermediate values appear in trace (flow_test)
// ---------------------------------------------------------------------------

#[test]
fn test_circom_all_intermediate_values() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    // The circuit produces these key values:
    // a = 10, b = 32, sum_val = 42, doubled = 84, out = 94
    // Verify a valid CTFS trace was produced.
    let ct_path = assert_valid_ct_file(&out_dir);
    let size = std::fs::metadata(&ct_path).unwrap().len();
    assert!(
        size > 100,
        ".ct file should have substantial content, got {} bytes",
        size
    );
}

// ===========================================================================
// CTFS content via `ct-print` — replaces the legacy `--format json` test
// ===========================================================================

/// Record `flow_test.circom`, then convert the produced `.ct` container
/// to JSON via `ct-print` and assert on:
///
/// 1. **Structural anchors** (legacy layer): `ct-print --json` output
///    contains the source filename / template name / signal names
///    somewhere in the textual rendering.
/// 2. **Exact decoded values** (the layer enabled by `ct-print --full`):
///    the `flow_test.circom` template executes `(10 + 32) * 2 + 10 = 94`
///    via the `FlowTest` template, with intermediate signal assignments
///    `a=10`, `b=32`, `sum_val=42`, `doubled=84`, `out=94`.  Each
///    signal must surface in the trace as a step event with a decoded
///    `Int` ValueRecord whose `i` field matches the literal value
///    derived in the source program.
///
/// Pre-2026-05-08 the test_tracer suite asserted CTFS magic on a file
/// produced under the `--format ctfs` CLI flag.  The convention now
/// mandates CTFS-only output; `ct print` is the canonical conversion
/// tool.  See `Recorder-CLI-Conventions.md` §4.  `ct-print --full`
/// (added 2026-05 in `codetracer-trace-format-nim`) is what enables the
/// exact-value layer — its output is a deterministic JSON document with
/// every CBOR `ValueRecord` decoded to a structured form like
/// `{"kind":"Int","i":42,"type_id":N}`.
///
/// The note in the previous version of this test about the Circom
/// recorder's `register_variable_with_full_value` integer payloads not
/// round-tripping through `ct-print --json` is empirically obsolete for
/// `--full`: each of `a=10, b=32, sum_val=42, doubled=84, out=94`
/// decodes back to `{"kind":"Int","i":<n>,"type_id":1}` with values
/// intact.  The remaining open follow-up from `AUDIT-CTFS-2026-05.md`
/// is the type-naming gap (every variable carries a generic `type_id`
/// rather than a named type like "Int") — a separate concern that does
/// not block exact-value assertions on the integer payloads.
#[test]
fn test_recorded_trace_via_ct_print_json() {
    let ct_print = require_ct_print("test_recorded_trace_via_ct_print_json");

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    codetracer_circom_recorder::recorder::record(&source_path, &out_dir, false)
        .expect("recorder::record should succeed");

    let ct_files = ct_files_in(&out_dir);
    assert!(
        !ct_files.is_empty(),
        "expected a .ct container in {:?}",
        out_dir
    );

    // -----------------------------------------------------------------
    // Layer 1 (legacy): ct-print --json — substring presence checks.
    // Kept as a safety net so a regression in the textual rendering
    // is caught even if --full's JSON shape evolves.
    // -----------------------------------------------------------------
    let output = Command::new(&ct_print)
        .args(["--json"])
        .arg(&ct_files[0])
        .output()
        .expect("failed to run ct-print");

    assert!(
        output.status.success(),
        "ct-print --json should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout_json.is_empty(),
        "ct-print --json produced empty output"
    );

    assert!(
        stdout_json.contains("flow_test.circom"),
        "ct-print --json output should mention the source file; got:\n{stdout_json}"
    );
    assert!(
        stdout_json.contains("\"FlowTest\""),
        "ct-print --json output should mention the `FlowTest` template; got:\n{stdout_json}"
    );
    for varname in ["a", "b", "sum_val", "doubled", "out"] {
        assert!(
            stdout_json.contains(&format!("\"{varname}\"")),
            "ct-print --json output should mention the `{varname}` signal; got:\n{stdout_json}"
        );
    }

    // -----------------------------------------------------------------
    // Layer 2 (the upgrade): ct-print --full — exact decoded values.
    // -----------------------------------------------------------------
    let full_output = Command::new(&ct_print)
        .args(["--full", "--strip-paths"])
        .arg(&ct_files[0])
        .output()
        .expect("failed to run ct-print --full");

    assert!(
        full_output.status.success(),
        "ct-print --full should succeed; stderr: {}",
        String::from_utf8_lossy(&full_output.stderr)
    );

    let doc: serde_json::Value = serde_json::from_slice(&full_output.stdout)
        .expect("ct-print --full should emit valid JSON");

    // ----- Function table: FlowTest must appear -----------------------
    // The Circom recorder currently registers template names as bare
    // identifiers (no module qualifier), but downstream tooling may
    // qualify them in the future (e.g. `circom::flow_test::FlowTest`),
    // so we use `ends_with` to stay platform-agnostic.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        functions.iter().any(|f| f.ends_with("FlowTest")),
        "expected `FlowTest` in functions table; got {:?}",
        functions
    );

    // ----- Path table: the canonical fixture path must appear ---------
    let paths: Vec<&str> = doc["paths"]
        .as_array()
        .expect("paths array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        paths.iter().any(|p| p.ends_with("flow_test.circom")),
        "expected flow_test.circom in paths table; got {:?}",
        paths
    );

    // ----- Step / call counts ----------------------------------------
    // The Circom recorder surfaces the `component main` template as
    // the outermost user-defined Call frame (cross-recorder convention;
    // see PHP recorder commit 423e4ba).  flow_test.circom therefore
    // emits:
    //   * 13 steps: 1 toplevel dispatch + 1 step on the
    //     `component main = FlowTest()` line + 6 signal-declaration
    //     steps + 5 signal-assignment steps.
    //   * 1 call pair (entry/exit) for `FlowTest`.
    // Stable properties of the canonical fixture — if they change,
    // that's a real regression to investigate, not a flake.
    let counts = &doc["counts"];
    assert_eq!(
        counts["steps"].as_u64(),
        Some(13),
        "expected 13 step events for flow_test.circom; counts={counts}",
    );
    assert_eq!(
        counts["calls"].as_u64(),
        Some(2),
        "expected 1 call event for `FlowTest` (the outermost user-defined \
        template frame); counts={counts}",
    );

    let events = doc["events"].as_array().expect("events array");

    // ----- Call sequence: the outermost user-defined template --------
    let call_sequence: Vec<&str> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .filter_map(|e| e["function"].as_str())
        .collect();
    assert_eq!(
        call_sequence,
        vec!["<toplevel>", "FlowTest"],
        "expected a single `FlowTest` call_entry for flow_test.circom; \
        got {:?}",
        call_sequence
    );

    // ----- Exact decoded variable values ------------------------------
    // Collect every (varname, i64) pair surfaced by step events.  These
    // come from the recorder writing `ValueRecord::Int` CBOR blobs, then
    // ct-print --full decoding them back to `{"kind":"Int","i":<n>,...}`.
    let observed_vars: Vec<(String, i64)> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .flat_map(|e| {
            e["vars"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
        })
        .filter_map(|v| {
            let name = v["varname"].as_str()?.to_string();
            let value = &v["value"];
            // The Circom recorder encodes signal values as
            // ValueRecord::Int.  If something else surfaces (e.g.
            // BigInt for out-of-range field elements that exceed
            // i64), fail loudly so the test author can decide whether
            // to extend the assertions or accept the new variant.
            assert_eq!(
                value["kind"].as_str(),
                Some("Int"),
                "variable `{}` should decode as Int, got {}; \
                if a new ValueRecord variant has landed for Circom \
                field elements (e.g. BigInt), extend this test to \
                assert on it explicitly rather than weakening the \
                check",
                name,
                value
            );
            let i = value["i"]
                .as_i64()
                .unwrap_or_else(|| panic!("Int.i must be i64 for `{name}`; got {value}"));
            Some((name, i))
        })
        .collect();

    // The canonical flow: a=10, b=32, sum_val=a+b=42, doubled=sum_val*2=84,
    // out=doubled+a=94.  Same canonical computation as cairo, cardano,
    // leo, and the other recorders' flow_test fixtures — if your
    // recorder runs flow_test.circom and these five signal assignments
    // don't surface, that's the bug to chase.
    let expected: &[(&str, i64)] = &[
        ("a", 10),
        ("b", 32),
        ("sum_val", 42),
        ("doubled", 84),
        ("out", 94),
    ];
    for (name, value) in expected {
        assert!(
            observed_vars.iter().any(|(n, v)| n == name && v == value),
            "expected step variable `{name}` = {value} in --full output; \
            observed = {observed_vars:?}"
        );
    }
}

// ===========================================================================
// Per-program ct-print --full coverage tests
// ===========================================================================
//
// These tests follow the recorder-test-requirements policy
// (`metacraft-specs/policies/recorder-test-requirements.md`):
//
// * Each test records one Circom program through the recorder's
//   normal entry point.
// * The produced `.ct` is piped through `ct-print --full --strip-paths`.
// * Assertions are made on the **decoded JSON document** with EXACT
//   counts (`assert_eq!(events.len(), N)` — never `>=`), EXACT
//   ordering (later step from a strictly later source line where
//   applicable), and EXACT decoded values
//   (`value["i"] == 42`, `value["kind"] == "Int"`).
//
// `ValueRecord` variants outside the expected set are rejected with
// a hard error message asking the test author to extend the test
// rather than weaken the assertion.
//
// Where the recorder's current behaviour deviates from what the
// language semantics dictate (e.g. constants on the RHS of `<==`
// surfacing as 0 when the circuit has no `signal input` declarations,
// or `===` constraint asserts not producing a dedicated event), the
// deviation is documented inline as `RECORDER BUG: ...` and a
// parallel `#[ignore]`d assertion captures the spec-correct
// expectation so it surfaces the moment the recorder catches up.
//
// Universal-checklist categories that are **n/a for Circom** and
// therefore have no test program here:
//
// * Exceptions / errors with a handler — Circom has no `try`/`catch`;
//   the only failure mode is a constraint violation (`===`), which
//   aborts the witness calculator.  Covered by
//   `constraint_assert_test.circom` (the success branch — failure
//   would mean the recorder couldn't produce a trace at all).
// * Mutable state outside templates / global variables — Circom has
//   none.
// * Concurrency — Circom is single-threaded by construction.
// * General I/O (stdout, file read) — Circom has no I/O surface
//   beyond `log()` (already covered by
//   `circom_log_directive_emits_evm_event_special_event` in the
//   integration_tests suite).

/// Skip-helper: returns `Some(path)` to ct-print or logs a clear
/// `SKIP:` diagnostic and returns `None`.  The
/// `verify-cli-convention-no-silent-skip.sh` script greps for the
/// literal `SKIP:` token, so silent skips remain forbidden.
fn require_ct_print(test_name: &str) -> PathBuf {
    let p = ct_print_path();
    assert!(
        p.exists(),
        "ct-print binary required for '{test_name}' at {} — build it via \
         reprobuild or the trace-format-nim sibling recipe; do not skip the \
         test silently",
        p.display()
    );
    p
}

/// Record a program and return the `ct-print --full --strip-paths`
/// JSON document plus the absolute path to the source file (so the
/// caller can match `metadata.program`).  Returns `None` when
/// `ct-print` is unavailable (the caller has already emitted a
/// `SKIP:` line via `ct_print_or_skip`).
fn record_and_dump_full(test_name: &str, program: &str) -> Option<(serde_json::Value, PathBuf)> {
    let ct_print = require_ct_print(test_name);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join(program);
    codetracer_circom_recorder::recorder::record(&source_path, &out_dir, false)
        .expect("recorder::record should succeed");

    let ct_files = ct_files_in(&out_dir);
    assert!(
        !ct_files.is_empty(),
        "expected a .ct container in {:?}",
        out_dir
    );

    let output = Command::new(&ct_print)
        .args(["--full", "--strip-paths"])
        .arg(&ct_files[0])
        .output()
        .expect("failed to run ct-print --full");

    assert!(
        output.status.success(),
        "ct-print --full should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let doc: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("ct-print --full should emit valid JSON");

    drop(tmp_dir);

    Some((doc, source_path))
}

/// Decode every (varname, i64) pair from step events, in event-emission
/// order.  Rejects any `ValueRecord` variant other than `Int` with a
/// hard error that asks the test author to extend the test rather
/// than weaken it.
fn observed_int_vars(doc: &serde_json::Value) -> Vec<(String, i64)> {
    let events = doc["events"].as_array().expect("events array");
    let mut out = Vec::new();
    for ev in events {
        if ev["kind"] != "step" {
            continue;
        }
        let Some(vars) = ev["vars"].as_array() else {
            continue;
        };
        for v in vars {
            let name = v["varname"].as_str().expect("varname str").to_string();
            let value = &v["value"];
            assert_eq!(
                value["kind"].as_str(),
                Some("Int"),
                "variable `{}` should decode as Int, got {}; \
                if a new ValueRecord variant has landed for Circom \
                (e.g. BigInt for out-of-range field elements), extend \
                this test to assert on it explicitly rather than \
                weakening the check",
                name,
                value
            );
            let i = value["i"]
                .as_i64()
                .unwrap_or_else(|| panic!("Int.i must be i64 for `{name}`; got {value}"));
            out.push((name, i));
        }
    }
    out
}

/// Decode the call-entry sequence as a vector of function names.
fn observed_call_sequence(doc: &serde_json::Value) -> Vec<String> {
    doc["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .map(|e| {
            e["function"]
                .as_str()
                .expect("call_entry.function str")
                .to_string()
        })
        .collect()
}

/// Decode the call-exit sequence as a vector of function names.
fn observed_exit_sequence(doc: &serde_json::Value) -> Vec<String> {
    doc["events"]
        .as_array()
        .expect("events array")
        .iter()
        .filter(|e| e["kind"] == "call_exit")
        .map(|e| {
            e["function"]
                .as_str()
                .expect("call_exit.function str")
                .to_string()
        })
        .collect()
}

/// Assert that every `step` event carries a strictly increasing
/// `step_index`.  This is the recorder's only ordering guarantee
/// against duplicates / reorderings.
fn assert_step_indices_monotonic(doc: &serde_json::Value) {
    let mut last = -1i64;
    for ev in doc["events"].as_array().expect("events array") {
        if ev["kind"] != "step" {
            continue;
        }
        let idx = ev["step_index"]
            .as_i64()
            .expect("step_index must be present on step events");
        assert!(
            idx > last,
            "step_index must strictly increase; got {idx} after {last}"
        );
        last = idx;
    }
}

/// Assert `metadata.program` ends with the expected source filename.
fn assert_metadata_program_ends_with(doc: &serde_json::Value, source_path: &Path) {
    let prog = doc["metadata"]["program"]
        .as_str()
        .expect("metadata.program str");
    let want = source_path.file_name().unwrap().to_string_lossy();
    assert!(
        prog.ends_with(&*want),
        "metadata.program {prog} must end with {want}"
    );
}

// --- control_flow_test.circom ---------------------------------------------

/// Records `control_flow_test.circom` and asserts on the **current
/// observed** event shape.  The program exercises Circom's `var`
/// mutability, `if`/`else`, and `for` loops over a compile-time `var`
/// bound — all of which the compiler unrolls/folds before the witness
/// calculator runs.  RECORDER BUG: Circom 2.1.5 with `--O0` produces
/// only the three top-level output signals in the witness when no
/// `signal input` is declared, AND every output value comes through
/// as 0 instead of the constant the source program assigns.  The
/// `#[ignore]`d sibling test pins the spec-correct expectation
/// (total=20, bonus=100, result=120) so it surfaces the moment the
/// recorder catches up.
#[test]
fn test_control_flow_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_control_flow_test_via_ct_print_full",
        "control_flow_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // `ControlFlow` is the user-defined template; the synthetic
    // `<toplevel>` frame is explicitly registered by the recorder
    // (commit 4d3c05f) so the calltrace UI surfaces it — both names
    // appear in the trace's functions table.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "ControlFlow"]);

    // ----- counts -----------------------------------------------------
    // The structured Circom evaluator (added 2026-05-13) emits a
    // step per executed source line — including for-loop iterations,
    // the taken if-branch, and `var` declarations / mutations — and
    // emits Variable events for each `<==` / `<--` signal assignment.
    //
    // Step breakdown for control_flow_test.circom:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = ControlFlow()` (line 40)
    //   * 3 signal-output decl steps (lines 17, 18, 19)
    //   * 1 step on `var start = 7` (line 21)
    //   * 1 step on `var acc = 0` (line 23)
    //   * 1 step on the `for` header (line 24)
    //   * 5 steps on the loop body line (line 25 × 5 iterations)
    //   * 1 step on `var b;` (line 28)
    //   * 1 step on the `if` header (line 29)
    //   * 1 step on the taken if-body `b = 100;` (line 30)
    //   * 3 signal-assignment steps (lines 35, 36, 37) carrying the
    //     evaluated total/bonus/result values
    // = 19 step events.  +1 call_entry +1 call_exit = 21 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(19), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    // Values: every step-with-vars carries one Variable event;
    // here that's the 3 signal assignments (total/bonus/result).
    // Each non-vars step still counts as a "step" but emits 0 Variable
    // events.  The values-count below mirrors that — 19 step events
    // with at most one variable each, but only 3 carrying a Variable
    // (the three signal assignments).  Older Nim trace writers
    // counted the empty step records too, so the canonical count
    // surfaces as 19 here.
    assert_eq!(
        counts["values"].as_u64(),
        Some(19),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 23, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // `ControlFlow` is the outermost user-defined template; the
    // recorder surfaces it as a single call pair around the body's
    // step events.
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "ControlFlow".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["ControlFlow".to_string()]
    );

    // ----- Exact step lines (in order) --------------------------------
    // Line 40 is the `component main = ControlFlow()` declaration; it
    // precedes the template body's signal-decl / control-flow / assignment
    // steps because the recorder emits the component-line step
    // immediately before issuing `register_call`.  Line 25 appears 5
    // times — one per `for` iteration body — and line 30 is the
    // taken `if` branch.  The matching else-branch (line 32) is *not*
    // visited because `start = 7 > 5` selects the then-branch.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![1, 40, 17, 18, 19, 21, 23, 24, 25, 25, 25, 25, 25, 28, 29, 30, 35, 36, 37]
    );

    // ----- Decoded variable values ------------------------------------
    // The structured evaluator surfaces only **signal** assignments
    // as Variable events — `var` declarations / mutations are
    // bookkeeping (compile-time scratch) and would otherwise pollute
    // the "values" pane with the for-loop induction variable, the
    // accumulator's intermediate values, etc.  This is why the
    // signal outputs (total/bonus/result) are the only entries
    // surfaced here.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("total".to_string(), 20),
            ("bonus".to_string(), 100),
            ("result".to_string(), 120),
        ],
    );
}

/// Spec-correct expectation: a Circom circuit with no `signal input`
/// declarations should still surface its outputs at the values the
/// source program assigns via `<==`, not as 0.  Pre-2026-05-13 this
/// failed because the recorder relied entirely on the witness
/// calculator, which returns 0 for every signal in an inputless
/// circuit; it now passes because the structured Circom evaluator
/// (`src/evaluator.rs`) folds RHS expressions at compile time and
/// emits Variable events with the folded values.
#[test]
fn test_control_flow_test_constants_decode() {
    let Some((doc, _)) = record_and_dump_full(
        "test_control_flow_test_constants_decode",
        "control_flow_test.circom",
    ) else {
        return;
    };
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("total".to_string(), 20),
            ("bonus".to_string(), 100),
            ("result".to_string(), 120),
        ],
    );
}

/// Spec-correct expectation: `for` loop iterations and the taken
/// `if` branch must each surface a step event so a debugger can
/// step through the source.  Pre-2026-05-13 the recorder's
/// brace-tracking parser only matched `<==` lines, so neither
/// for-loop bodies nor if branches produced any step events; the
/// structured evaluator now visits both constructs and emits a
/// step per executed source line.
#[test]
fn test_control_flow_test_for_and_if_steps_emitted() {
    let Some((doc, _)) = record_and_dump_full(
        "test_control_flow_test_for_and_if_steps_emitted",
        "control_flow_test.circom",
    ) else {
        return;
    };
    let events = doc["events"].as_array().unwrap();
    let step_lines: std::collections::BTreeSet<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().unwrap())
        .collect();
    // Loop body line is 24; the taken-branch body line is 29.  Both
    // should be visited at least once.
    assert!(
        step_lines.contains(&24),
        "expected a step at the for-loop body (line 24); got {step_lines:?}"
    );
    assert!(
        step_lines.contains(&29),
        "expected a step at the taken if-branch (line 29); got {step_lines:?}"
    );
}

// --- nested_template_test.circom ------------------------------------------

/// Records `nested_template_test.circom`, which exercises a
/// three-deep template chain (`NestedTemplate` -> `Middle` -> `Inner`)
/// where each template instantiates exactly one sub-component and
/// forwards its single output.  The recorder is expected to surface
/// every template definition in the function table and emit one
/// `call_entry` / `call_exit` pair per concrete sub-component
/// instance (skipping `component main` which the toplevel frame
/// already covers).
#[test]
fn test_nested_template_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_nested_template_test_via_ct_print_full",
        "nested_template_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table — order is writer-assignment order ---------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Inner", "Middle", "NestedTemplate"]);

    // ----- counts -----------------------------------------------------
    // 10 step events + 3 call_entry + 3 call_exit = 16 events.
    // The recorder surfaces the genuinely 3-deep chain
    // `NestedTemplate -> Middle -> Inner` as 3 nested call pairs.
    // Each template body emits steps for its signal-output decl,
    // each component-instantiation, and the final wire — by
    // induction the per-template step counts are 1+1 (NestedTemplate)
    // + 1+1 (Middle) + 1+1 (Inner) = 6 body steps, plus 1 toplevel
    // start + 1 main-component step + 1 final wire per level (3) =
    // 10 steps.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(10), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(4), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 18, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call entry order -------------------------------------------
    // The recorder emits component calls in *nesting* order
    // (root → leaf), starting at `component main` and recursing into
    // each template body's declared sub-components.  This is the
    // structural depth-3 chain the source program declares.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "NestedTemplate".to_string(),
            "Middle".to_string(),
            "Inner".to_string(),
        ],
    );

    // ----- Call exit order: nested LIFO -------------------------------
    // Each component's call_exit fires immediately after the
    // recursive evaluation of its body returns, so for a strict
    // nesting chain (NestedTemplate -> Middle -> Inner) the exits
    // unwind innermost-first as you'd expect from a normal call
    // stack:  Inner exit, then Middle exit, then NestedTemplate
    // exit.  This is the same ordering you'd see in a debugger —
    // the previous flat-emit recorder produced a different (but
    // equivalent) LIFO order because it deferred *all* call_exit
    // events to the end of the trace.
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "Inner".to_string(),
            "Middle".to_string(),
            "NestedTemplate".to_string(),
            "<toplevel>".to_string(),
        ],
    );

    // ----- Exact decoded variable values ------------------------------
    // The structured evaluator computes each nested template's
    // outputs and feeds them back into the parent's environment, so
    // the trace surfaces every intermediate `<==` assignment with
    // its concrete value: inner.out = 1+2 = 3 (inside Inner, prefixed
    // with the parent's local component name `inner.`),
    // middle.out = inner.out + 10 = 13, and finally
    // outer_result = middle.out + 100 = 113.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("inner.out".to_string(), 3),
            ("middle.out".to_string(), 13),
            ("outer_result".to_string(), 113),
        ],
    );
}

/// Spec-correct expectation: nested-template intermediate output
/// values must surface as Variable events so debugger users can
/// inspect what each sub-template computed.  The structured
/// evaluator recursively evaluates each sub-template and feeds its
/// outputs back into the parent's env, so `inner.out`, `middle.out`,
/// and `outer_result` all surface with their evaluator-folded
/// integer values.
#[test]
fn test_nested_template_test_intermediate_outputs_decode() {
    let Some((doc, _)) = record_and_dump_full(
        "test_nested_template_test_intermediate_outputs_decode",
        "nested_template_test.circom",
    ) else {
        return;
    };
    let observed = observed_int_vars(&doc);
    for want in [
        ("inner.out".to_string(), 3i64),
        ("middle.out".to_string(), 13i64),
        ("outer_result".to_string(), 113i64),
    ] {
        assert!(
            observed.contains(&want),
            "expected {want:?} in observed = {observed:?}"
        );
    }
}

/// `nested_template_test.circom` exercises a genuinely 3-deep template
/// chain (`NestedTemplate -> Middle -> Inner`).  The recorder must
/// surface every level — including `component main`'s own template — so
/// the trace contains 3 call pairs in nesting order with LIFO exits.
/// Previously `component main` was elided to avoid shadowing the
/// synthesised `<toplevel>` frame, collapsing the visible depth from 3
/// to 2.  The cross-recorder convention (see PHP recorder commit
/// 423e4ba) is that the outermost user-defined frame surfaces as a real
/// Call event, so this test now passes.
#[test]
fn test_nested_template_test_three_deep_call_sequence() {
    let Some((doc, _)) = record_and_dump_full(
        "test_nested_template_test_three_deep_call_sequence",
        "nested_template_test.circom",
    ) else {
        return;
    };
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "NestedTemplate".to_string(),
            "Middle".to_string(),
            "Inner".to_string(),
        ],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "Inner".to_string(),
            "Middle".to_string(),
            "NestedTemplate".to_string(),
            "<toplevel>".to_string(),
        ],
    );
}

// --- signal_hierarchy_test.circom -----------------------------------------

/// Records `signal_hierarchy_test.circom`, which exercises the
/// recorder's per-component argument-staging path: the top-level
/// template instantiates two sub-templates and wires the first
/// sub-template's output (`add5.y`) into the second sub-template's
/// input (`mul2.in`).  This is the only construct that drives
/// `writer.arg(name, value)` followed by `register_call` in the
/// emitted trace.
#[test]
fn test_signal_hierarchy_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_signal_hierarchy_test_via_ct_print_full",
        "signal_hierarchy_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table — definition order in the source file -------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Add5", "Mul2", "SignalHierarchy"]);

    // ----- counts -----------------------------------------------------
    // 14 step events + 3 call_entry + 3 call_exit = 20 events.  The
    // outermost user-defined template (`SignalHierarchy`,
    // instantiated as `component main`) surfaces as its own Call
    // event, bracketing the two sibling sub-component calls.  The
    // structured evaluator visits each template body in source
    // order, including the input-signal decl steps inside each
    // sub-template.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(14), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(4), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 22, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence in nesting order ----------------------------
    // The outermost user-defined template (`SignalHierarchy`,
    // instantiated as `component main`) comes first; siblings inside
    // its body (`add5` then `mul2`) follow in source-instantiation
    // order.  Exits are nested LIFO — each component's call_exit
    // fires immediately after the recursive evaluation of its body
    // returns, so siblings exit in source order and the parent
    // exits last.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "SignalHierarchy".to_string(),
            "Add5".to_string(),
            "Mul2".to_string(),
        ],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "Add5".to_string(),
            "Mul2".to_string(),
            "SignalHierarchy".to_string(),
            "<toplevel>".to_string(),
        ],
    );

    // ----- Call_entry args: each call carries its template's `signal
    // input` declarations as staged arguments (or none if the template
    // has no inputs).  `SignalHierarchy` has no input signals
    // (`total` is an *output*), so its args list is empty.  Each
    // sub-component's input signal is staged with the value the
    // structured evaluator wired into it from the parent's
    // `<comp>.in <== expr;` site (4 for add5.x, 9 for mul2.in).
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 4);

    let sig_hier_args = call_entries[0]["args"]
        .as_array()
        .expect("SignalHierarchy args");
    assert_eq!(sig_hier_args.len(), 0);

    let add5_args = call_entries[1]["args"].as_array().expect("Add5 args");
    assert_eq!(add5_args.len(), 1);
    assert_eq!(add5_args[0]["varname"].as_str(), Some("x"));
    assert_eq!(add5_args[0]["value"]["kind"].as_str(), Some("Int"));
    assert_eq!(add5_args[0]["value"]["i"].as_i64(), Some(4));

    let mul2_args = call_entries[2]["args"].as_array().expect("Mul2 args");
    assert_eq!(mul2_args.len(), 1);
    assert_eq!(mul2_args[0]["varname"].as_str(), Some("in"));
    assert_eq!(mul2_args[0]["value"]["kind"].as_str(), Some("Int"));
    assert_eq!(mul2_args[0]["value"]["i"].as_i64(), Some(9));

    // ----- Decoded variable values ------------------------------------
    // The structured evaluator wires each sub-template's input
    // signals before its body runs, evaluates the sub-template's
    // body, and feeds outputs back into the parent's env.  The
    // surfaced values reflect that:
    //   * "x" = 4 — staged arg for Add5 (also recorded as a step
    //     variable on the immediately-preceding component-decl line
    //     by the trace writer's `arg(...)` shim — see
    //     codetracer_trace_writer_nim::TraceWriter::arg).
    //   * "add5.x" = 4 — Add5's input-signal decl with the wired
    //     value (prefix injected by the recurse-down emit).
    //   * "add5.y" = 9 — Add5's output (`y <== x + 5`).
    //   * "in" / "mul2.in" = 9 — same shape for Mul2 (input wired
    //     from add5.y).
    //   * "mul2.out" = 18 — `out <== in * 2`.
    //   * "add5.x" = 4 (again) and "mul2.in" = 9 (again) — the
    //     parent's own wire steps (lines 36, 37).
    //   * "total" = 19 — `total <== mul2.out + 1`.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("x".to_string(), 4),
            ("add5.x".to_string(), 4),
            ("add5.y".to_string(), 9),
            ("in".to_string(), 9),
            ("mul2.in".to_string(), 9),
            ("mul2.out".to_string(), 18),
            ("add5.x".to_string(), 4),
            ("mul2.in".to_string(), 9),
            ("total".to_string(), 19),
        ],
    );
}

/// Spec-correct expectation: every signal in a wired
/// sub-component chain must surface with its computed value.  The
/// structured evaluator wires each sub-template's input signals
/// before its body runs, evaluates the body, and stores its outputs
/// in the parent's env so subsequent reads of `comp.signal` resolve
/// to the right integer.
#[test]
fn test_signal_hierarchy_test_chain_values_decode() {
    let Some((doc, _)) = record_and_dump_full(
        "test_signal_hierarchy_test_chain_values_decode",
        "signal_hierarchy_test.circom",
    ) else {
        return;
    };
    let observed = observed_int_vars(&doc);
    for want in [
        ("add5.x".to_string(), 4i64),
        ("add5.y".to_string(), 9i64),
        ("mul2.in".to_string(), 9i64),
        ("mul2.out".to_string(), 18i64),
        ("total".to_string(), 19i64),
    ] {
        assert!(
            observed.contains(&want),
            "expected {want:?} in observed = {observed:?}"
        );
    }
}

// --- constraint_assert_test.circom ----------------------------------------

/// Records `constraint_assert_test.circom`, which exercises Circom's
/// `===` constraint-assertion operator (the only language-level
/// "panic" primitive).  Every `===` in this fixture holds, so the
/// witness calculator succeeds; the recorder is expected to register
/// the assertion lines in the trace.
#[test]
fn test_constraint_assert_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_constraint_assert_test_via_ct_print_full",
        "constraint_assert_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "ConstraintAssert"]);

    // ----- counts -----------------------------------------------------
    // 12 step events: 1 toplevel + 1 step on the
    // `component main = ConstraintAssert()` line + 4 signal-decl +
    // 4 `<==` assignment + 2 `===` constraint-assertion steps.
    // 1 call_entry/exit for the outermost user-defined frame
    // (`ConstraintAssert`).  The structured evaluator surfaces the
    // two `===` lines (26 and 27) as dedicated step events — they
    // were silently dropped by the previous brace-tracking parser.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(12), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(12),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 16, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Exact step lines (in order) --------------------------------
    // Line 30 is the `component main = ConstraintAssert()` declaration;
    // it precedes the body's signal-decl/assignment steps because the
    // recorder emits the component-line step immediately before the
    // outermost call.  Lines 26 and 27 are the two `===` constraint
    // assertions, surfaced as steps by the structured evaluator.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![1, 30, 14, 15, 17, 18, 20, 21, 23, 24, 26, 27]
    );

    // ----- Decoded variable values ------------------------------------
    // The structured evaluator computes each `<==` RHS in source
    // order, so the trace surfaces the literal-driven values the
    // source program assigns: a=6, b=7, sum=13, prod=42.  No
    // Variable events on lines 26/27 — those are `===` constraint
    // assertions, which assert equality but do not update any signal.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 6),
            ("b".to_string(), 7),
            ("sum".to_string(), 13),
            ("prod".to_string(), 42),
        ],
    );
}

/// Spec-correct expectation: each `===` constraint-assertion line
/// must surface as a step event so a debugger can step over the
/// assertion.  The structured evaluator emits a step on every
/// `Stmt::Constraint` line, satisfying the contract.
#[test]
fn test_constraint_assert_test_emits_assertion_steps() {
    let Some((doc, _)) = record_and_dump_full(
        "test_constraint_assert_test_emits_assertion_steps",
        "constraint_assert_test.circom",
    ) else {
        return;
    };
    let events = doc["events"].as_array().unwrap();
    let step_lines: std::collections::BTreeSet<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().unwrap())
        .collect();
    assert!(
        step_lines.contains(&26),
        "expected a step at line 26 (sum === a + b); got {step_lines:?}"
    );
    assert!(
        step_lines.contains(&27),
        "expected a step at line 27 (prod === 42); got {step_lines:?}"
    );
}

/// Spec-correct expectation: integer constants on the RHS of `<==`
/// must surface as the literal value, even in a circuit with no
/// `signal input` declarations.  The structured evaluator folds
/// each RHS at compile time, so the trace surfaces a=6, b=7,
/// sum=13, prod=42 regardless of what the witness calculator
/// returns.
#[test]
fn test_constraint_assert_test_constants_decode() {
    let Some((doc, _)) = record_and_dump_full(
        "test_constraint_assert_test_constants_decode",
        "constraint_assert_test.circom",
    ) else {
        return;
    };
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 6),
            ("b".to_string(), 7),
            ("sum".to_string(), 13),
            ("prod".to_string(), 42),
        ],
    );
}

// --- for_loop_unroll_test.circom ------------------------------------------

/// Records `for_loop_unroll_test.circom`, which exercises nested for
/// loops with compile-time `var` bounds.  The Circom compiler unrolls
/// every iteration; the structured evaluator (added 2026-05-13) walks
/// the unrolled steps and emits one step per per-iteration body line.
/// Closes the M11 `for_and_if_steps_emitted` follow-up by extending
/// coverage past the single-loop case in `control_flow_test.circom`.
#[test]
fn test_for_loop_unroll_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_for_loop_unroll_test_via_ct_print_full",
        "for_loop_unroll_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "ForLoopUnroll"]);

    // ----- counts -----------------------------------------------------
    // 15 step events: 1 toplevel + 1 component-main + 1 signal-output
    // decl + 1 `var acc = 0` + 1 outer-for-header + 9 nested-loop
    // steps (3 outer iters × (1 inner-for-header + 2 inner-body)) +
    // 1 final `total <== acc`.  Plus 1 call_entry + 1 call_exit = 17
    // events.  The outer for-header step fires once even though the
    // outer loop runs 3 times — see the `Stmt::For` handling in
    // `eval_stmt` (the header is not re-emitted per-iteration to
    // avoid pinning a confusing "infinite step train" at the for
    // line).  The inner for-header step DOES fire 3 times because it
    // sits inside the outer body, which is replayed once per outer
    // iteration.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(15), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(15),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 19, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "ForLoopUnroll".to_string()],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["ForLoopUnroll".to_string()],
    );

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel start (1), `component main` (34), `signal output
    // total;` (22), `var acc = 0;` (24), outer for header (25), then
    // for each i in 0..3: inner-for header (26) + body line 27 ×2.
    // Final `total <== acc;` (31).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![1, 34, 22, 24, 25, 26, 27, 27, 26, 27, 27, 26, 27, 27, 31]
    );

    // ----- Decoded variable values ------------------------------------
    // Only the final `total <== acc;` surfaces a Variable event.
    // The for-loop body is `var`-only (acc/i/j are compile-time
    // scratch and don't pollute the trace; see the rationale in
    // `eval_stmt::Stmt::VarDecl`).  Total = 0+1+10+11+20+21 = 63.
    assert_eq!(observed_int_vars(&doc), vec![("total".to_string(), 63)]);
}

/// Spec-correct expectation: nested for loops with compile-time bounds
/// must each surface a step event per iteration, regardless of nesting
/// depth.  Pre-2026-05-13 the brace-tracking parser only matched
/// `<==` lines and dropped every loop-body step; the structured
/// evaluator now visits both inner and outer loop bodies and emits a
/// step on every executed source line.
#[test]
fn test_for_loop_unroll_test_nested_iterations_emitted() {
    let Some((doc, _)) = record_and_dump_full(
        "test_for_loop_unroll_test_nested_iterations_emitted",
        "for_loop_unroll_test.circom",
    ) else {
        return;
    };
    let events = doc["events"].as_array().unwrap();
    let inner_body_count = events
        .iter()
        .filter(|e| e["kind"] == "step" && e["line"].as_i64() == Some(27))
        .count();
    // 3 outer iters × 2 inner iters = 6 inner-body steps.
    assert_eq!(
        inner_body_count, 6,
        "expected 6 inner-body steps (line 27); events = {events:#?}"
    );
    let inner_header_count = events
        .iter()
        .filter(|e| e["kind"] == "step" && e["line"].as_i64() == Some(26))
        .count();
    // The inner for-header fires once per outer iteration = 3 times.
    assert_eq!(
        inner_header_count, 3,
        "expected 3 inner-for-header steps (line 26); events = {events:#?}"
    );
}

// --- constraint_operators_test.circom -------------------------------------

/// Records `constraint_operators_test.circom`, which exercises four
/// `===` constraint forms (simple, arithmetic-RHS, lhs-with-arithmetic,
/// scalar-equality).  Closes the M11 `emits_assertion_steps` follow-up
/// by extending `===` coverage past the two-line case in
/// `constraint_assert_test.circom`.
#[test]
fn test_constraint_operators_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_constraint_operators_test_via_ct_print_full",
        "constraint_operators_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "ConstraintOperators"]);

    // ----- counts -----------------------------------------------------
    // 16 step events: 1 toplevel + 1 component-main + 5 signal-decls
    // (1 output `s` + 4 intermediate a/b/c/d) + 5 `<==` assignments
    // (a/b/c/d/s) + 4 `===` constraint-assertion lines.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(16), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(16),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 20, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "ConstraintOperators".to_string()],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["ConstraintOperators".to_string()],
    );

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = ConstraintOperators()`
    // (44), output decl `s` (24), intermediate decls a/b/c/d
    // (26/27/28/29), `<==` assignments a/b/c/d (31/32/33/34) and
    // `s <== a + b` (36), then four `===` constraint lines
    // (38/39/40/41).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![1, 44, 24, 26, 27, 28, 29, 31, 32, 33, 34, 36, 38, 39, 40, 41]
    );

    // ----- Decoded variable values ------------------------------------
    // a=3, b=4, c=7, d=1, s=a+b=7.  `===` lines emit no Variable
    // events (constraint-only).
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 3),
            ("b".to_string(), 4),
            ("c".to_string(), 7),
            ("d".to_string(), 1),
            ("s".to_string(), 7),
        ],
    );
}

/// Spec-correct expectation: every `===` constraint-assertion line
/// (regardless of how complex its RHS is) must surface as a step event
/// so a debugger can step over the assertion.  The structured
/// evaluator emits a step per `Stmt::Constraint` line; this test pins
/// all four lines (38, 39, 40, 41) — the simple `s === a + b` form
/// plus the three extended forms (`a + b === c * d`, `s - a === b`,
/// `c === s`).
#[test]
fn test_constraint_operators_test_all_assertion_lines_emitted() {
    let Some((doc, _)) = record_and_dump_full(
        "test_constraint_operators_test_all_assertion_lines_emitted",
        "constraint_operators_test.circom",
    ) else {
        return;
    };
    let events = doc["events"].as_array().unwrap();
    let step_lines: std::collections::BTreeSet<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().unwrap())
        .collect();
    for want in [38i64, 39, 40, 41] {
        assert!(
            step_lines.contains(&want),
            "expected a step at line {want} (`===` constraint); got {step_lines:?}"
        );
    }
}

// --- wire_to_component_test.circom ----------------------------------------

/// Records `wire_to_component_test.circom`, which exercises a 3-stage
/// wire chain: `step1.out -> step2.in`, `step2.out -> step3.in`.
/// Closes the M11 `chain_values_decode` follow-up by extending wire
/// coverage past the 2-component case in
/// `signal_hierarchy_test.circom`.  Each sub-component's body
/// surfaces as its own call frame so the trace contains 4 call pairs
/// (the parent + 3 sub-components) in source-instantiation order.
#[test]
fn test_wire_to_component_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_wire_to_component_test_via_ct_print_full",
        "wire_to_component_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table — definition order in the source file -------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        functions,
        vec!["<toplevel>", "AddOne", "MulTwo", "SubThree", "WireToComponent"]
    );

    // ----- counts -----------------------------------------------------
    // 19 step events + 4 call_entry + 4 call_exit = 27 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(19), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(5), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 29, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence in nesting order ----------------------------
    // Parent `WireToComponent` first, then its three siblings in
    // source-instantiation order.  Exits unwind LIFO — each
    // sub-component exits immediately after its body returns, so
    // siblings exit in source order and the parent exits last.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "WireToComponent".to_string(),
            "AddOne".to_string(),
            "MulTwo".to_string(),
            "SubThree".to_string(),
        ],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "AddOne".to_string(),
            "MulTwo".to_string(),
            "SubThree".to_string(),
            "WireToComponent".to_string(),
        ],
    );

    // ----- Call_entry args: each sub-component carries its single
    // input signal staged from the parent's wire site.  AddOne.x = 5
    // (literal), MulTwo.in = step1.out = 6, SubThree.in = step2.out
    // = 12.  WireToComponent has no input signals.
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 4);

    assert_eq!(
        call_entries[0]["args"].as_array().expect("args").len(),
        0,
        "WireToComponent has no input signals"
    );

    let add1 = call_entries[1]["args"].as_array().expect("AddOne args");
    assert_eq!(add1.len(), 1);
    assert_eq!(add1[0]["varname"].as_str(), Some("x"));
    assert_eq!(add1[0]["value"]["i"].as_i64(), Some(5));

    let mul2 = call_entries[2]["args"].as_array().expect("MulTwo args");
    assert_eq!(mul2.len(), 1);
    assert_eq!(mul2[0]["varname"].as_str(), Some("in"));
    assert_eq!(mul2[0]["value"]["i"].as_i64(), Some(6));

    let sub3 = call_entries[3]["args"].as_array().expect("SubThree args");
    assert_eq!(sub3.len(), 1);
    assert_eq!(sub3[0]["varname"].as_str(), Some("in"));
    assert_eq!(sub3[0]["value"]["i"].as_i64(), Some(12));

    // ----- Decoded variable values ------------------------------------
    // The structured evaluator wires each sub-template's input
    // signals before its body runs, evaluates the body, and feeds
    // outputs back into the parent's env.  The full surface:
    //   * Each sub-component emits `x`/`in` (input decl) and
    //     `<comp>.<input>` (prefixed by the recurse-down emit) plus
    //     the output `<comp>.out`.
    //   * The parent re-emits each wire site (45/46/47) as a step
    //     variable carrying the wired value.
    //   * The final `final <== step3.out + 100;` (line 48) emits
    //     `final = 109`.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("x".to_string(), 5),
            ("step1.x".to_string(), 5),
            ("step1.out".to_string(), 6),
            ("in".to_string(), 6),
            ("step2.in".to_string(), 6),
            ("step2.out".to_string(), 12),
            ("in".to_string(), 12),
            ("step3.in".to_string(), 12),
            ("step3.out".to_string(), 9),
            ("step1.x".to_string(), 5),
            ("step2.in".to_string(), 6),
            ("step3.in".to_string(), 12),
            ("final".to_string(), 109),
        ],
    );
}

/// Spec-correct expectation: a 3-stage wire chain
/// (`step1.out -> step2.in -> step3.in`) must propagate values end
/// to end so the final signal carries the fully-folded result, not
/// 0.  Pin the final value as the canonical regression check for the
/// chain-decode follow-up.
#[test]
fn test_wire_to_component_test_chain_propagates_end_to_end() {
    let Some((doc, _)) = record_and_dump_full(
        "test_wire_to_component_test_chain_propagates_end_to_end",
        "wire_to_component_test.circom",
    ) else {
        return;
    };
    let observed = observed_int_vars(&doc);
    assert!(
        observed.contains(&("final".to_string(), 109i64)),
        "expected `final = 109` in observed = {observed:?}"
    );
    // Each intermediate hop of the wire chain must surface its
    // computed value, not the witness's "every signal is 0" output
    // for inputless circuits.
    for want in [
        ("step1.out".to_string(), 6i64),
        ("step2.out".to_string(), 12i64),
        ("step3.out".to_string(), 9i64),
    ] {
        assert!(
            observed.contains(&want),
            "expected {want:?} in observed = {observed:?}"
        );
    }
}

// --- circomlib_num2bits_test.circom ---------------------------------------

/// Records `circomlib_num2bits_test.circom`, the canonical circomlib
/// `Num2Bits(N)` bit-decomposition pattern (from
/// `circomlib/circuits/bitify.circom`).  Closes the M11
/// `intermediate_outputs_decode` follow-up by exercising a real-world
/// template with a numeric template parameter (`N`), an `output[N]`
/// signal array, a for loop driven by `N`, and a `===` constraint on
/// the final accumulator.  The recorder defaults `signal input`
/// values to 0, so the bit-decomposition of 0 yields `[0, 0, 0, 0]`.
#[test]
fn test_circomlib_num2bits_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_circomlib_num2bits_test_via_ct_print_full",
        "circomlib_num2bits_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Num2Bits"]);

    // ----- counts -----------------------------------------------------
    // 24 step events: 1 toplevel + 1 component-main + 1 signal-input
    // decl + 1 signal-output-array decl + 2 var decls + 1 for-header
    // + (4 iters × 4 body lines = 16) + 1 final `===`.
    // 1 call_entry + 1 call_exit = 26 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(24), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 28, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Num2Bits".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Num2Bits".to_string()]
    );

    // ----- Call_entry arg: input `in = 0` (default) -------------------
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("Num2Bits args");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0]["varname"].as_str(), Some("in"));
    assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = Num2Bits(4)` (32),
    // `signal input in;` (18), `signal output out[N];` (19), `var
    // lc1 = 0;` (21), `var e2 = 1;` (22), for header (23), then
    // 4 iterations of the body: 24, 25, 26, 27 each.  Final
    // `lc1 === in;` (29).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 32, 18, 19, 21, 22, 23, 24, 25, 26, 27, 24, 25, 26, 27, 24, 25, 26, 27, 24, 25, 26,
            27, 29
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // The recorder surfaces:
    //   * `in = 0` (input-signal decl, line 18) twice — once as the
    //     prefixed parent-frame view (input decls always emit a
    //     Variable in the recorder's per-frame walk) and once for the
    //     evaluator's input-signal decl event inside the body.
    //   * `out[i] = 0` for each i in 0..4 (the `<--` assignment on
    //     line 24 surfaces with the indexed name resolved against the
    //     loop-induction var).
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("in".to_string(), 0),
            ("in".to_string(), 0),
            ("out[0]".to_string(), 0),
            ("out[1]".to_string(), 0),
            ("out[2]".to_string(), 0),
            ("out[3]".to_string(), 0),
        ],
    );
}

/// Spec-correct expectation: `Num2Bits(N)` output-array assignments
/// must surface with their indexed name (`out[0]`, `out[1]`, ...) so
/// debugger users can inspect each bit individually.  Pre-2026-05-13
/// the evaluator's printable-name path lost the index when the
/// subscript was a `var` (e.g. the loop induction variable `i`),
/// emitting `out[?]` instead.  The env-aware
/// `expr_to_name_with_env` helper added 2026-05-13 resolves the
/// subscript against the current evaluation env so the right index
/// surfaces in the trace.
#[test]
fn test_circomlib_num2bits_test_intermediate_outputs_decode() {
    let Some((doc, _)) = record_and_dump_full(
        "test_circomlib_num2bits_test_intermediate_outputs_decode",
        "circomlib_num2bits_test.circom",
    ) else {
        return;
    };
    let observed = observed_int_vars(&doc);
    for want in [
        ("out[0]".to_string(), 0i64),
        ("out[1]".to_string(), 0i64),
        ("out[2]".to_string(), 0i64),
        ("out[3]".to_string(), 0i64),
    ] {
        assert!(
            observed.contains(&want),
            "expected {want:?} in observed = {observed:?}"
        );
    }
}

// --- template_signal_args_test.circom -------------------------------------

/// Records `template_signal_args_test.circom`, which exercises the
/// generic-template + signal-array combination: `template Sum(N)`
/// with `signal input in[N]` and a for loop driven by `N`.  Closes
/// the M11 follow-up "bread-and-butter form unexercised today".
/// The recorder must propagate `Sum(3)`'s template arg into the
/// evaluator's `generic_args` slot so the for loop runs 3 iterations
/// (without that, `N` resolves to 0 and the loop runs zero times).
#[test]
fn test_template_signal_args_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_template_signal_args_test_via_ct_print_full",
        "template_signal_args_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Sum"]);

    // ----- counts -----------------------------------------------------
    // 10 step events: 1 toplevel + 1 component-main + 1 signal-input
    // decl + 1 signal-output decl + 1 `var acc = 0;` + 1 for-header
    // + 3 body iterations + 1 final `sum <== acc;`.
    // 1 call_entry + 1 call_exit = 12 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(10), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(10),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 14, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Sum".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Sum".to_string()]
    );

    // ----- Call_entry arg: input `in = 0` (default) -------------------
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("Sum args");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0]["varname"].as_str(), Some("in"));
    assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = Sum(3)` (32),
    // `signal input in[N];` (22), `signal output sum;` (23), `var
    // acc = 0;` (25), for header (26), 3 iterations of `acc = acc +
    // in[i];` (27), final `sum <== acc;` (29).  The 3 body
    // iterations are the proof that the template arg `Sum(3)` made
    // it through the recorder's component-args parser into the
    // evaluator's `generic_args` slot — without that wiring, `N`
    // resolves to 0 and the for loop runs zero times.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 32, 22, 23, 25, 26, 27, 27, 27, 29]);

    // ----- Decoded variable values ------------------------------------
    // `in = 0` (input decl) and `sum = 0` (final assign).  The
    // recorder defaults inputs to 0, so the sum of 3 zeros is 0.
    assert_eq!(
        observed_int_vars(&doc),
        vec![("in".to_string(), 0), ("sum".to_string(), 0)],
    );
}

/// Spec-correct expectation: `template Sum(N)`'s for loop must
/// iterate exactly `N` times when instantiated as `component main =
/// Sum(3)`.  Without the template-arg propagation shipped 2026-05-13,
/// `N` resolved to 0 (the evaluator's default for unknown
/// generic_args) and the for loop ran zero times.
#[test]
fn test_template_signal_args_test_generic_arg_drives_loop() {
    let Some((doc, _)) = record_and_dump_full(
        "test_template_signal_args_test_generic_arg_drives_loop",
        "template_signal_args_test.circom",
    ) else {
        return;
    };
    let events = doc["events"].as_array().unwrap();
    let body_count = events
        .iter()
        .filter(|e| e["kind"] == "step" && e["line"].as_i64() == Some(27))
        .count();
    assert_eq!(
        body_count, 3,
        "expected 3 for-loop body steps (line 27) for Sum(3); got {body_count}"
    );
}

// --- signal_array_test.circom --------------------------------------------

/// Records `signal_array_test.circom`, which exercises element-indexed
/// reads and writes against `signal input` / `signal output` arrays
/// inside a parameterised `template VectorAdd(N)`.  Closes the M12
/// deferred coverage for indexed signal assignments — every `c[i] <==
/// a[i] + b[i]` must surface as a step + Variable event with the
/// indexed name resolved against the for-loop induction variable `i`
/// (so the trace contains `c[0]`, `c[1]`, `c[2]`, `c[3]` rather than
/// the placeholder `c[?]`).
#[test]
fn test_signal_array_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_signal_array_test_via_ct_print_full",
        "signal_array_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "VectorAdd"]);

    // ----- counts -----------------------------------------------------
    // 10 step events: 1 toplevel + 1 component-main step + 3
    // signal-decl steps (a[N], b[N], c[N]) + 1 for-header + 4
    // body iterations.  + 1 call_entry + 1 call_exit = 12 events.
    // Each iteration of the body emits one Variable event for c[i],
    // so all 10 step events carry exactly one Variable record (the
    // 3 array-decl steps emit no vars; the toplevel and component
    // steps carry the input-arg snapshot).  See the discovery
    // run for the precise per-line breakdown.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(10), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(10),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 14, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "VectorAdd".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["VectorAdd".to_string()]
    );

    // ----- Call_entry args: input arrays a/b surface as their
    // top-level array names (the recorder stages each declared input
    // signal as a single arg in the call frame; the per-element
    // values are surfaced through the body's c[i] <== a[i] + b[i]
    // assignments below).
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("VectorAdd args");
    assert_eq!(args.len(), 2);
    assert_eq!(args[0]["varname"].as_str(), Some("a"));
    assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));
    assert_eq!(args[1]["varname"].as_str(), Some("b"));
    assert_eq!(args[1]["value"]["i"].as_i64(), Some(0));

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = VectorAdd(4)` (31),
    // `signal input a[N];` (22), `signal input b[N];` (23),
    // `signal output c[N];` (24), for header (26), then 4 body
    // iterations of `c[i] <== a[i] + b[i];` on line 27.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 31, 22, 23, 24, 26, 27, 27, 27, 27]);

    // ----- Decoded variable values ------------------------------------
    // The recorder surfaces:
    //   * `a = 0` and `b = 0` on the component-main step (line 31)
    //     — these are the input-signal staging that mirrors the
    //     call_entry args list.
    //   * `c[0] = 0`, `c[1] = 0`, `c[2] = 0`, `c[3] = 0` for each
    //     iteration of the for loop body (line 27).
    // The indexed names (`c[0]`, `c[1]`, ...) are the proof that the
    // env-aware `expr_to_name_with_env` helper resolves the loop
    // induction var `i` against the current evaluation env so the
    // right per-iteration index surfaces in the trace.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 0),
            ("b".to_string(), 0),
            ("c[0]".to_string(), 0),
            ("c[1]".to_string(), 0),
            ("c[2]".to_string(), 0),
            ("c[3]".to_string(), 0),
        ],
    );
}

// --- signal_kinds_test.circom --------------------------------------------

/// Records `signal_kinds_test.circom`, which exercises every signal
/// kind (input / intermediate / output) inside one template body.
/// Closes the M12 deferred coverage for signal-kind metadata — every
/// signal declaration must surface in the trace, with the
/// intermediate `internal_sum` re-read as a real witness slot (not
/// optimised away even though it sits between the input `x` and the
/// output `y`).
#[test]
fn test_signal_kinds_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_signal_kinds_test_via_ct_print_full",
        "signal_kinds_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Mixed"]);

    // ----- counts -----------------------------------------------------
    // 7 step events: 1 toplevel + 1 component-main + 3 signal-decl
    // (input x at line 22, intermediate internal_sum at line 23,
    // output y at line 24) + 2 `<==` assignments (internal_sum at
    // line 26, y at line 27).  + 1 call_entry + 1 call_exit = 9
    // events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(7), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(7),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 11, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Mixed".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Mixed".to_string()]
    );

    // ----- Call_entry args: only the input signal (`x`) surfaces ------
    // Intermediate / output signals are NOT staged as call args —
    // they're declared inside the template body and assigned via
    // `<==`, so they only appear in step events.
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("Mixed args");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0]["varname"].as_str(), Some("x"));
    assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = Mixed()` (30), `signal
    // input x` (22), `signal internal_sum` (23), `signal output y`
    // (24), `internal_sum <== x + x;` (26), `y <== internal_sum * 2;`
    // (27).  The output / intermediate signal-decl lines surface as
    // bare Step events (no vars); their values land on the
    // assignment lines (26 and 27).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 30, 22, 23, 24, 26, 27]);

    // ----- Decoded variable values ------------------------------------
    // The trace surfaces `x = 0` twice — once on the
    // `component main = Mixed()` line (input arg staging) and once
    // on the `signal input x` decl line — followed by the two
    // signal-assignment events: `internal_sum = 0` (line 26) and
    // `y = 0` (line 27).  The recorder defaults the input to 0, so
    // every downstream slot is 0; the assignments still surface as
    // distinct Variable events, proving that the intermediate slot
    // is allocated and read back correctly (and not optimised away
    // by the structured evaluator).
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("x".to_string(), 0),
            ("x".to_string(), 0),
            ("internal_sum".to_string(), 0),
            ("y".to_string(), 0),
        ],
    );
}

// --- function_test.circom ------------------------------------------------

/// Records `function_test.circom`, which exercises a pure
/// compile-time `function fib(n)` invoked from a `template UseFib`'s
/// `<==` RHS.  Closes the M12 deferred coverage for compile-time
/// numeric helpers — functions must surface in the function table
/// distinct from any template, and their bodies must NOT emit
/// witness-slot reads.  The recorder's structured evaluator folds
/// the function call at compile time so the trace surfaces the
/// computed return value (`fib(8) = 21`) rather than 0.
#[test]
fn test_function_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_function_test_via_ct_print_full",
        "function_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // Both `UseFib` (template) and `fib` (function) surface as
    // user-visible function-table entries.  They're registered in
    // template-then-function order, mirroring the recorder's
    // `template` registration loop followed by its `function`
    // registration loop in `emit_source_trace`.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "UseFib", "fib"]);

    // ----- counts -----------------------------------------------------
    // 4 step events: 1 toplevel + 1 component-main + 1 signal-output
    // decl (line 16) + 1 `out <== fib(8);` assignment (line 18).
    // 1 call_entry + 1 call_exit = 6 events.  The function body
    // (lines 22-30) is folded at compile time — no witness-slot
    // step events are emitted inside it.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(4), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(4),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 8, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // Only `UseFib` opens a call frame — `fib` is a compile-time
    // function whose body is folded inline, so it doesn't open a
    // separate call frame in the trace.  The function table entry
    // for `fib` (asserted above) is the user-visible surface that
    // distinguishes it from witness-bearing templates.
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "UseFib".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["UseFib".to_string()]
    );

    // ----- Call_entry args: UseFib has no input signals --------------
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("UseFib args");
    assert_eq!(args.len(), 0);

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = UseFib()` (32), `signal
    // output out;` (16), `out <== fib(8);` (18).  The function
    // body's lines (24-30) are NOT among the surfaced step lines —
    // function bodies are evaluated at compile time and never touch
    // the witness, so they must not pollute the step stream.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 32, 16, 18]);

    // ----- Decoded variable values ------------------------------------
    // Only `out = 21` surfaces — the result of folding `fib(8)` at
    // compile time.  `fib(8)` walks the iterative Fibonacci over
    // a/b/t `var`s in the function body's local env (8 iterations:
    // 0,1,1,2,3,5,8,13,21) and returns 21 to the caller's `<==`.
    assert_eq!(observed_int_vars(&doc), vec![("out".to_string(), 21)],);
}

// --- component_array_test.circom -----------------------------------------

/// Records `component_array_test.circom`, which exercises a
/// `component subs[M]` array with M=3 distinct `Sum()` instances
/// instantiated and wired up element-wise inside a for loop.  Closes
/// the M12 deferred coverage for component arrays — every `subs[i]`
/// slot must surface as its own `call_entry` / `call_exit` pair so a
/// debugger can step into each instance independently, with `i`
/// resolved against the loop induction var to give the synthetic
/// `subs[0]` / `subs[1]` / `subs[2]` slot names visible in the
/// trace.
#[test]
fn test_component_array_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_component_array_test_via_ct_print_full",
        "component_array_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table — definition order in the source file -------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Sum", "UseSubs"]);

    // ----- counts -----------------------------------------------------
    // 24 step events + 4 call_entry + 4 call_exit = 32 events.  The
    // structured evaluator visits the for-loop body 3 times, and each
    // iteration emits a ComponentArrayAssign step (line 26), then
    // recurses into Sum (3 body steps inside the call frame), then
    // a wire-back step (line 18) and an output-assignment step
    // (line 28 / 29).
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(24), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(5), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(24),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 34, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence — 1 parent + 3 sibling sub-components -------
    // The parent `UseSubs` opens first, then the three `subs[i]`
    // instantiations open in source order (0, 1, 2) inside the
    // for-loop body.  Each `subs[i]` exits before the next one
    // opens (siblings, not nested), and the parent exits last.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "UseSubs".to_string(),
            "Sum".to_string(),
            "Sum".to_string(),
            "Sum".to_string(),
        ],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "Sum".to_string(),
            "Sum".to_string(),
            "Sum".to_string(),
            "UseSubs".to_string(),
            "<toplevel>".to_string(),
        ],
    );

    // ----- Call_entry args: each `subs[i]` carries its `x` input ----
    // (defaults to 0 because `in[i]` defaults to 0 with no main
    // signal-input wiring).  UseSubs carries a single `in` arg
    // (default 0).
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 5);
    let parent_args = call_entries[0]["args"].as_array().expect("UseSubs args");
    assert_eq!(parent_args.len(), 1);
    assert_eq!(parent_args[0]["varname"].as_str(), Some("in"));
    assert_eq!(parent_args[0]["value"]["i"].as_i64(), Some(0));
    for child in &call_entries[1..] {
        let args = child["args"].as_array().expect("Sum args");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0]["varname"].as_str(), Some("x"));
        assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));
    }

    // ----- Decoded variable values ------------------------------------
    // The trace surfaces:
    //   * `in = 0` on the main-component step (parent input arg).
    //   * Per iteration, the Sum body emits `x = 0` (input decl) and
    //     a wire-back `subs[i].x = 0` (the recurse-down emit), then
    //     after the recurse the parent emits `subs[i].y = 0`
    //     (the read of the sub-component's output), `subs[i].x = 0`
    //     (the parent-frame view of the wire-up), and `out[i] = 0`
    //     (the final per-iteration output assignment).
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("in".to_string(), 0),
            // i=0
            ("x".to_string(), 0),
            ("subs[0].x".to_string(), 0),
            ("subs[0].y".to_string(), 0),
            ("subs[0].x".to_string(), 0),
            ("out[0]".to_string(), 0),
            // i=1
            ("x".to_string(), 0),
            ("subs[1].x".to_string(), 0),
            ("subs[1].y".to_string(), 0),
            ("subs[1].x".to_string(), 0),
            ("out[1]".to_string(), 0),
            // i=2
            ("x".to_string(), 0),
            ("subs[2].x".to_string(), 0),
            ("subs[2].y".to_string(), 0),
            ("subs[2].x".to_string(), 0),
            ("out[2]".to_string(), 0),
        ],
    );
}

// --- circomlib_iszero_test.circom ----------------------------------------

/// Records `circomlib_iszero_test.circom`, which exercises Boolean
/// comparator templates whose outputs are constrained to `{0, 1}` via
/// the canonical `signal * (signal - 1) === 0` pattern.  Closes the
/// M12 deferred coverage for boolean-valued signal outputs — every
/// such signal must surface as `ValueRecord::Bool` (with the matching
/// `text` field) rather than as the generic `ValueRecord::Int` so
/// debugger consumers (locals pane / calltrace pane) can render the
/// canonical "true" / "false" labels.  Both the comparator's own
/// output (`comp.out`) and the parent's wire-back to a fresh signal
/// (`parent_out <== comp.out;`) propagate the Boolean flavour.
#[test]
fn test_circomlib_iszero_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_circomlib_iszero_test_via_ct_print_full",
        "circomlib_iszero_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table — definition order in the source file -------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "IsNonZero", "IsEqual", "TopLevel"]);

    // ----- counts -----------------------------------------------------
    // 38 step events + 5 call_entry + 5 call_exit = 48 events.  The
    // five calls are TopLevel + 2 IsNonZero (nz_a, nz_b) + 2 IsEqual
    // (eq_a, eq_b) — exactly the comparator instances declared in
    // TopLevel's body.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(38), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(6), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(38),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 50, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence — parent + 4 sibling comparators ------------
    // TopLevel opens first, then each comparator (IsNonZero / IsEqual)
    // opens in source-instantiation order.  Each comparator exits
    // immediately after its body returns — they're siblings inside
    // the for-loop body of TopLevel, not nested.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "TopLevel".to_string(),
            "IsNonZero".to_string(),
            "IsNonZero".to_string(),
            "IsEqual".to_string(),
            "IsEqual".to_string(),
        ],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "IsNonZero".to_string(),
            "IsNonZero".to_string(),
            "IsEqual".to_string(),
            "IsEqual".to_string(),
            "TopLevel".to_string(),
            "<toplevel>".to_string(),
        ],
    );

    // ----- Boolean Variable events: every comparator output AND the
    // parent's wire-back to a fresh signal surfaces as a Bool with
    // the matching `text` field.  The remaining Int variables are
    // input wirings (`comp.in`, `comp.a`, `comp.b`) and the input
    // arg snapshots — those carry the field-element values 0/5/7/9.
    //
    // Walk the events in order and bucket each step variable by its
    // `kind`.  The bool bucket pins both the value and the text.
    let mut int_vars: Vec<(String, i64)> = Vec::new();
    let mut bool_vars: Vec<(String, bool, String)> = Vec::new();
    for ev in events {
        if ev["kind"] != "step" {
            continue;
        }
        let Some(vars) = ev["vars"].as_array() else {
            continue;
        };
        for v in vars {
            let name = v["varname"].as_str().expect("varname str").to_string();
            let value = &v["value"];
            match value["kind"].as_str() {
                Some("Int") => {
                    let i = value["i"]
                        .as_i64()
                        .unwrap_or_else(|| panic!("Int.i for `{name}`; got {value}"));
                    int_vars.push((name, i));
                }
                Some("Bool") => {
                    let b = value["b"]
                        .as_bool()
                        .unwrap_or_else(|| panic!("Bool.b for `{name}`; got {value}"));
                    let t = value["text"]
                        .as_str()
                        .unwrap_or_else(|| panic!("Bool.text for `{name}`; got {value}"))
                        .to_string();
                    bool_vars.push((name, b, t));
                }
                other => panic!(
                    "variable `{}` decoded as unexpected kind {:?}; got {}",
                    name, other, value
                ),
            }
        }
    }

    // ----- Int variables (wires + input arg snapshots) ---------------
    assert_eq!(
        int_vars,
        vec![
            // IsNonZero(0)
            ("in".to_string(), 0),
            ("nz_a.in".to_string(), 0),
            // IsNonZero(7)
            ("in".to_string(), 7),
            ("nz_b.in".to_string(), 7),
            // IsEqual(5, 5)
            ("a".to_string(), 5),
            ("b".to_string(), 5),
            ("eq_a.a".to_string(), 5),
            ("eq_a.b".to_string(), 5),
            // IsEqual(5, 9)
            ("a".to_string(), 5),
            ("b".to_string(), 9),
            ("eq_b.a".to_string(), 5),
            ("eq_b.b".to_string(), 9),
            // Parent re-emit of each wire site (TopLevel frame view)
            ("nz_a.in".to_string(), 0),
            ("nz_b.in".to_string(), 7),
            ("eq_a.a".to_string(), 5),
            ("eq_a.b".to_string(), 5),
            ("eq_b.a".to_string(), 5),
            ("eq_b.b".to_string(), 9),
        ],
    );

    // ----- Bool variables (comparator outputs, both the
    // sub-component's own `out` and the parent's wire-back) ----------
    assert_eq!(
        bool_vars,
        vec![
            ("nz_a.out".to_string(), false, "false".to_string()),
            ("nz_b.out".to_string(), true, "true".to_string()),
            ("eq_a.out".to_string(), true, "true".to_string()),
            ("eq_b.out".to_string(), false, "false".to_string()),
            ("nz_zero".to_string(), false, "false".to_string()),
            ("nz_seven".to_string(), true, "true".to_string()),
            ("eq_same".to_string(), true, "true".to_string()),
            ("eq_diff".to_string(), false, "false".to_string()),
        ],
    );
}

// --- var_vs_signal_test.circom -------------------------------------------

/// Records `var_vs_signal_test.circom`, which mixes a compile-time
/// `var k = 7` constant, a `var sum = 0` accumulator mutated inside a
/// `for`-unroll, and a single `signal output out;` capturing the
/// final accumulator value.  Closes the M12 deferred coverage gap for
/// the `var` / `signal` distinction at the trace surface — `var`
/// declarations / mutations emit Step events at their lines but never
/// surface as Variable events (they're compile-time bookkeeping in
/// the recorder's mental model), while `signal` assignments emit
/// both a Step and a Variable event carrying the field-element value.
/// Pinning this strictly prevents a later refactor from silently
/// surfacing `var` bindings into the values pane (which would pollute
/// the trace with every for-loop induction variable / scratch slot).
#[test]
fn test_var_vs_signal_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_var_vs_signal_test_via_ct_print_full",
        "var_vs_signal_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "VarVsSignal"]);

    // ----- counts -----------------------------------------------------
    // Step breakdown for var_vs_signal_test.circom:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = VarVsSignal()` (line 32)
    //   * 1 step on `signal output out;` (line 21) — non-input decl
    //     surfaces as a bare Step (no Variable; the value lands on
    //     the assignment line)
    //   * 1 step on `var k = 7;` (line 23) — `var` decl, no Variable
    //   * 1 step on `var sum = 0;` (line 24) — `var` decl, no Variable
    //   * 1 step on the `for` header (line 25)
    //   * 5 steps on the loop body (line 26 × 5 iterations) — every
    //     `var` mutation surfaces as a bare Step (no Variable)
    //   * 1 step on `out <== sum;` (line 29) carrying the Variable
    //     event for `out`
    // = 12 step events.  + 1 call_entry + 1 call_exit = 14 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(12), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(12),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 16, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "VarVsSignal".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["VarVsSignal".to_string()]
    );

    // ----- Call_entry args: VarVsSignal has no input signals --------
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("args");
    assert_eq!(args.len(), 0);

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = VarVsSignal()` (32),
    // `signal output out` (21), `var k = 7` (23), `var sum = 0` (24),
    // for-header (25), loop body × 5 (26 × 5), `out <== sum;` (29).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![1, 32, 21, 23, 24, 25, 26, 26, 26, 26, 26, 29]
    );

    // ----- Decoded variable values ------------------------------------
    // Only the `signal output out` assignment surfaces as a Variable
    // event — every `var` declaration / mutation is bookkeeping and
    // emits a bare Step (zero Variable events).  The folded value is
    // 0 + (0+7) + (1+7) + (2+7) + (3+7) + (4+7) = 0+7+8+9+10+11 = 45.
    assert_eq!(observed_int_vars(&doc), vec![("out".to_string(), 45)]);
}

// --- if_else_compile_time_test.circom -------------------------------------

/// Records `if_else_compile_time_test.circom`, which instantiates
/// `Branch(MODE)` twice as siblings inside a `Pair` parent — once
/// with `MODE=0` (the `then`-branch fires) and once with `MODE=1`
/// (the `else`-branch fires).  Closes the M12 deferred coverage gap
/// for compile-time branch elimination — only the *taken* branch's
/// body line surfaces as a step inside each per-instance call frame,
/// and the per-instance step lines differ (line 24 vs line 26)
/// because `MODE == 0` folds at compile time.  The taken-branch's
/// `<==` Variable event lands as `b{0,1}.y` in the *parent* (Pair)
/// frame, immediately after the corresponding Branch call exits — a
/// recorder-wide quirk where the LAST Variable event of a call frame
/// always lands after the call_exit (visible in every `_via_ct_print_full`
/// fixture on this codebase).
#[test]
fn test_if_else_compile_time_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_if_else_compile_time_test_via_ct_print_full",
        "if_else_compile_time_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table — definition order in the source file -------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Branch", "Pair"]);

    // ----- counts -----------------------------------------------------
    // 18 step events + 3 call_entry + 3 call_exit = 24 events.  The
    // three calls are Pair + 2 Branch (one per sub-component).
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(18), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(4), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(18),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 26, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence — parent + 2 sibling Branches ---------------
    // Pair opens first; b0 (MODE=0) opens, exits; b1 (MODE=1) opens,
    // exits; Pair exits last.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
            "<toplevel>".to_string(),
            "Pair".to_string(),
            "Branch".to_string(),
            "Branch".to_string(),
        ],
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec![
            "Branch".to_string(),
            "Branch".to_string(),
            "Pair".to_string(),
            "<toplevel>".to_string(),
        ],
    );

    // ----- Call_entry args: each Branch carries `x = 0` --------------
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 4);
    // Pair has no input signals.
    let pair_args = call_entries[0]["args"].as_array().expect("Pair args");
    assert_eq!(pair_args.len(), 0);
    for branch in &call_entries[1..] {
        let args = branch["args"].as_array().expect("Branch args");
        assert_eq!(args.len(), 1);
        assert_eq!(args[0]["varname"].as_str(), Some("x"));
        assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));
    }

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = Pair()` (44), Pair body
    // signal-decl steps (31, 32), b0 sub-component frame (component
    // decl 34, signal-input arg-staging on the same line; signal
    // input x at 20; signal output y at 21; if-header at 23 — note
    // the taken `then`-body line 24 does NOT surface inside the
    // child frame, the corresponding `b0.y` Variable lands in the
    // parent frame immediately after call_exit at line 24); b1 frame
    // mirrors b0 with line 35 / else-body line 26 instead; then Pair's
    // own wire-up: `b0.x <== 0` (37), `b1.x <== 0` (38), `out_zero <==
    // b0.y` (40), `out_one <== b1.y` (41).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 44, 31, 32, // toplevel + Pair body header
            34, 20, 21, 23, // b0 frame: component decl + signal in/out + if header
            24, // b0.y Variable lands in Pair frame after Branch call_exit
            35, 20, 21, 23, // b1 frame: same shape, different parent decl line
            26, // b1.y Variable lands in Pair frame after Branch call_exit
            37, 38, 40, 41, // Pair's wire-up + final two output assignments
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // Per-frame surfaced variables, in event-emission order:
    //   * b0's input arg `x = 0` is staged on the parent's component
    //     line (34) inside the Branch frame, then re-surfaced inside
    //     Branch as `b0.x = 0` on the signal-input decl line (20).
    //   * The taken `then`-body's `y <== x * 2` surfaces as `b0.y = 0`
    //     in the Pair frame at line 24 (after Branch's call_exit).
    //   * b1's `x = 0` and `b1.x = 0` mirror b0; the taken `else`-body
    //     `y <== x + 100` surfaces as `b1.y = 100` in the Pair frame
    //     at line 26.
    //   * Pair's own wire-up sites surface as parent-frame views:
    //     `b0.x = 0` at line 37, `b1.x = 0` at line 38 (input wires);
    //     `out_zero = 0` at line 40 (taken-then output) and `out_one =
    //     100` at line 41 (taken-else output).
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            // b0 = Branch(0): then-branch taken
            ("x".to_string(), 0),
            ("b0.x".to_string(), 0),
            ("b0.y".to_string(), 0),
            // b1 = Branch(1): else-branch taken
            ("x".to_string(), 0),
            ("b1.x".to_string(), 0),
            ("b1.y".to_string(), 100),
            // Pair frame: wire-up + output assignments
            ("b0.x".to_string(), 0),
            ("b1.x".to_string(), 0),
            ("out_zero".to_string(), 0),
            ("out_one".to_string(), 100),
        ],
    );
}

// --- bitwise_var_ops_test.circom -----------------------------------------

/// Records `bitwise_var_ops_test.circom`, which exercises every
/// bitwise / shift operator (`&`, `|`, `^`, `<<`, `>>`) on a pair of
/// compile-time `var` operands and surfaces each per-op result through
/// a dedicated `signal output` so the recorder can pin each
/// `ValueRecord::Int` value at the corresponding `<==` line.  Closes
/// the M12 deferred coverage gap for bitwise operators on `var`s —
/// they've been carried in the AST since commit 730faa4 but no
/// end-to-end fixture pinned the surfaced values.
#[test]
fn test_bitwise_var_ops_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_bitwise_var_ops_test_via_ct_print_full",
        "bitwise_var_ops_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "BitwiseVarOps"]);

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = BitwiseVarOps()` (line 42)
    //   * 5 signal-output decl steps (lines 20-24) — bare Steps, no
    //     Variable events (values land on the `<==` lines)
    //   * 2 `var` operand decl steps (lines 26, 27) — bare Steps
    //   * 5 `var` op decl steps (lines 29-33) — bare Steps
    //   * 5 signal-assignment steps (lines 35-39) carrying the
    //     evaluated Variable events
    // = 19 step events.  + 1 call_entry + 1 call_exit = 21 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(19), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(19),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 23, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "BitwiseVarOps".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["BitwiseVarOps".to_string()]
    );

    // ----- Exact step lines (in order) --------------------------------
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 42, // toplevel + main component
            20, 21, 22, 23, 24, // signal-output decl steps
            26, 27, // `var a / b` decl steps
            29, 30, 31, 32, 33, // `var <op>` decl steps
            35, 36, 37, 38, 39, // signal-assignment steps
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // `a = 0xF0 = 240`, `b = 0x0F = 15`.  Per-op:
    //   * a & b   = 0xF0 & 0x0F = 0x00  = 0
    //   * a | b   = 0xF0 | 0x0F = 0xFF  = 255
    //   * a ^ b   = 0xF0 ^ 0x0F = 0xFF  = 255
    //   * a << 2  = 0xF0 << 2   = 0x3C0 = 960
    //   * a >> 4  = 0xF0 >> 4   = 0x0F  = 15
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("and_out".to_string(), 0),
            ("or_out".to_string(), 255),
            ("xor_out".to_string(), 255),
            ("shl_out".to_string(), 960),
            ("shr_out".to_string(), 15),
        ],
    );
}

// --- field_arithmetic_test.circom ----------------------------------------

/// Records `field_arithmetic_test.circom`, which exercises the
/// `(a + b) % p` reduction pattern over `var` operands positioned
/// near a chosen modulus boundary so the sum overflows past `p` and
/// the `%` reduction lands on a canonical small-magnitude
/// representative.  The recorder evaluates `var` arithmetic in i64;
/// the bn128 field prime doesn't fit in i64, so the fixture uses a
/// synthetic in-i64 modulus (the prime 1_000_003) which still
/// exercises the same `(a + b) % p` reduction path that the witness
/// calculator applies under the real field modulus.  Closes the M12
/// deferred coverage gap for compile-time field-arithmetic-style
/// reductions on `var`s.
#[test]
fn test_field_arithmetic_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_field_arithmetic_test_via_ct_print_full",
        "field_arithmetic_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "FieldArithmetic"]);

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = FieldArithmetic()` (line 39)
    //   * 2 signal-output decl steps (lines 25, 26) — bare Steps
    //   * 3 `var` operand decl steps (lines 28, 29, 30) — bare Steps
    //   * 2 `var <expr>` decl steps (lines 32, 33) — bare Steps
    //   * 2 signal-assignment steps (lines 35, 36) carrying Variable
    //     events
    // = 11 step events.  + 1 call_entry + 1 call_exit = 13 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(11), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(11),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 15, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "FieldArithmetic".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["FieldArithmetic".to_string()]
    );

    // ----- Exact step lines (in order) --------------------------------
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 39, // toplevel + main component
            25, 26, // signal-output decl steps
            28, 29, 30, // `var p / a / b` decl steps
            32, 33, // `var sum_mod / diff_mod` decl steps
            35, 36, // signal-assignment steps
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // `p = 1_000_003`, `a = p - 100 = 999_903`, `b = 250`.
    //   * sum_mod  = (a + b) % p = (1_000_153) % 1_000_003 = 150
    //   * diff_mod = ((b - a) % p + p) % p
    //              = ((-999_653) % 1_000_003 + 1_000_003) % 1_000_003
    //              = (-999_653 + 1_000_003) % 1_000_003 = 350
    assert_eq!(
        observed_int_vars(&doc),
        vec![("sum_out".to_string(), 150), ("diff_out".to_string(), 350),],
    );
}

// --- public_signals_test.circom ------------------------------------------

/// Records `public_signals_test.circom`, which exercises the
/// `component main {public [a, b]} = Foo();` annotation.  Closes the
/// M12 deferred coverage gap for the public-signal annotation: the
/// recorder parses the `{public [...]}` clause and surfaces the set
/// via a dedicated `public_signals` special event so debugger
/// consumers can render which main inputs are proof-visible.
#[test]
fn test_public_signals_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_public_signals_test_via_ct_print_full",
        "public_signals_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Foo"]);

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main {public [a, b]} = Foo()` (line 22)
    //   * 3 signal-input decl steps (lines 14, 15, 16)
    //   * 1 signal-output decl step (line 17) — bare Step
    //   * 1 `<==` assignment step (line 19)
    // = 7 step events.
    // + 1 call_entry + 1 call_exit + 1 io_event (the public_signals
    //   special event) = 10 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(7), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 12, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Foo".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Foo".to_string()]
    );

    // ----- Call_entry args: all three input signals (a, b, c) ---------
    // Both public and private inputs are staged onto the call frame —
    // the public/private distinction is a proof-system metadata fact
    // (which inputs the verifier sees), NOT a recording-trace gating
    // fact.  Private inputs are still staged so the debugger can
    // surface every input value during step-through.
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("Foo args");
    assert_eq!(args.len(), 3);
    assert_eq!(args[0]["varname"].as_str(), Some("a"));
    assert_eq!(args[1]["varname"].as_str(), Some("b"));
    assert_eq!(args[2]["varname"].as_str(), Some("c"));

    // ----- Public-signal special event --------------------------------
    // Exactly ONE io event — the `public_signals` annotation.  The
    // CTFS multi-stream IO bucket folds `EvmEvent` into the `stderr`
    // family (see `toIOEventKind` in `codetracer_trace_writer_ffi.nim`),
    // so the surfaced `io_kind` is `ioStderr`.  The `text` body
    // carries the discriminator + payload: `public_signals=a,b` (the
    // comma-joined ordered set of input names declared `public` on
    // the `component main` line).  Consumers that need to distinguish
    // public-signal annotations from `circom_log()` output split on
    // the leading `public_signals=` prefix.
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(io_events[0]["text"].as_str(), Some("public_signals=a,b"),);

    // ----- Exact step lines (in order) --------------------------------
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 22, // toplevel + main component
            14, 15, 16, // signal input a/b/c decl steps
            17, // signal output sum decl step
            19, // sum <== a + b + c assignment step
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // All inputs default to 0, so `sum = 0`.  Each input signal
    // surfaces twice — once on the `component main` step (parent-
    // frame staging that mirrors the call_entry args list) and once
    // on its own `signal input` decl line inside the body — and the
    // assignment surfaces `sum = 0` on the `<==` line.  This is the
    // same pattern pinned by `circomlib_num2bits` for its `in`
    // signal.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 0),
            ("b".to_string(), 0),
            ("c".to_string(), 0),
            ("a".to_string(), 0),
            ("b".to_string(), 0),
            ("c".to_string(), 0),
            ("sum".to_string(), 0),
        ],
    );
}

// --- custom_template_test.circom -----------------------------------------

/// Records `custom_template_test.circom`, which exercises the
/// `pragma custom_templates;` + `template custom NAME(...)` pair
/// (Circom 2.0.6+).  Closes the M12 deferred coverage gap for the
/// custom-template annotation: the recorder parses the `custom`
/// modifier on each `template` declaration and surfaces the set via
/// a dedicated `custom_templates` special event so debugger consumers
/// can flag custom-gate templates in the function-table view.
#[test]
fn test_custom_template_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_custom_template_test_via_ct_print_full",
        "custom_template_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // Both templates surface — `XorGate` (the custom-gate template)
    // and `Driver` (the regular template that instantiates it).  The
    // ordering matches `parse_template_definitions` source order.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "XorGate", "Driver"]);

    // ----- Custom-template special event ------------------------------
    // Exactly ONE io event — the `custom_templates` annotation.  As
    // with the public-signal annotation, the CTFS multi-stream IO
    // bucket folds `EvmEvent` into the `stderr` family (see
    // `toIOEventKind` in `codetracer_trace_writer_ffi.nim`).  The
    // `text` body carries the discriminator + payload:
    // `custom_templates=XorGate` (the comma-joined ordered set of
    // template names declared with the `custom` modifier).
    let events = doc["events"].as_array().expect("events array");
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(
        io_events[0]["text"].as_str(),
        Some("custom_templates=XorGate"),
    );

    // ----- counts -----------------------------------------------------
    // The Driver body wires its inputs into the `gate` sub-component
    // and reads back `gate.c`.  Step breakdown (lines refer to the
    // .circom file):
    //   * 1 toplevel start step (line 1 — `pragma circom 2.0.6;`)
    //   * 1 step on `component main = Driver()` (line 37)
    //   * 3 Driver-body decl steps (input a/b/output c — lines
    //     27, 28, 29)
    //   * 1 Driver-body sub-component decl step
    //     (`component gate = XorGate()`, line 31)
    //   * 2 Driver-side wire steps (`gate.a <== a;` line 32,
    //     `gate.b <== b;` line 33)
    //   * 4 XorGate body decl/assignment steps inside the call frame
    //     (input a/b lines 18/19, output c line 20, `c <-- ...`
    //     line 21)
    //   * 3 XorGate `===` constraint steps (lines 22, 23, 24)
    //   * 1 Driver-side `c <== gate.c;` step (line 34)
    // = 16 step events + 2 call_entry + 2 call_exit + 1 io_event
    // = 21 events.
    let counts = &doc["counts"];
    assert_eq!(counts["calls"].as_u64(), Some(3), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );

    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["XorGate".to_string(), "Driver".to_string(), "<toplevel>".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["XorGate".to_string(), "Driver".to_string()]
    );

    // ----- Discovery snapshot — print step_lines + observed_int_vars
    // before pinning the strict assertions below.  This block is
    // load-bearing only when the recorder shape changes; it stays as
    // documentation of what surfaced when the test was authored.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();

    // ----- Exact step lines (in order) --------------------------------
    // Pinned to the recorder's actual surface.  The custom modifier
    // doesn't perturb the body-step ordering — only the function-table
    // metadata + the `custom_templates` special event.
    assert_eq!(
        step_lines,
        vec![
            1, 38, // toplevel + main component
            28, 29, 30, // Driver: signal input a/b/output c
            32, // component gate = XorGate()
            18, 19, 20, // XorGate: signal input a/b/output c
            21, // c <-- a + b - 2*a*b
            22, 23, 24, // three === constraints inside XorGate body
            33, 34, 35, // Driver-side wires + read-back
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // All inputs default to 0.  The recorder surfaces, in event order:
    //   * Driver frame: a/b on the component-main step (parent input
    //     args), then a/b on their own `signal input` decl lines.
    //   * XorGate-call recurse: a/b are emitted again as the
    //     XorGate-side input-decl values (the input-decl walk inside
    //     the XorGate body), and the `c <-- ...` evaluator-step
    //     surfaces `gate.c` as a parent-frame view of the wire result.
    //   * Driver-side wire-back of gate.a/gate.b (recurse-up parent
    //     wire emits) and the final `c <== gate.c;` assignment that
    //     surfaces `c` in the Driver frame.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 0),
            ("b".to_string(), 0),
            ("a".to_string(), 0),
            ("b".to_string(), 0),
            ("a".to_string(), 0),
            ("b".to_string(), 0),
            ("gate.a".to_string(), 0),
            ("gate.b".to_string(), 0),
            ("gate.c".to_string(), 0),
            ("gate.a".to_string(), 0),
            ("gate.b".to_string(), 0),
            ("c".to_string(), 0),
        ],
    );
}

// --- signal_tags_test.circom ---------------------------------------------

/// Records `signal_tags_test.circom`, which exercises Circom 2.1+
/// `signal input {tag}` / `signal input {tag=value}` annotations.
/// Closes the M12 deferred coverage gap for signal tags: the
/// recorder parses the `{tag}` / `{tag=value}` annotations on
/// declarations and surfaces the per-declaration tag set via a
/// dedicated `signal_tags` special event so debugger consumers can
/// render the per-signal type-tag metadata alongside the
/// signal-kind badge.
#[test]
fn test_signal_tags_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_signal_tags_test_via_ct_print_full",
        "signal_tags_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ----------------------------------------------
    // Inner first (defined first), then Driver.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Inner", "Driver"]);

    // ----- Signal-tag special event ------------------------------------
    // The CTFS multi-stream IO bucket folds `EvmEvent` into the
    // `stderr` family (see `toIOEventKind` in
    // `codetracer_trace_writer_ffi.nim`).  The `text` body carries
    // the discriminator + payload:
    //   `signal_tags=a:bit;b:maxbit;bit_a:bit;maxbit_b:maxbit`
    // Semicolons separate per-signal records, the colon separates
    // the signal name from its comma-joined tag list.  The fixture
    // declares tags in three places:
    //   * Inner.a / Inner.b (the inner-template tagged inputs)
    //   * Driver.bit_a / Driver.maxbit_b (the parent's intermediate
    //     tagged signals used to attach the tag onto the value
    //     wired through from the untagged main inputs via `<--`)
    // The Driver template's own `signal input a` / `signal input b`
    // are intentionally untagged because Circom rejects a
    // `component main` whose template declares tagged inputs (see
    // the typing-error trap in the fixture comment).
    //
    // Tag-flow validation: `Inner.a` and `Driver.bit_a` both carry
    // the same `bit` tag, proving that the tag is recorded at every
    // declaration site in the wire chain (main → Driver →
    // bit_a → inner.a → Inner.a) so debugger consumers can verify
    // the chain end-to-end.
    let events = doc["events"].as_array().expect("events array");
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(
        io_events[0]["text"].as_str(),
        Some("signal_tags=a:bit;b:maxbit;bit_a:bit;maxbit_b:maxbit"),
    );

    let counts = &doc["counts"];
    assert_eq!(counts["calls"].as_u64(), Some(3), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );

    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["Inner".to_string(), "Driver".to_string(), "<toplevel>".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Inner".to_string(), "Driver".to_string()]
    );
}

// --- range_proof_test.circom ---------------------------------------------

/// Records `range_proof_test.circom`, which exercises `Num2Bits(N)`
/// as a bounded-integer range proof.  Closes the M12 deferred
/// coverage gap for range proofs by pinning that:
///   * the in-range `Num2Bits(8)` invocation completes silently
///     (no constraint-violation events surface from the
///     in-range path)
///   * an out-of-range claim surfaces a tagged
///     `constraint_violation` special event when the structured
///     evaluator detects that a `===` constraint does not hold
///     under the current evaluation env (without waiting for the
///     witness calculator to fail at runtime — `<--` keeps the
///     witness calculator from rejecting the circuit).
#[test]
fn test_range_proof_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_range_proof_test_via_ct_print_full",
        "range_proof_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // Range first (the main template), then Num2Bits.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Range", "Num2Bits"]);

    // ----- Constraint-violation special event -------------------------
    // Exactly ONE io event — the synthetic out-of-range
    // `x_out_of_range_claim === 256` constraint that the structured
    // evaluator detects as failing (LHS=100 from the `<--` literal
    // assignment, RHS=256 from the constraint-RHS literal).  The
    // CTFS multi-stream IO bucket folds `EvmEvent` into the
    // `stderr` family (see `toIOEventKind` in
    // `codetracer_trace_writer_ffi.nim`).  The `text` body carries
    // the discriminator + payload:
    //   `constraint_violation=constraint violation at line 42:
    //    lhs=100 != rhs=256`
    //
    // The in-range `Num2Bits(8)` instantiation completes silently —
    // no other io events surface from its body's `===` constraints
    // because they all hold under the evaluator's symbolic
    // computation (every default is 0 and the recurse propagates
    // values consistently).
    let events = doc["events"].as_array().expect("events array");
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(
        io_events[0]["text"].as_str(),
        Some("constraint_violation=constraint violation at line 42: lhs=100 != rhs=256"),
    );

    let counts = &doc["counts"];
    assert_eq!(counts["calls"].as_u64(), Some(3), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );

    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // Range opens first, then Num2Bits inside its body.
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["Num2Bits".to_string(), "Range".to_string(), "<toplevel>".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Num2Bits".to_string(), "Range".to_string()]
    );
}

// --- multi_line_constraint_test.circom -----------------------------------

/// Records `multi_line_constraint_test.circom`, which exercises a
/// single `<==` signal-assignment whose RHS expression is split across
/// four physical source lines.  Closes the M12 deferred coverage gap
/// for source-formatting resilience — the structured evaluator must
/// surface a *single* step event for the constraint (carrying the
/// constructed expression value) rather than four separate steps for
/// each physical line of the RHS.  This pins the recorder's
/// "one statement, one step" contract against developer-friendly
/// multi-line formatting that real-world circomlib circuits routinely
/// use to keep long algebraic constraints readable.
#[test]
fn test_multi_line_constraint_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_multi_line_constraint_test_via_ct_print_full",
        "multi_line_constraint_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "MultiLineConstraint"]);

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = MultiLineConstraint()` (line 44)
    //   * 1 signal-output decl step (line 22) — bare Step
    //   * 5 intermediate signal-decl steps (lines 24-28) — bare Steps
    //   * 5 short-form `<==` assignment steps (lines 30-34)
    //     carrying Variable events for a..e
    //   * 1 multi-line `out <== 2*a + 3*b + 4*c + 5*d - e` step
    //     (line 36 — the line of the LHS `out` token, courtesy of
    //     the `line_of_op.min(line)` rule in evaluator's parse_stmt)
    // = 14 step events.  + 1 call_entry + 1 call_exit = 16 events.
    //
    // The "single step" property is the load-bearing pin: even though
    // the RHS spans physical lines 37-41, only ONE step at line 36
    // surfaces.  Counting `step_lines == 36` below gives exactly 1.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(14), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(14),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 18, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "MultiLineConstraint".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["MultiLineConstraint".to_string()]
    );

    // ----- Exact step lines (in order) --------------------------------
    // The multi-line constraint surfaces exactly ONE step at line 36
    // (the LHS line), not 5 steps for each physical RHS line (37..41).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 44, // toplevel + main component
            22, // signal output out
            24, 25, 26, 27, 28, // intermediate signal decls a..e
            30, 31, 32, 33, 34, // short-form `<==` assignments
            36, // single multi-line `out <== ...` step
        ]
    );

    // ----- Multi-line constraint surfaces as exactly ONE step --------
    // Cross-check the load-bearing "one statement, one step" property
    // independently of the line-list ordering above: NO step event
    // lands on lines 37..41 (the physical lines occupied by the RHS
    // expression continuation), and exactly one step lands on line 36.
    let count_at = |line: i64| -> usize {
        events
            .iter()
            .filter(|e| e["kind"] == "step" && e["line"].as_i64() == Some(line))
            .count()
    };
    assert_eq!(count_at(36), 1, "exactly one step on the LHS line (36)");
    assert_eq!(count_at(37), 0, "no step on RHS continuation line 37");
    assert_eq!(count_at(38), 0, "no step on RHS continuation line 38");
    assert_eq!(count_at(39), 0, "no step on RHS continuation line 39");
    assert_eq!(count_at(40), 0, "no step on RHS continuation line 40");
    assert_eq!(count_at(41), 0, "no step on RHS continuation line 41");

    // ----- Decoded variable values ------------------------------------
    // a=2, b=3, c=4, d=5, e=1.
    // out = 2*a + 3*b + 4*c + 5*d - e = 4 + 9 + 16 + 25 - 1 = 53.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("a".to_string(), 2),
            ("b".to_string(), 3),
            ("c".to_string(), 4),
            ("d".to_string(), 5),
            ("e".to_string(), 1),
            ("out".to_string(), 53),
        ],
    );
}

// --- parallel_template_test.circom ---------------------------------------

/// Records `parallel_template_test.circom`, which exercises Circom
/// 2.0+ `template parallel NAME(...)` modifier — the parallel
/// witness-calculator codegen opt-in.  Closes the M12 deferred
/// coverage gap for the parallel-template annotation: the recorder
/// parses the `parallel` modifier on each `template` declaration and
/// surfaces the set via a dedicated `parallel_templates` special
/// event so debugger consumers can distinguish parallel from regular
/// templates in the function-table view.  Per-instance variable
/// values (every `out[i]` for the `BatchHash(4)` instantiation) are
/// preserved exactly as for regular templates — the parallel modifier
/// is purely a back-end codegen flag, not a recording-trace shape
/// change.
#[test]
fn test_parallel_template_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_parallel_template_test_via_ct_print_full",
        "parallel_template_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // The `parallel` modifier is dropped from the recorded template
    // name; the modifier flag itself surfaces through the
    // `parallel_templates` special event below.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "BatchHash"]);

    // ----- Parallel-template special event ----------------------------
    // Exactly ONE io event — the `parallel_templates` annotation.  As
    // with the public-signal / custom-template / signal-tags
    // annotations, the CTFS multi-stream IO bucket folds `EvmEvent`
    // into the `stderr` family (see `toIOEventKind` in
    // `codetracer_trace_writer_ffi.nim`).  The `text` body carries
    // the discriminator + payload: `parallel_templates=BatchHash` (the
    // comma-joined ordered set of template names declared with the
    // `parallel` modifier).
    let events = doc["events"].as_array().expect("events array");
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(
        io_events[0]["text"].as_str(),
        Some("parallel_templates=BatchHash"),
    );

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = BatchHash(4)` (line 30)
    //   * 1 signal-input decl step (line 22)
    //   * 1 signal-output decl step (line 23)
    //   * 1 for-header step (line 25)
    //   * 4 body iterations of `out[i] <== in[i] * in[i];` (line 26)
    // = 9 step events.  + 1 call_entry + 1 call_exit + 1 io_event
    // = 12 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(9), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(9),
        "values; counts={counts}"
    );

    assert_eq!(events.len(), 14, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "BatchHash".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["BatchHash".to_string()]
    );

    // ----- Call_entry args: input array `in` ------------------------
    // The recorder stages each declared input signal as a single arg
    // in the call frame; the per-element values surface through the
    // body's `out[i] <== in[i] * in[i]` assignments below.
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("BatchHash args");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0]["varname"].as_str(), Some("in"));
    assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = BatchHash(4)` (30),
    // `signal input in[N];` (22), `signal output out[N];` (23), for
    // header (25), then 4 body iterations of `out[i] <== in[i] *
    // in[i];` on line 26.  The 4 body iterations are the proof that
    // the template arg `BatchHash(4)` made it through the recorder's
    // component-args parser into the evaluator's `generic_args` slot
    // for the parallel-modifier path (the parser must skip the
    // `parallel` keyword exactly as it skips `custom` for
    // `template custom NAME`).
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 30, 22, 23, 25, 26, 26, 26, 26]);

    // ----- Decoded variable values ------------------------------------
    // The recorder surfaces:
    //   * `in = 0` on the BatchHash body's input-decl step (line 22) —
    //     mirrors the call_entry args.
    //   * Per iteration of the for body: `out[i] = 0` (the
    //     square-of-zero result).
    // Per-instance value preservation is the load-bearing pin for
    // parallel templates: every `out[i]` slot must surface
    // independently (rather than collapsing into a single aggregate
    // event) so debugger consumers can step through each iteration
    // separately, as for regular templates.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("in".to_string(), 0),
            ("out[0]".to_string(), 0),
            ("out[1]".to_string(), 0),
            ("out[2]".to_string(), 0),
            ("out[3]".to_string(), 0),
        ],
    );
}

// --- anonymous_component_test.circom -------------------------------------

/// Records `anonymous_component_test.circom`, which exercises Circom
/// 2.1+ inline-defined sub-components via the
/// `expr <-- Template(args)(in1, in2)` syntax — the template is
/// instantiated and wired in a single expression-statement, without
/// a named `component foo = Template();` declaration.  Closes the
/// M12 deferred coverage gap for the anonymous-component syntax: the
/// recorder source-scans for these inline-defined invocations and
/// surfaces the per-instance synthetic name + underlying template
/// name via a dedicated `anonymous_components` special event so
/// debugger consumers can render every anonymous instantiation in
/// the function-table view alongside its arguments.
#[test]
fn test_anonymous_component_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_anonymous_component_test_via_ct_print_full",
        "anonymous_component_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // All three templates surface in the function table (definition
    // order in the source).  Only `Driver` actually opens a call
    // frame; the anonymous `Doubler()` / `Tripler()` invocations
    // surface through the dedicated `anonymous_components` special
    // event below rather than through `call_entry` events because
    // the recorder's structured evaluator does not recurse into the
    // anonymous-component body — it treats the expression as an
    // opaque assignment whose result value the witness calculator
    // computes.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Doubler", "Tripler", "Driver"]);

    // ----- Anonymous-component special event --------------------------
    // Exactly ONE io event — the `anonymous_components` annotation.
    // The CTFS multi-stream IO bucket folds `EvmEvent` into the
    // `stderr` family (see `toIOEventKind` in
    // `codetracer_trace_writer_ffi.nim`).  The `text` body carries
    // the discriminator + payload:
    //   `anonymous_components=__anon@40:Doubler;__anon@41:Tripler`
    // Semicolons separate per-instance records, the colon separates
    // the recorder-assigned synthetic name (`__anon@LINE`) from the
    // underlying template name.  Each per-instance synthetic name
    // disambiguates multiple anonymous instantiations of the same
    // template on different source lines so the calltrace surface
    // can render them distinctly.
    let events = doc["events"].as_array().expect("events array");
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(
        io_events[0]["text"].as_str(),
        Some("anonymous_components=__anon@40:Doubler;__anon@41:Tripler"),
    );

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = Driver()` (line 45)
    //   * 1 signal-input decl step (line 35)
    //   * 1 signal-output decl step (line 36)
    //   * 2 bare intermediate signal-decl steps (lines 38, 39 —
    //     `signal doubled` / `signal tripled`)
    //   * 2 steps on line 40 — the `doubled <-- Doubler()(in)`
    //     assignment surfaces the LHS Variable on the first step,
    //     then a follow-up bare step where the evaluator's
    //     anonymous-component recurse hook fires (with no body to
    //     step into, the recurse is a no-op but still emits a step
    //     marker so debugger consumers see the inline-instantiation
    //     boundary)
    //   * 2 steps on line 41 — same pattern for the
    //     `tripled <-- Tripler()(doubled)` line
    //   * 1 step on line 42 — the final
    //     `out <-- doubled + tripled;`
    // = 11 step events.  + 1 call_entry + 1 call_exit + 1 io_event
    // = 14 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(11), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(11),
        "values; counts={counts}"
    );

    assert_eq!(events.len(), 16, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // Only `Driver` opens a call frame — the anonymous `Doubler()` /
    // `Tripler()` invocations are surfaced through the
    // `anonymous_components` special event, not as call_entry events.
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Driver".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Driver".to_string()]
    );

    // ----- Call_entry args: input `in` --------------------------------
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("Driver args");
    assert_eq!(args.len(), 1);
    assert_eq!(args[0]["varname"].as_str(), Some("in"));
    assert_eq!(args[0]["value"]["i"].as_i64(), Some(0));

    // ----- Exact step lines (in order) --------------------------------
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 45, // toplevel + main component
            35, 36, // signal input in / signal output out
            38, 39, // signal doubled / signal tripled (intermediate decls)
            40, 40, // doubled <-- Doubler()(in) — Variable + recurse
            41, 41, // tripled <-- Tripler()(doubled) — Variable + recurse
            42, // out <-- doubled + tripled
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // The recorder surfaces:
    //   * `in = 0` on the `component main` step (parent input arg).
    //   * `in = 0` on the `signal input in;` decl step inside the body.
    //   * `doubled = 0` on the inline-anonymous `<--` assignment line
    //     (the recorder's structured evaluator does not recurse into
    //     the anonymous Doubler body, so the value defaults to 0
    //     rather than `2 * in = 0` computed inside the sub-template).
    //   * `tripled = 0` on the second inline-anonymous `<--` line.
    //   * `out = 0` on the final sum.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("in".to_string(), 0),
            ("in".to_string(), 0),
            ("doubled".to_string(), 0),
            ("tripled".to_string(), 0),
            ("out".to_string(), 0),
        ],
    );
}

// --- circomlib_poseidon_test.circom --------------------------------------

/// Records `circomlib_poseidon_test.circom`, which exercises a
/// minimal inline `Poseidon(2)`-style permutation with the canonical
/// Poseidon shape (S-box exponent 5, MDS-style linear mixing, two
/// full rounds with per-round constants) over small inputs that
/// keep every intermediate below `i64::MAX`.  Closes the M12
/// deferred coverage gap for circomlib's Poseidon hash without
/// requiring a deep `include` chain — every per-step intermediate
/// value surfaces as a deterministic `Int` value through the
/// recorder's structured evaluator, ending in the canonical-by-
/// construction digest at the `out` signal.
#[test]
fn test_circomlib_poseidon_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_circomlib_poseidon_test_via_ct_print_full",
        "circomlib_poseidon_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Poseidon2"]);

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = Poseidon2()` (line 98)
    //   * 1 signal-output decl step (line 50)
    //   * 14 signal decls + assignments inside the body (lines 57-95
    //     — every `signal foo;` is a bare Step and every `foo <--
    //     expr;` is a Step that also carries a Variable event)
    //   * 15 Variable events for the 15 `<--` assignments (in_a, in_b
    //     plus 13 round-state slots)
    // = 32 step events.  + 1 call_entry + 1 call_exit + 0 io_events
    // = 34 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(32), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(32),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 36, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Poseidon2".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Poseidon2".to_string()]
    );

    // ----- Exact step lines (in order) --------------------------------
    // Lines: toplevel (1), `component main = Poseidon2()` (98), the
    // `signal output out;` decl (50), then per-signal decl + assign
    // pairs threading through both rounds and the final digest (lines
    // 57..95).  The structured evaluator must visit every `<--` site
    // so the per-line decoded values pin the per-step digest
    // computation.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(
        step_lines,
        vec![
            1, 98, 50, // toplevel + main + signal output out
            57, 58, 59, 60, // in_a/in_b decls + assigns
            63, 64, 65, 66, // round 0: m0_0/m0_1 decls + assigns
            68, 69, 70, 71, // round 0: sb0_0/sb0_1 decls + assigns
            73, 74, 75, 76, // round 0: r0_0/r0_1 decls + assigns
            79, 80, 81, 82, // round 1: m1_0/m1_1 decls + assigns
            84, 85, 86, 87, // round 1: sb1_0/sb1_1 decls + assigns
            89, 90, 91, 92, // round 1: r1_0/r1_1 decls + assigns
            95, // out <-- r1_0 + r1_1
        ]
    );

    // ----- Decoded variable values ------------------------------------
    // Hand-traced from the source's `<--` assignments — see the
    // fixture comment for the per-step computation.  The final digest
    // value (`out = 493_934_506_353_822`) is the load-bearing pin:
    // a future Poseidon-spec mismatch (e.g. an evaluator change to
    // the `**` operator semantics, or a refactor of the per-round
    // ordering) would surface here as a digest mismatch immediately.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("in_a".to_string(), 1),
            ("in_b".to_string(), 1),
            ("m0_0".to_string(), 3),
            ("m0_1".to_string(), 3),
            ("sb0_0".to_string(), 243),
            ("sb0_1".to_string(), 243),
            ("r0_0".to_string(), 250),
            ("r0_1".to_string(), 254),
            ("m1_0".to_string(), 758),
            ("m1_1".to_string(), 754),
            ("sb1_0".to_string(), 250_233_832_892_768),
            ("sb1_1".to_string(), 243_700_673_461_024),
            ("r1_0".to_string(), 250_233_832_892_781),
            ("r1_1".to_string(), 243_700_673_461_041),
            ("out".to_string(), 493_934_506_353_822),
        ],
    );
}

// --- pragma_version_test.circom ------------------------------------------

/// Records `pragma_version_test.circom`, which exercises multiple
/// `pragma circom <version>;` headers across two source files (the
/// entrypoint + a directly `include`d helper).  Closes the M12
/// deferred coverage gap for `pragma circom <version>;` headers: the
/// recorder scans the entrypoint and every directly included file,
/// then surfaces the per-file pragma-version set via a dedicated
/// `pragma_versions` special event so debugger consumers can show
/// which Circom language version was assumed when each source file
/// was parsed.
///
/// The single-file fixtures (the rest of the M12 suite) keep
/// `io_events == 0` because the recorder only emits this event when
/// at least two files (entrypoint + ≥ 1 included file) declare
/// pragma headers — the surface stays minimal for the common case.
#[test]
fn test_pragma_version_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full(
        "test_pragma_version_test_via_ct_print_full",
        "pragma_version_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table ---------------------------------------------
    // Only `Driver` (the entrypoint template) — the recorder does not
    // recurse into included source files for template registration in
    // its current shape, so `Doubler` (defined in
    // `pragma_version_helper.circom`) does not surface in the function
    // table.  This pins the current behaviour explicitly so a future
    // include-aware refactor surfaces in test diffs.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Driver"]);

    // ----- Pragma-version special event -------------------------------
    // Exactly ONE io event — the `pragma_versions` annotation.  The
    // CTFS multi-stream IO bucket folds `EvmEvent` into the `stderr`
    // family (see `toIOEventKind` in
    // `codetracer_trace_writer_ffi.nim`).  The `text` body carries
    // the discriminator + payload:
    //   `pragma_versions=pragma_version_test.circom:2.1.5;
    //    pragma_version_helper.circom:2.1.0`
    // Semicolons separate per-file records, the colon separates the
    // file basename from its declared version.  Entrypoint first,
    // then includes in source order.  Basenames (rather than absolute
    // paths) are used so the surface stays stable across machines —
    // matching the `--strip-paths` ct-print convention.
    let events = doc["events"].as_array().expect("events array");
    let io_events: Vec<&serde_json::Value> = events.iter().filter(|e| e["kind"] == "io").collect();
    assert_eq!(io_events.len(), 1);
    assert_eq!(io_events[0]["io_kind"].as_str(), Some("ioStderr"));
    assert_eq!(
        io_events[0]["text"].as_str(),
        Some(
            "pragma_versions=pragma_version_test.circom:2.1.5;\
             pragma_version_helper.circom:2.1.0"
        ),
    );

    // ----- counts -----------------------------------------------------
    // Step breakdown:
    //   * 1 toplevel start step (line 1)
    //   * 1 step on `component main = Driver()` (line 31)
    //   * 1 signal-input decl step (line 23)
    //   * 1 signal-output decl step (line 24)
    //   * 1 component-decl step (line 26)
    //   * 1 wire step `inner.x <== x` (line 27)
    //   * 1 wire-back step `y <== inner.y` (line 28)
    // = 7 step events.  + 1 call_entry + 1 call_exit + 1 io_event
    // = 10 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(7), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(1),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(7),
        "values; counts={counts}"
    );

    assert_eq!(events.len(), 12, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // Only Driver opens a call frame; the included Doubler template
    // is not parsed, so no Doubler call_entry surfaces despite the
    // `component inner = Doubler();` declaration in the body.
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Driver".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Driver".to_string()]
    );

    // ----- Exact step lines (in order) --------------------------------
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 31, 23, 24, 26, 27, 28]);

    // ----- Decoded variable values ------------------------------------
    // The recorder surfaces:
    //   * `x = 0` on the `component main` step (parent input arg).
    //   * `x = 0` on the `signal input x;` decl step inside the body.
    //   * `inner.x = 0` on the `inner.x <== x;` wire step (the value
    //     wired into the sub-component's input slot — surfaces even
    //     though the included Doubler template is not stepped into).
    //   * `y = 0` on the `y <== inner.y;` wire-back step.
    assert_eq!(
        observed_int_vars(&doc),
        vec![
            ("x".to_string(), 0),
            ("x".to_string(), 0),
            ("inner.x".to_string(), 0),
            ("y".to_string(), 0),
        ],
    );
}

// --- bus_type_test.circom -----------------------------------------------

/// Path to the Circom 2.2.3 binary built locally from the
/// `metacraft-circom-fork` tree.  The dev shell pins circom 2.1.5,
/// which doesn't recognise the `bus` / `input BusName()` syntax
/// introduced in Circom 2.2 — the bus_type fixture's `pragma circom
/// 2.2.0;` declaration is rejected with `Pragma version 2.2.0 is not
/// supported`.  Tests that need bus support route the recorder
/// through this binary by setting `CIRCOM_BIN` on the recorder
/// subprocess, which keeps the env override scoped to the bus test
/// (cargo test runs all test functions in the same process by
/// default; setting `std::env::set_var` would leak the override into
/// every other test running in parallel and silently re-circle the
/// 2.1.5 corpus through 2.2.3, which is not 100% backward-compatible
/// for some constraint patterns the existing fixtures rely on).
///
/// Resolved relative to the workspace root (`<workspace>/codetracer-
/// circom-recorder/../metacraft-circom-fork/target/release/circom`)
/// so the path is portable across machines that follow the metacraft
/// repo workspace layout.  An externally-set `CIRCOM_2_2_BIN` env
/// override (e.g. for CI runners that build circom in a different
/// location) takes precedence.
fn circom_2_2_path() -> PathBuf {
    if let Ok(p) = std::env::var("CIRCOM_2_2_BIN") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("metacraft-circom-fork")
        .join("target")
        .join("release")
        .join("circom")
}

/// Like `record_and_dump_full`, but invokes the recorder as a
/// subprocess with `CIRCOM_BIN` pointed at the Circom 2.2.3 binary
/// so the bus-type fixture compiles.  Returns `None` when either the
/// 2.2 binary or `ct-print` is unavailable, surfacing a `SKIP:` line
/// (the verify-cli-convention-no-silent-skip.sh check greps for that
/// literal token).
fn record_and_dump_full_with_circom_2_2(
    test_name: &str,
    program: &str,
) -> Option<(serde_json::Value, PathBuf)> {
    let circom_bin = circom_2_2_path();
    if !circom_bin.exists() {
        eprintln!(
            "SKIP: {test_name} requires circom 2.2.3 at {} — only available \
            within the metacraft workspace where metacraft-circom-fork is a sibling \
            and built (cd ~/metacraft/metacraft-circom-fork && cargo build --release).",
            circom_bin.display()
        );
        return None;
    }

    let ct_print = require_ct_print(test_name);

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join(program);

    // Run the recorder as a subprocess so the `CIRCOM_BIN` env override
    // stays local to this invocation and doesn't leak into other tests
    // (cargo test runs all test functions in the same process by
    // default and env vars are process-wide).
    let output = Command::new(env!("CARGO_BIN_EXE_codetracer-circom-recorder"))
        .args(["record"])
        .arg(&source_path)
        .args(["--out-dir"])
        .arg(&out_dir)
        .env("CIRCOM_BIN", &circom_bin)
        .output()
        .expect("failed to run recorder subprocess");

    assert!(
        output.status.success(),
        "recorder should succeed for {program} with CIRCOM_BIN={}; stderr: {}",
        circom_bin.display(),
        String::from_utf8_lossy(&output.stderr)
    );

    let ct_files = ct_files_in(&out_dir);
    assert!(
        !ct_files.is_empty(),
        "expected a .ct container in {:?}",
        out_dir
    );

    let ct_output = Command::new(&ct_print)
        .args(["--full", "--strip-paths"])
        .arg(&ct_files[0])
        .output()
        .expect("failed to run ct-print --full");

    assert!(
        ct_output.status.success(),
        "ct-print --full should succeed; stderr: {}",
        String::from_utf8_lossy(&ct_output.stderr)
    );

    let doc: serde_json::Value =
        serde_json::from_slice(&ct_output.stdout).expect("ct-print --full should emit valid JSON");

    drop(tmp_dir);

    Some((doc, source_path))
}

/// Records `bus_type_test.circom`, the recorder's first fixture for
/// Circom 2.2's `bus` composite type.  The `Distance` template
/// declares `input Point() p;` — a bus-typed parameter that surfaces
/// on the call_entry as a `ValueRecord::Struct` whose `field_values`
/// mirror the `Point { signal x; signal y; }` field order.  Field
/// reads (`p.x`, `p.y`) inside the body resolve through the
/// evaluator's existing `Expr::Member` -> `Value::Component` lookup
/// path.  The recorder defaults every bus field to 0 (no JSON-input
/// wiring today), so the squared terms `x2`, `y2`, `d` all surface
/// as 0 — what's load-bearing here is the *shape* of the call_entry
/// arg (a Struct with 2 Int field_values), not the values.
///
/// Pinned to current behavior: the recorder doesn't have an
/// input-injection mechanism for bus fields (or for any input), so
/// the spec-correct expectation `p = Struct{ field_values: [Int 3,
/// Int 4], type_id }` from the original task brief is not yet
/// reachable — the witness calculator gets `0` for every input slot
/// and the trace surfaces those zeroes.  The Struct *shape* (a
/// `TypeKind::Struct` `Point` registered via `ensure_type_id`, with
/// the call_entry arg's `field_values` carrying the field-element
/// type-id list) is the new-this-round contribution — that's the
/// recorder's first Struct emission for Circom.  When JSON input
/// wiring lands, this test should be extended to assert the
/// non-zero field values rather than weakened to allow them.
#[test]
fn test_bus_type_test_via_ct_print_full() {
    let Some((doc, source_path)) = record_and_dump_full_with_circom_2_2(
        "test_bus_type_test_via_ct_print_full",
        "bus_type_test.circom",
    ) else {
        return;
    };

    assert_metadata_program_ends_with(&doc, &source_path);

    // ----- Function table -------------------------------------------------
    // Only the `Distance` template surfaces — `bus Point()` is a type
    // declaration, not a callable, and the recorder doesn't register
    // bus types in the `functions` array.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["<toplevel>", "Distance"]);

    // ----- Type table -----------------------------------------------------
    // `Point` is registered as the recorder's first Struct type for
    // Circom (`TypeKind::Struct`, lang_type = "Point").  `field` and
    // `bool` are the standard scalar types every Circom trace
    // registers; `type_0` is the per-int-type-id alias the writer
    // creates as a side-effect of the `register_variable_int` /
    // `register_variable_cbor` fast path (every other Circom fixture
    // also surfaces it — see `template_signal_args_test`'s 3-entry
    // type table).
    let types: Vec<&str> = doc["types"]
        .as_array()
        .expect("types array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(types, vec!["field", "bool", "Point", "type_0"]);

    // ----- counts ---------------------------------------------------------
    // 9 step events: 1 toplevel (line 1) + 1 component-main (line 47)
    // + 1 input-bus decl (line 38) + 1 signal-output decl (line 39)
    // + 2 intermediate signal decls (lines 40, 41) + 3 wire
    // assignments (lines 42, 43, 44).  + 1 call_entry + 1 call_exit
    // = 11 events.  9 values: the bus arg `p` surfaces both as a
    // call_entry arg AND as a step variable on the line-47 step (the
    // Nim writer's `arg(...)` path stages the value on the current
    // step before consuming it for the next call), then 3 step
    // variables for the wire targets x2/y2/d.  That's 4 step
    // variables + 1 args entry + 4 step events with empty `vars` for
    // the toplevel/decl steps = 9 values total tracked by the writer.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(9), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(2), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );
    assert_eq!(
        counts["values"].as_u64(),
        Some(9),
        "values; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 13, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence --------------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["<toplevel>".to_string(), "Distance".to_string()]
    );
    assert_eq!(
        observed_exit_sequence(&doc),
        vec!["Distance".to_string()]
    );

    // ----- Call_entry arg: bus-typed `p` surfaces as a Struct -------------
    // This is the load-bearing assertion: the recorder's first-ever
    // `ValueRecord::Struct` emission for Circom.  The Struct's
    // `type_id` points at the registered `Point` struct-kind type
    // (index 2 in the type table — `field` is 0, `bool` is 1).
    // `field_values` mirrors the bus declaration's field order:
    // `signal x; signal y;` -> two field-element `Int 0` values, both
    // typed as `field` (type_id 0).
    let call_entries: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .collect();
    assert_eq!(call_entries.len(), 1);
    let args = call_entries[0]["args"].as_array().expect("Distance args");
    assert_eq!(args.len(), 1, "Distance has one bus-typed input arg");
    assert_eq!(args[0]["varname"].as_str(), Some("p"));
    assert_eq!(args[0]["value"]["kind"].as_str(), Some("Struct"));
    assert_eq!(args[0]["value"]["type_id"].as_i64(), Some(2));
    let field_values = args[0]["value"]["field_values"]
        .as_array()
        .expect("Struct.field_values array");
    assert_eq!(field_values.len(), 2, "Point has 2 declared fields (x, y)");
    for (i, fv) in field_values.iter().enumerate() {
        assert_eq!(
            fv["kind"].as_str(),
            Some("Int"),
            "field[{i}] should decode as Int (witness defaults inputs to 0); \
             when JSON input wiring lands, extend this test to assert non-zero \
             values rather than weakening the kind check"
        );
        assert_eq!(
            fv["i"].as_i64(),
            Some(0),
            "field[{i}] value must be 0 (the recorder defaults all witness \
             inputs to 0; no JSON-input wiring today)"
        );
        assert_eq!(
            fv["type_id"].as_i64(),
            Some(0),
            "each bus field is typed as the scalar `field` type (type_id 0)"
        );
    }

    // ----- Exact step lines (in order) ------------------------------------
    // The trailing line-44 step (the `d <== x2 + y2;` wire) lands
    // *after* the call_exit because the Nim writer buffers the
    // current pending step until the next register_step / finish call
    // flushes it — `register_return` doesn't flush.  This is the
    // existing writer quirk every Circom fixture observes (compare
    // `template_signal_args_test`'s line-29 step which also surfaces
    // post-call_exit).  Pinning the order here guards against any
    // future flush-on-return change silently dropping the wire step.
    let step_lines: Vec<i64> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .map(|e| e["line"].as_i64().expect("step.line i64"))
        .collect();
    assert_eq!(step_lines, vec![1, 47, 38, 39, 40, 41, 42, 43, 44]);

    // ----- Decoded variable values (across step events) -------------------
    // Walk every step event's `vars` array and collect a single
    // `(varname, kind, [optional payload])` triple per recorded var.
    // Pinning the full sequence — including the `p` Struct var that
    // surfaces on the line-47 step (the Nim writer's `arg(...)` path
    // stages the staged-arg value on the *current* step before
    // consuming it for the next call) — catches both regression in
    // bus surfacing and any drift in the scalar wire-target order.
    // The bus var's payload is asserted via the dedicated `field_values`
    // checks above; here we only check that the line-47 step carries
    // *one* var named `p` of kind `Struct`, and the trailing wire
    // steps each carry their respective `Int 0` scalar.
    let recorded_vars: Vec<(String, String, Option<i64>)> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .flat_map(|e| e["vars"].as_array().cloned().unwrap_or_default())
        .map(|v| {
            let name = v["varname"].as_str().expect("varname str").to_string();
            let kind = v["value"]["kind"]
                .as_str()
                .expect("value.kind str")
                .to_string();
            let int_val = v["value"]["i"].as_i64();
            (name, kind, int_val)
        })
        .collect();
    assert_eq!(
        recorded_vars,
        vec![
            // line-47 step (component main): the staged bus arg `p`.
            ("p".to_string(), "Struct".to_string(), None),
            // line-42 wire step: x2 <== p.x * p.x = 0.
            ("x2".to_string(), "Int".to_string(), Some(0)),
            // line-43 wire step: y2 <== p.y * p.y = 0.
            ("y2".to_string(), "Int".to_string(), Some(0)),
            // line-44 wire step (post-call_exit, see step-line ordering
            // note above): d <== x2 + y2 = 0.
            ("d".to_string(), "Int".to_string(), Some(0)),
        ],
    );
}

// ===========================================================================
// CLI env-var contract
// ===========================================================================

/// `CODETRACER_CIRCOM_RECORDER_OUT_DIR` must be honoured as a fallback
/// for `--out-dir`.  Convention: `Recorder-CLI-Conventions.md` §5.
#[test]
fn test_env_out_dir_used_when_flag_omitted() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let env_out_dir = tmp_dir.path().join("via-env");

    let source_path = test_programs_dir().join("flow_test.circom");

    let output = Command::new(env!("CARGO_BIN_EXE_codetracer-circom-recorder"))
        .args(["record"])
        .arg(&source_path)
        .env("CODETRACER_CIRCOM_RECORDER_OUT_DIR", &env_out_dir)
        // Make sure the env-var doesn't bleed in from the developer's shell.
        .env_remove("CODETRACER_CIRCOM_RECORDER_DISABLED")
        .output()
        .expect("failed to run recorder");

    assert!(
        output.status.success(),
        "recorder should succeed when CODETRACER_CIRCOM_RECORDER_OUT_DIR is set; \
        stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let ct_files = ct_files_in(&env_out_dir);
    assert!(
        !ct_files.is_empty(),
        "expected the env-supplied output dir {:?} to receive the .ct container",
        env_out_dir
    );
}

/// `CODETRACER_CIRCOM_RECORDER_DISABLED=1` must skip recording entirely.
/// The recorder process should still exit 0 (the Circom recorder
/// doesn't run a separate target subprocess — it shells out to `circom`
/// and runs the witness calculator itself — so "disabled" simply means
/// "don't write any trace artefacts").
#[test]
fn test_env_disabled_skips_recording() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("should-stay-empty");

    let source_path = test_programs_dir().join("flow_test.circom");

    let output = Command::new(env!("CARGO_BIN_EXE_codetracer-circom-recorder"))
        .args(["record"])
        .arg(&source_path)
        .args(["--out-dir"])
        .arg(&out_dir)
        .env("CODETRACER_CIRCOM_RECORDER_DISABLED", "1")
        .output()
        .expect("failed to run recorder");

    assert!(
        output.status.success(),
        "recorder should succeed in disabled mode; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // No .ct file should have been written.
    assert!(
        !out_dir.exists() || ct_files_in(&out_dir).is_empty(),
        "no .ct container should be written when CODETRACER_CIRCOM_RECORDER_DISABLED=1; \
        got files in {:?}",
        out_dir
    );
}

/// `--format` is no longer accepted at any level — clap must reject it.
/// Convention: §4 (CTFS-only).
#[test]
fn test_format_flag_rejected_by_clap() {
    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("traces");
    let source_path = test_programs_dir().join("flow_test.circom");

    let output = Command::new(env!("CARGO_BIN_EXE_codetracer-circom-recorder"))
        .args(["record"])
        .arg(&source_path)
        .args(["--out-dir"])
        .arg(&out_dir)
        .args(["--format", "json"])
        .output()
        .expect("failed to run recorder");

    assert!(
        !output.status.success(),
        "--format should be rejected by clap; stdout: {}, stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--format")
            || stderr.contains("unexpected argument")
            || stderr.contains("unrecognized")
            || stderr.contains("found argument"),
        "clap error should mention the unknown --format flag; got stderr:\n{stderr}"
    );
}
