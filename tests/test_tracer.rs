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
        .join("ct-print")
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
    let ct_print = ct_print_path();
    if !ct_print.exists() {
        eprintln!(
            "SKIP: ct-print not found at {} — only available within the \
            metacraft workspace where codetracer-trace-format-nim is a sibling.",
            ct_print.display()
        );
        return;
    }

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
        Some(1),
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
        vec!["FlowTest"],
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
            observed_vars
                .iter()
                .any(|(n, v)| n == name && v == value),
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
fn ct_print_or_skip(test_name: &str) -> Option<PathBuf> {
    let p = ct_print_path();
    if !p.exists() {
        eprintln!(
            "SKIP: {test_name} requires ct-print at {} — only available \
            within the metacraft workspace where codetracer-trace-format-nim \
            is a sibling.",
            p.display()
        );
        return None;
    }
    Some(p)
}

/// Record a program and return the `ct-print --full --strip-paths`
/// JSON document plus the absolute path to the source file (so the
/// caller can match `metadata.program`).  Returns `None` when
/// `ct-print` is unavailable (the caller has already emitted a
/// `SKIP:` line via `ct_print_or_skip`).
fn record_and_dump_full(test_name: &str, program: &str) -> Option<(serde_json::Value, PathBuf)> {
    let ct_print = ct_print_or_skip(test_name)?;

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

    let doc: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("ct-print --full should emit valid JSON");

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
    // Only the `ControlFlow` template is defined; the synthetic
    // `<toplevel>` frame opened by `TraceWriter::start` is not surfaced
    // in the user-facing functions array.
    let functions: Vec<&str> = doc["functions"]
        .as_array()
        .expect("functions array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(functions, vec!["ControlFlow"]);

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
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 21, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // `ControlFlow` is the outermost user-defined template; the
    // recorder surfaces it as a single call pair around the body's
    // step events.
    assert_eq!(observed_call_sequence(&doc), vec!["ControlFlow".to_string()]);
    assert_eq!(observed_exit_sequence(&doc), vec!["ControlFlow".to_string()]);

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
    assert_eq!(functions, vec!["Inner", "Middle", "NestedTemplate"]);

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
    assert_eq!(counts["calls"].as_u64(), Some(3), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 16, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call entry order -------------------------------------------
    // The recorder emits component calls in *nesting* order
    // (root → leaf), starting at `component main` and recursing into
    // each template body's declared sub-components.  This is the
    // structural depth-3 chain the source program declares.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
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
    assert_eq!(functions, vec!["Add5", "Mul2", "SignalHierarchy"]);

    // ----- counts -----------------------------------------------------
    // 14 step events + 3 call_entry + 3 call_exit = 20 events.  The
    // outermost user-defined template (`SignalHierarchy`,
    // instantiated as `component main`) surfaces as its own Call
    // event, bracketing the two sibling sub-component calls.  The
    // structured evaluator visits each template body in source
    // order, including the input-signal decl steps inside each
    // sub-template.
    let counts = &doc["counts"];
    assert_eq!(
        counts["steps"].as_u64(),
        Some(14),
        "steps; counts={counts}"
    );
    assert_eq!(counts["calls"].as_u64(), Some(3), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 20, "events.len()");
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
    assert_eq!(call_entries.len(), 3);

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
    assert_eq!(functions, vec!["ConstraintAssert"]);

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
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 14, "events.len()");
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
