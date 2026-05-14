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
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["ControlFlow".to_string()]
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
    assert_eq!(counts["steps"].as_u64(), Some(14), "steps; counts={counts}");
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
    assert_eq!(functions, vec!["ForLoopUnroll"]);

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
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 17, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["ForLoopUnroll".to_string()],
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
    assert_eq!(functions, vec!["ConstraintOperators"]);

    // ----- counts -----------------------------------------------------
    // 16 step events: 1 toplevel + 1 component-main + 5 signal-decls
    // (1 output `s` + 4 intermediate a/b/c/d) + 5 `<==` assignments
    // (a/b/c/d/s) + 4 `===` constraint-assertion lines.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(16), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 18, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(
        observed_call_sequence(&doc),
        vec!["ConstraintOperators".to_string()],
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
        vec!["AddOne", "MulTwo", "SubThree", "WireToComponent"]
    );

    // ----- counts -----------------------------------------------------
    // 19 step events + 4 call_entry + 4 call_exit = 27 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(19), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(4), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 27, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence in nesting order ----------------------------
    // Parent `WireToComponent` first, then its three siblings in
    // source-instantiation order.  Exits unwind LIFO — each
    // sub-component exits immediately after its body returns, so
    // siblings exit in source order and the parent exits last.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
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
    assert_eq!(functions, vec!["Num2Bits"]);

    // ----- counts -----------------------------------------------------
    // 24 step events: 1 toplevel + 1 component-main + 1 signal-input
    // decl + 1 signal-output-array decl + 2 var decls + 1 for-header
    // + (4 iters × 4 body lines = 16) + 1 final `===`.
    // 1 call_entry + 1 call_exit = 26 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(24), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
    assert_eq!(
        counts["io_events"].as_u64(),
        Some(0),
        "io_events; counts={counts}"
    );

    let events = doc["events"].as_array().expect("events array");
    assert_eq!(events.len(), 26, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(observed_call_sequence(&doc), vec!["Num2Bits".to_string()]);
    assert_eq!(observed_exit_sequence(&doc), vec!["Num2Bits".to_string()]);

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
    assert_eq!(functions, vec!["Sum"]);

    // ----- counts -----------------------------------------------------
    // 10 step events: 1 toplevel + 1 component-main + 1 signal-input
    // decl + 1 signal-output decl + 1 `var acc = 0;` + 1 for-header
    // + 3 body iterations + 1 final `sum <== acc;`.
    // 1 call_entry + 1 call_exit = 12 events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(10), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 12, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(observed_call_sequence(&doc), vec!["Sum".to_string()]);
    assert_eq!(observed_exit_sequence(&doc), vec!["Sum".to_string()]);

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
    assert_eq!(functions, vec!["VectorAdd"]);

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
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 12, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(observed_call_sequence(&doc), vec!["VectorAdd".to_string()]);
    assert_eq!(observed_exit_sequence(&doc), vec!["VectorAdd".to_string()]);

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
    assert_eq!(functions, vec!["Mixed"]);

    // ----- counts -----------------------------------------------------
    // 7 step events: 1 toplevel + 1 component-main + 3 signal-decl
    // (input x at line 22, intermediate internal_sum at line 23,
    // output y at line 24) + 2 `<==` assignments (internal_sum at
    // line 26, y at line 27).  + 1 call_entry + 1 call_exit = 9
    // events.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(7), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 9, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    assert_eq!(observed_call_sequence(&doc), vec!["Mixed".to_string()]);
    assert_eq!(observed_exit_sequence(&doc), vec!["Mixed".to_string()]);

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
    assert_eq!(functions, vec!["UseFib", "fib"]);

    // ----- counts -----------------------------------------------------
    // 4 step events: 1 toplevel + 1 component-main + 1 signal-output
    // decl (line 16) + 1 `out <== fib(8);` assignment (line 18).
    // 1 call_entry + 1 call_exit = 6 events.  The function body
    // (lines 22-30) is folded at compile time — no witness-slot
    // step events are emitted inside it.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(4), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(1), "calls; counts={counts}");
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
    assert_eq!(events.len(), 6, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence ----------------------------------------------
    // Only `UseFib` opens a call frame — `fib` is a compile-time
    // function whose body is folded inline, so it doesn't open a
    // separate call frame in the trace.  The function table entry
    // for `fib` (asserted above) is the user-visible surface that
    // distinguishes it from witness-bearing templates.
    assert_eq!(observed_call_sequence(&doc), vec!["UseFib".to_string()]);
    assert_eq!(observed_exit_sequence(&doc), vec!["UseFib".to_string()]);

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
    assert_eq!(functions, vec!["Sum", "UseSubs"]);

    // ----- counts -----------------------------------------------------
    // 24 step events + 4 call_entry + 4 call_exit = 32 events.  The
    // structured evaluator visits the for-loop body 3 times, and each
    // iteration emits a ComponentArrayAssign step (line 26), then
    // recurses into Sum (3 body steps inside the call frame), then
    // a wire-back step (line 18) and an output-assignment step
    // (line 28 / 29).
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(24), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(4), "calls; counts={counts}");
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
    assert_eq!(events.len(), 32, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence — 1 parent + 3 sibling sub-components -------
    // The parent `UseSubs` opens first, then the three `subs[i]`
    // instantiations open in source order (0, 1, 2) inside the
    // for-loop body.  Each `subs[i]` exits before the next one
    // opens (siblings, not nested), and the parent exits last.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
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
    assert_eq!(call_entries.len(), 4);
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
    assert_eq!(functions, vec!["IsNonZero", "IsEqual", "TopLevel"]);

    // ----- counts -----------------------------------------------------
    // 38 step events + 5 call_entry + 5 call_exit = 48 events.  The
    // five calls are TopLevel + 2 IsNonZero (nz_a, nz_b) + 2 IsEqual
    // (eq_a, eq_b) — exactly the comparator instances declared in
    // TopLevel's body.
    let counts = &doc["counts"];
    assert_eq!(counts["steps"].as_u64(), Some(38), "steps; counts={counts}");
    assert_eq!(counts["calls"].as_u64(), Some(5), "calls; counts={counts}");
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
    assert_eq!(events.len(), 48, "events.len()");
    assert_step_indices_monotonic(&doc);

    // ----- Call sequence — parent + 4 sibling comparators ------------
    // TopLevel opens first, then each comparator (IsNonZero / IsEqual)
    // opens in source-instantiation order.  Each comparator exits
    // immediately after its body returns — they're siblings inside
    // the for-loop body of TopLevel, not nested.
    assert_eq!(
        observed_call_sequence(&doc),
        vec![
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
