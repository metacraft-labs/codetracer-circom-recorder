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
    // The Circom recorder emits one step per witness-calculator step
    // for the FlowTest template's body (12 events total: dispatch +
    // signal-declaration steps + the five signal-assignment steps that
    // surface variable values).  It emits no `call_entry` events
    // (Circom is single-template here — there are no nested component
    // invocations and the recorder doesn't synthesise a call event for
    // the top-level main component).  Stable properties of the
    // canonical fixture — if they change, that's a real regression to
    // investigate, not a flake.
    let counts = &doc["counts"];
    assert_eq!(
        counts["steps"].as_u64(),
        Some(12),
        "expected 12 step events for flow_test.circom; counts={counts}",
    );
    assert_eq!(
        counts["calls"].as_u64(),
        Some(0),
        "expected 0 call events (Circom flow_test has no nested components); \
        counts={counts}",
    );

    let events = doc["events"].as_array().expect("events array");

    // ----- Call sequence: empty for a single-template circuit ---------
    let call_sequence: Vec<&str> = events
        .iter()
        .filter(|e| e["kind"] == "call_entry")
        .filter_map(|e| e["function"].as_str())
        .collect();
    assert!(
        call_sequence.is_empty(),
        "expected no call_entry events for flow_test.circom; got {:?}",
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
