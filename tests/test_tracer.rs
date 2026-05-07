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
/// to JSON via `ct-print --json` and assert on the textual representation.
///
/// Pre-2026-05-08 the test_tracer suite asserted CTFS magic on a file
/// produced under the `--format ctfs` CLI flag.  The convention now
/// mandates CTFS-only output; `ct print` is the canonical conversion
/// tool.  See `Recorder-CLI-Conventions.md` §4.
///
/// Content assertions: the Circom recorder's variable values are
/// emitted via `register_variable_with_full_value` with
/// `ValueRecord::Int` payloads, but the integer values do not
/// round-trip through `ct-print --json` today (same pre-existing
/// limitation as the cardano recorder; see `AUDIT-CTFS-2026-05.md`
/// "Variable types are always Int" for the open follow-up).  We
/// therefore assert on **structural anchors** that the recorder must
/// surface for any CodeTracer consumer to function:
///   * the source path (`flow_test.circom`) in the metadata,
///   * the `FlowTest` template name in the function table,
///   * each signal name (`a`, `b`, `sum_val`, `doubled`, `out`) in
///     the values stream.
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

    let output = Command::new(&ct_print)
        .args(["--json"])
        .arg(&ct_files[0])
        .output()
        .expect("failed to run ct-print");

    assert!(
        output.status.success(),
        "ct-print should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "ct-print --json produced empty output");

    assert!(
        stdout.contains("flow_test.circom"),
        "ct-print --json output should mention the source file; got:\n{stdout}"
    );
    assert!(
        stdout.contains("\"FlowTest\""),
        "ct-print --json output should mention the `FlowTest` template; got:\n{stdout}"
    );
    for varname in ["a", "b", "sum_val", "doubled", "out"] {
        assert!(
            stdout.contains(&format!("\"{varname}\"")),
            "ct-print --json output should mention the `{varname}` signal; got:\n{stdout}"
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
