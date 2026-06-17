//! Column-aware replay-navigation regression test for the Circom
//! recorder.
//!
//! Mirrors the sibling tests in `codetracer-solana-recorder`,
//! `codetracer-evm-recorder`, and the cross-recorder JS reference
//! (`codetracer-js-recorder/tests/integration/column-aware.test.ts`).
//!
//! Circom's parser (see `evaluator::EvalEvent`, plus
//! `tracer::{ComponentInstance, SignalDecl, SignalAssignment,
//! TemplateDef}`) currently tracks only 1-based line numbers — there
//! is no column source in the recorder pipeline.  The recorder still
//! opts the writer into column-aware step encoding so:
//!
//!   * `meta.dat` advertises bit 4 (`FLAG_HAS_COLUMN_AWARE_STEPS`),
//!     surfaced by `ct-print --full` as
//!     `metadata.flags.has_column_aware_steps == true`.
//!   * Each step lands through `register_step_with_column(..., None)`
//!     so the step events remain extensible: when column info ever
//!     becomes available in the pipeline, only the call sites change
//!     — the wire / reader contract is already in place.
//!
//! See `tracer.rs::start_trace` for the `enable_column_aware_steps`
//! and `register_path_with_line_lengths` call pair landed alongside
//! this test.

use std::path::PathBuf;
use std::process::Command;

/// Path to the `ct-print` binary shipped with `codetracer-trace-format-nim`.
fn ct_print_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("codetracer-trace-format-nim")
        .join(format!("ct-print{}", std::env::consts::EXE_SUFFIX))
}

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

fn test_programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-programs/circom")
}

fn ct_files_in(out_dir: &std::path::Path) -> Vec<PathBuf> {
    std::fs::read_dir(out_dir)
        .expect("read_dir")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "ct"))
        .collect()
}

/// Even though the Circom recorder cannot resolve per-step columns
/// today (the parser stores line numbers only), it still opts the
/// writer into column-aware mode so `meta.dat` bit 4 is set
/// unconditionally.  Downstream readers (Cairo / Solana / EVM / JS
/// convention) rely on this flag to decide whether to surface a
/// `column` field at all; the absence of column info per step is
/// signalled by the *step events* lacking a `column` field, not by a
/// clear flag.
#[test]
fn test_column_aware_flag_set_on_flow_test() {
    let test_name = "test_column_aware_flag_set_on_flow_test";
    let Some(ct_print) = ct_print_or_skip(test_name) else {
        return;
    };

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    codetracer_circom_recorder::recorder::record(&source_path, &out_dir, false)
        .expect("record should succeed");

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

    let flag = doc["metadata"]["flags"]["has_column_aware_steps"].as_bool();
    assert_eq!(
        flag,
        Some(true),
        "expected metadata.flags.has_column_aware_steps == true; \
         got {} for the full document; recorder must call \
         enable_column_aware_steps before emitting any step",
        doc["metadata"]
    );

    // Sanity: the trace must still contain step events (regression
    // guard against accidentally dropping the step emission path).
    let events = doc["events"].as_array().expect("events array");
    let step_count = events.iter().filter(|e| e["kind"] == "step").count();
    assert!(
        step_count > 0,
        "expected at least one step event in the column-aware \
         flow_test trace; got {step_count} (events={events:#?})"
    );
}

/// Companion regression test: the Circom parser carries no column
/// info, so every step event must land on `column == 1` (the writer's
/// column cursor after `register_step` — no `DeltaColumn` is emitted
/// when `register_step_with_column` receives `None`).  This documents
/// the current contract — if a future change wires real columns
/// through `EvalEvent` and friends, the assertion will fire and
/// direct the author to extend the test alongside the new column
/// source (cf. the Solana / EVM "distinct columns on one line"
/// fixtures).
#[test]
fn test_column_aware_steps_land_on_column_one_today() {
    let test_name = "test_column_aware_steps_land_on_column_one_today";
    let Some(ct_print) = ct_print_or_skip(test_name) else {
        return;
    };

    let tmp_dir = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    codetracer_circom_recorder::recorder::record(&source_path, &out_dir, false)
        .expect("record should succeed");

    let ct_files = ct_files_in(&out_dir);
    let output = Command::new(&ct_print)
        .args(["--full", "--strip-paths"])
        .arg(&ct_files[0])
        .output()
        .expect("failed to run ct-print --full");
    assert!(output.status.success());
    let doc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    let events = doc["events"].as_array().expect("events array");
    let off_column_steps: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["kind"] == "step")
        .filter(|e| {
            // Only flag steps whose column is non-null AND != 1; a
            // missing `column` field is still fine (reader-side
            // back-compat).
            match e.get("column").and_then(|c| c.as_i64()) {
                Some(c) => c != 1,
                None => false,
            }
        })
        .collect();

    assert!(
        off_column_steps.is_empty(),
        "Circom's parser does not yet carry column info — every step \
         event must land on column 1 (writer cursor default after \
         register_step with column=None).  If you intentionally added \
         a column source to the recorder pipeline, extend this test \
         to assert distinct columns on a multi-statement line (cf. \
         the Solana / EVM 'distinct columns on one line' fixtures).  \
         Got: {off_column_steps:#?}"
    );
}
