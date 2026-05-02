//! CTFS audit regression tests for the Circom recorder (audit 1.58 in
//! /tmp/isonim-migration.txt).
//!
//! These tests guard the audit's concrete fixes:
//!
//!   * Audit (a) — CLI defaults to `--format ctfs` for `record`.
//!   * Audit (g) — recorder produces a canonical `.ct` multi-stream
//!     container starting with the CTFS magic bytes (`C0 DE 72 AC E2`)
//!     when invoked with `TraceEventsFileFormat::Ctfs`.
//!   * Audit (c) — `writer.arg(name, NONE_VALUE)` staging path keeps
//!     producing a valid CTFS container even for circuits that
//!     instantiate sub-component templates with input signals.
//!
//! Read-side end-to-end content assertions (i.e. that the embedded
//! event stream contains the expected `register_call` /
//! `register_special_event` records) need the
//! `codetracer_trace_reader_nim` dev-dep added and a small reader-walk
//! helper.  Tracked in AUDIT-CTFS-2026-05.md as an open follow-up
//! (also open for Cairo, Cardano, Flow, Fuel, PolkaVM, Miden, TON).

use std::path::PathBuf;

use codetracer_trace_writer_nim::TraceEventsFileFormat;

/// CTFS magic bytes: `C0 DE 72 AC E2`.  Defined in
/// `codetracer-trace-format-spec/`.
const CTFS_MAGIC: [u8; 5] = [0xC0, 0xDE, 0x72, 0xAC, 0xE2];

/// Path to the bundled Circom test programs (`flow_test.circom`,
/// `component_test.circom`, `array_test.circom`).
fn test_programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-programs/circom")
}

/// Locate the single `.ct` file produced by a recorder run.  Panics
/// if zero or more than one is present.
fn find_ct_file(out_dir: &std::path::Path) -> PathBuf {
    let entries: Vec<_> = std::fs::read_dir(out_dir)
        .expect("failed to read output directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "ct"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "expected exactly one .ct file in {}, found {:?}",
        out_dir.display(),
        entries
    );
    entries.into_iter().next().unwrap()
}

// ---------------------------------------------------------------------------
// (g) CTFS schema match — flow_test.circom produces a valid .ct file.
// ---------------------------------------------------------------------------

#[test]
fn ctfs_writer_produces_ct_container() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    codetracer_circom_recorder::recorder::record(
        &source_path,
        &out_dir,
        TraceEventsFileFormat::Ctfs,
        false, // WASM backend
    )
    .expect("record should succeed");

    let ct_path = find_ct_file(&out_dir);
    let bytes = std::fs::read(&ct_path).expect("read .ct");

    assert!(
        bytes.len() >= CTFS_MAGIC.len(),
        ".ct file is shorter than the CTFS magic header ({} bytes)",
        bytes.len()
    );
    assert_eq!(
        &bytes[..CTFS_MAGIC.len()],
        &CTFS_MAGIC,
        ".ct file does not start with the canonical CTFS magic bytes"
    );
    // Materially populated -- guards against an empty container that
    // technically has the magic header but no events / metadata / paths.
    assert!(
        bytes.len() > 64,
        ".ct file is suspiciously small ({} bytes); expected >64",
        bytes.len()
    );
}

// ---------------------------------------------------------------------------
// (a) CLI defaults to ctfs for `record --help`.
// ---------------------------------------------------------------------------

/// Locate the just-built `codetracer-circom-recorder` binary via Cargo's
/// `CARGO_BIN_EXE_<name>` env var.  Same idiom used by Flow 1.52,
/// Fuel 1.53, PolkaVM 1.55, Miden 1.56, TON 1.57.
fn recorder_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_codetracer-circom-recorder"))
}

#[test]
fn ctfs_format_advertised_in_record_help() {
    let output = std::process::Command::new(recorder_bin())
        .args(["record", "--help"])
        .output()
        .expect("spawn record --help");
    assert!(
        output.status.success(),
        "record --help should succeed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let help = String::from_utf8(output.stdout).expect("utf-8 help");

    // `ctfs` must appear as a possible value (clap renders ValueEnum
    // variants in lower-snake-case).
    assert!(
        help.contains("ctfs"),
        "record --help did not advertise `ctfs` as a --format value:\n{help}"
    );

    // The default must be `ctfs` -- catching accidental regressions of
    // the audit's default-format fix.  Clap renders `[default: <value>]`.
    assert!(
        help.contains("[default: ctfs]"),
        "record --help did not show `[default: ctfs]`:\n{help}"
    );
}

// ---------------------------------------------------------------------------
// (c) call-arg staging path -- structural smoke test.
//
// component_test.circom instantiates an Adder sub-component whose template
// has two `signal input` declarations (`a`, `b`).  Post-fix the recorder
// stages each name through `writer.arg(name, NONE_VALUE)` immediately
// before `register_call`.  This test asserts that the staging branch
// still produces a valid CTFS container -- the more thorough assertion
// (that the staged names appear on `CallRecord.args` in the embedded
// event stream) needs the `codetracer_trace_reader_nim` dev-dep + a
// reader-walk helper, tracked as an open follow-up.
// ---------------------------------------------------------------------------

#[test]
fn call_arg_staging_does_not_empty_trace() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out_dir = tmp.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("component_test.circom");
    codetracer_circom_recorder::recorder::record(
        &source_path,
        &out_dir,
        TraceEventsFileFormat::Ctfs,
        false,
    )
    .expect("record should succeed");

    let ct_path = find_ct_file(&out_dir);
    let bytes = std::fs::read(&ct_path).expect("read .ct");

    assert_eq!(&bytes[..CTFS_MAGIC.len()], &CTFS_MAGIC);
    assert!(
        bytes.len() > 64,
        "component_test trace is suspiciously small ({} bytes); the \
        writer.arg(name, NONE_VALUE) staging path may have aborted \
        the trace prematurely",
        bytes.len()
    );
}
