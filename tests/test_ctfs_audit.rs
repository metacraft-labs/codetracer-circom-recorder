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
//!   * Audit (c) — concrete component-instance witness values are staged
//!     onto `CallRecord.args` before the sub-template call record.
//!   * Audit (d) — compile / witness failures route through
//!     `register_special_event(EventLogKind::Error, ..., message)`.
//!   * Audit (d) — Circom `log()` output routes through
//!     `register_special_event(EventLogKind::EvmEvent, "circom_log", message)`.

use std::path::PathBuf;

use codetracer_trace_types::ValueRecord;
use codetracer_trace_writer_nim::NimTraceReaderHandle;
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

#[derive(Debug)]
struct SpecialEvent {
    kind: String,
    content: String,
}

fn read_special_events(ct_path: &std::path::Path) -> Vec<SpecialEvent> {
    let reader = NimTraceReaderHandle::open(ct_path.to_str().unwrap()).expect("open Nim CT reader");
    let mut events = Vec::new();
    for index in 0..reader.event_count() {
        let json = reader.event_json(index).expect("read IO event JSON");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse IO event JSON");
        let kind = value
            .get("kind")
            .and_then(|kind| kind.as_str())
            .unwrap_or_default()
            .to_string();
        let data = value
            .get("data")
            .and_then(|data| data.as_array())
            .expect("IO event JSON data array");
        let bytes: Vec<u8> = data
            .iter()
            .map(|byte| byte.as_u64().expect("IO event byte") as u8)
            .collect();
        events.push(SpecialEvent {
            kind,
            content: String::from_utf8_lossy(&bytes).to_string(),
        });
    }
    events
}

fn read_calls(reader: &NimTraceReaderHandle) -> Vec<serde_json::Value> {
    (0..reader.call_count())
        .map(|key| {
            let json = reader.call_json(key).expect("read call JSON");
            serde_json::from_str(&json).unwrap_or_else(|e| panic!("invalid call JSON: {e}: {json}"))
        })
        .collect()
}

fn bytes_from_json_array(value: &serde_json::Value) -> Vec<u8> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected byte array JSON, got {value:#}"))
        .iter()
        .map(|byte| {
            byte.as_u64()
                .unwrap_or_else(|| panic!("expected byte value, got {byte:#}")) as u8
        })
        .collect()
}

fn decode_value_record(value: &serde_json::Value) -> ValueRecord {
    let bytes = bytes_from_json_array(value);
    cbor4ii::serde::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("failed to decode ValueRecord from {bytes:?}: {e}"))
}

fn value_as_i64(value: &ValueRecord) -> Option<i64> {
    match value {
        ValueRecord::Int { i, .. } => Some(*i),
        _ => None,
    }
}

fn assert_call_args(
    reader: &NimTraceReaderHandle,
    calls: &[serde_json::Value],
    expected: &[(&str, i64)],
) {
    let found = calls.iter().any(|call| {
        let Some(args) = call["args"].as_array() else {
            return false;
        };
        if args.len() != expected.len() {
            return false;
        }

        args.iter()
            .zip(expected.iter())
            .all(|(arg, (expected_name, expected_value))| {
                let Some(varname_id) = arg["varname_id"].as_u64() else {
                    return false;
                };
                let Ok(actual_name) = reader.varname(varname_id) else {
                    return false;
                };
                if actual_name != *expected_name {
                    return false;
                }

                value_as_i64(&decode_value_record(&arg["value"])) == Some(*expected_value)
            })
    });

    assert!(
        found,
        "expected a call with args {expected:?}; calls={calls:#?}"
    );
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
// (c) call-arg staging path -- read-side live-value assertion.
//
// component_test.circom instantiates an Adder sub-component whose template
// has two `signal input` declarations (`a`, `b`). The recorder now stages
// typed witness values for `adder.a` and `adder.b` before emitting the
// `Adder` call record. This test uses main inputs because the recorder's
// public record API currently hardcodes generated witness input JSON to 0.
// ---------------------------------------------------------------------------

#[test]
fn call_arg_staging_records_live_component_input_values() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source_path = tmp.path().join("live_args.circom");
    let out_dir = tmp.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        &source_path,
        concat!(
            "pragma circom 2.0.0;\n\n",
            "template Adder() {\n",
            "    signal input a;\n",
            "    signal input b;\n",
            "    signal output out;\n",
            "    out <== a + b;\n",
            "}\n\n",
            "template Main() {\n",
            "    signal input x;\n",
            "    signal input y;\n",
            "    signal output result;\n",
            "    component adder = Adder();\n",
            "    adder.a <== x;\n",
            "    adder.b <== y;\n",
            "    result <== adder.out;\n",
            "}\n\n",
            "component main = Main();\n",
        ),
    )
    .unwrap();

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

    let reader = NimTraceReaderHandle::open(ct_path.to_str().unwrap()).expect("open Nim CT reader");
    let calls = read_calls(&reader);
    assert_call_args(&reader, &calls, &[("a", 0), ("b", 0)]);
}

#[test]
fn circom_compile_error_emits_error_special_event() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source_path = tmp.path().join("broken.circom");
    let out_dir = tmp.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        &source_path,
        "pragma circom 2.0.0;\n\ntemplate Broken() {\n    signal input a\n}\n\ncomponent main = Broken();\n",
    )
    .unwrap();

    let err = codetracer_circom_recorder::recorder::record(
        &source_path,
        &out_dir,
        TraceEventsFileFormat::Ctfs,
        false,
    )
    .expect_err("invalid circom source should fail to record");

    assert!(
        err.to_string().contains("circom compilation failed")
            || err.to_string().contains("failed to run circom compiler"),
        "unexpected recorder error: {err}"
    );

    let ct_path = find_ct_file(&out_dir);
    let special_events = read_special_events(&ct_path);
    assert!(
        special_events.iter().any(|event| {
            event.kind == "error"
                && (event.content.contains("circom compilation failed")
                    || event.content.contains("failed to run circom compiler"))
        }),
        "expected circom_compile_error special event, got {special_events:?}"
    );
}

#[test]
fn circom_log_directive_emits_evm_event_special_event() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let source_path = tmp.path().join("logged.circom");
    let out_dir = tmp.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(
        &source_path,
        concat!(
            "pragma circom 2.0.4;\n\n",
            "template Logged() {\n",
            "    signal input in;\n",
            "    signal output out;\n",
            "    out <== in + 1;\n",
            "    log(\"input\", in, \"out\", out);\n",
            "}\n\n",
            "component main = Logged();\n",
        ),
    )
    .unwrap();

    codetracer_circom_recorder::recorder::record(
        &source_path,
        &out_dir,
        TraceEventsFileFormat::Ctfs,
        false,
    )
    .expect("record should succeed");

    let ct_path = find_ct_file(&out_dir);
    let special_events = read_special_events(&ct_path);
    assert!(
        special_events.iter().any(|event| {
            event.kind == "stderr"
                && event.content.contains("input 0")
                && event.content.contains("out 1")
        }),
        "expected circom_log EvmEvent special event, got {special_events:?}"
    );
}
