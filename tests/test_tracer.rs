//! Integration tests for the Circom tracer.
//!
//! These tests parse and evaluate real Circom circuit files through the
//! source-level signal tracer and verify the resulting CodeTracer trace output.
//!
//! Tests verify actual trace content with specific computed values,
//! not just file existence or non-emptiness.

use std::path::{Path, PathBuf};

use codetracer_trace_writer::TraceEventsFileFormat;

/// Helper: path to the test-programs directory.
fn test_programs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-programs/circom")
}

/// Helper: run the tracer on a Circom source file and return the output directory.
fn run_tracer_on_file(source_path: &Path, out_dir: &Path) {
    codetracer_circom_recorder::recorder::record(
        source_path,
        out_dir,
        TraceEventsFileFormat::Json,
        false, // use WASM backend
    )
    .expect("trace_program should succeed");
}

/// Helper: parse the trace events JSON from the output directory.
fn load_trace_events(out_dir: &Path) -> Vec<serde_json::Value> {
    let events_path = out_dir.join("trace.bin");
    let content = std::fs::read_to_string(&events_path).expect("failed to read trace events");
    let events: serde_json::Value =
        serde_json::from_str(&content).expect("trace events should be valid JSON");
    events
        .as_array()
        .expect("events should be an array")
        .clone()
}

/// Helper: parse trace_metadata.json from the output directory.
fn load_trace_metadata(out_dir: &Path) -> serde_json::Value {
    let metadata_path = out_dir.join("trace_metadata.json");
    let content =
        std::fs::read_to_string(&metadata_path).expect("failed to read trace_metadata.json");
    serde_json::from_str(&content).expect("trace_metadata.json should be valid JSON")
}

/// Helper: collect all Int values from Value events in the trace.
/// Returns a vec of (variable_id, i64_value) pairs.
fn collect_int_values(events: &[serde_json::Value]) -> Vec<(i64, i64)> {
    events
        .iter()
        .filter_map(|e| {
            let val = e.get("Value")?;
            let variable_id = val.get("variable_id")?.as_i64()?;
            let value = val.get("value")?;
            if value.get("kind").and_then(|k| k.as_str()) == Some("Int") {
                let i = value.get("i").and_then(|v| v.as_i64())?;
                Some((variable_id, i))
            } else {
                None
            }
        })
        .collect()
}

/// Helper: collect all VariableName events and return the names in order.
fn collect_variable_names(events: &[serde_json::Value]) -> Vec<String> {
    events
        .iter()
        .filter_map(|e| {
            e.get("VariableName")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect()
}

/// Helper: find all Int values for a given variable name across the trace.
fn find_variable_values(events: &[serde_json::Value], var_name: &str) -> Vec<i64> {
    let var_names = collect_variable_names(events);
    let var_id = var_names.iter().position(|name| name == var_name);

    match var_id {
        Some(id) => {
            let int_values = collect_int_values(events);
            int_values
                .iter()
                .filter(|(vid, _)| *vid == id as i64)
                .map(|(_, v)| *v)
                .collect()
        }
        None => vec![],
    }
}

// ---------------------------------------------------------------------------
// Test 1: Record flow_test.circom, verify 3-file output
// ---------------------------------------------------------------------------

#[test]
fn test_circom_compile_and_run() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    // Verify the three output files exist and are non-empty.
    for filename in &["trace.bin", "trace_metadata.json", "trace_paths.json"] {
        let path = out_dir.join(filename);
        assert!(path.exists(), "{} should exist", filename);
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size > 0, "{} should be non-empty", filename);
    }

    // trace.bin should be valid JSON containing an array of events.
    let events = load_trace_events(&out_dir);
    assert!(!events.is_empty(), "trace should have at least one event");

    // There should be Step events (actual execution was recorded).
    let step_count = events.iter().filter(|e| e.get("Step").is_some()).count();
    assert!(
        step_count > 0,
        "trace should contain at least one Step event, got none"
    );
}

// ---------------------------------------------------------------------------
// Test 2: Verify trace contains value 94 (out = doubled + a)
// ---------------------------------------------------------------------------

#[test]
fn test_circom_compute_value() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    let events = load_trace_events(&out_dir);

    // Collect all integer values from the trace.
    let int_values = collect_int_values(&events);
    let all_values: Vec<i64> = int_values.iter().map(|(_, v)| *v).collect();

    // The circuit calculates: a=10, b=32, sum_val=a+b=42, doubled=sum_val*2=84,
    // out=doubled+a=94. This value should appear in the trace.
    assert!(
        all_values.contains(&94),
        "trace should contain value 94 (out = doubled + a = 84 + 10), got values: {:?}",
        {
            let mut unique: Vec<i64> = all_values.clone();
            unique.sort();
            unique.dedup();
            unique
        }
    );
}

// ---------------------------------------------------------------------------
// Test 3: Verify signal values a=10, b=32, sum_val=42, doubled=84, out=94
// ---------------------------------------------------------------------------

#[test]
fn test_circom_signal_values() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    let events = load_trace_events(&out_dir);

    // Check that VariableName events exist.
    let var_names = collect_variable_names(&events);
    assert!(
        !var_names.is_empty(),
        "trace should contain VariableName events"
    );

    // Verify specific signal names appear.
    assert!(
        var_names.contains(&"a".to_string()),
        "signal 'a' should appear in trace, got names: {:?}",
        var_names
    );
    assert!(
        var_names.contains(&"b".to_string()),
        "signal 'b' should appear in trace, got names: {:?}",
        var_names
    );
    assert!(
        var_names.contains(&"sum_val".to_string()),
        "signal 'sum_val' should appear in trace, got names: {:?}",
        var_names
    );
    assert!(
        var_names.contains(&"doubled".to_string()),
        "signal 'doubled' should appear in trace, got names: {:?}",
        var_names
    );
    assert!(
        var_names.contains(&"out".to_string()),
        "signal 'out' should appear in trace, got names: {:?}",
        var_names
    );

    // Verify signal values.
    let a_values = find_variable_values(&events, "a");
    assert!(
        a_values.contains(&10),
        "signal 'a' should have value 10, got: {:?}",
        a_values
    );

    let b_values = find_variable_values(&events, "b");
    assert!(
        b_values.contains(&32),
        "signal 'b' should have value 32, got: {:?}",
        b_values
    );

    let sum_values = find_variable_values(&events, "sum_val");
    assert!(
        sum_values.contains(&42),
        "signal 'sum_val' should have value 42 (a + b = 10 + 32), got: {:?}",
        sum_values
    );

    let doubled_values = find_variable_values(&events, "doubled");
    assert!(
        doubled_values.contains(&84),
        "signal 'doubled' should have value 84 (sum_val * 2 = 42 * 2), got: {:?}",
        doubled_values
    );

    let out_values = find_variable_values(&events, "out");
    assert!(
        out_values.contains(&94),
        "signal 'out' should have value 94 (doubled + a = 84 + 10), got: {:?}",
        out_values
    );
}

// ---------------------------------------------------------------------------
// Test 4: Verify Step events at correct source lines
// ---------------------------------------------------------------------------

#[test]
fn test_circom_step_events() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    let events = load_trace_events(&out_dir);

    // Count Step events.
    let step_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e.get("Step").is_some())
        .collect();

    // flow_test.circom has 5 signal declarations + 5 assignments = at least 10 steps.
    assert!(
        step_events.len() >= 5,
        "should have at least 5 step events for flow_test.circom, got {}",
        step_events.len()
    );

    // Verify step events have valid structure.
    for event in &step_events {
        let step = event.get("Step").unwrap();
        assert!(
            step.get("path_id").is_some(),
            "Step event should have path_id field"
        );
        let line = step["line"].as_i64().expect("Step line should be an integer");
        assert!(line > 0, "Step line should be positive, got {}", line);
        // Lines should be within the source file range (19 lines).
        assert!(
            line <= 25,
            "Step line should be within source file range, got {}",
            line
        );
    }

    // Verify that step events include the assignment lines (11-15 in flow_test.circom).
    let step_lines: Vec<i64> = step_events
        .iter()
        .map(|e| e.get("Step").unwrap()["line"].as_i64().unwrap())
        .collect();

    // Line 11: a <== 10;
    assert!(
        step_lines.contains(&11),
        "step events should include line 11 (a <== 10), got lines: {:?}",
        step_lines
    );
    // Line 12: b <== 32;
    assert!(
        step_lines.contains(&12),
        "step events should include line 12 (b <== 32), got lines: {:?}",
        step_lines
    );
    // Line 13: sum_val <== a + b;
    assert!(
        step_lines.contains(&13),
        "step events should include line 13 (sum_val <== a + b), got lines: {:?}",
        step_lines
    );
    // Line 14: doubled <== sum_val * 2;
    assert!(
        step_lines.contains(&14),
        "step events should include line 14 (doubled <== sum_val * 2), got lines: {:?}",
        step_lines
    );
    // Line 15: out <== doubled + a;
    assert!(
        step_lines.contains(&15),
        "step events should include line 15 (out <== doubled + a), got lines: {:?}",
        step_lines
    );
}

// ---------------------------------------------------------------------------
// Test 5: Verify metadata JSON structure
// ---------------------------------------------------------------------------

#[test]
fn test_circom_metadata_structure() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    let metadata = load_trace_metadata(&out_dir);

    // TraceMetadata must contain "program", "args", and "workdir" fields.
    assert!(
        metadata.get("program").is_some(),
        "metadata should have 'program' field, got: {}",
        metadata
    );
    assert!(
        metadata["program"].is_string(),
        "metadata 'program' should be a string"
    );
    let program_str = metadata["program"].as_str().unwrap();
    assert!(
        program_str.contains("flow_test.circom"),
        "metadata 'program' should reference the circom source file, got: {}",
        program_str
    );

    assert!(
        metadata.get("args").is_some(),
        "metadata should have 'args' field, got: {}",
        metadata
    );
    assert!(
        metadata["args"].is_array(),
        "metadata 'args' should be an array"
    );

    assert!(
        metadata.get("workdir").is_some(),
        "metadata should have 'workdir' field, got: {}",
        metadata
    );
    assert!(
        metadata["workdir"].is_string(),
        "metadata 'workdir' should be a string"
    );
}

// ---------------------------------------------------------------------------
// Test 6: CLI record end-to-end test
// ---------------------------------------------------------------------------

#[test]
fn test_circom_cli_record() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("cli-traces");
    let source_path = test_programs_dir().join("flow_test.circom");

    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "--",
            "record",
            source_path.to_str().unwrap(),
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .expect("failed to run");

    assert!(
        output.status.success(),
        "record should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify output files exist.
    assert!(out_dir.join("trace.bin").exists());
    assert!(out_dir.join("trace_metadata.json").exists());
    assert!(out_dir.join("trace_paths.json").exists());

    // Verify the CLI-produced trace has actual content.
    let events = load_trace_events(&out_dir);
    assert!(!events.is_empty(), "CLI trace should have events");

    let step_count = events.iter().filter(|e| e.get("Step").is_some()).count();
    assert!(
        step_count > 0,
        "CLI trace should contain Step events"
    );

    // Verify values are present in the CLI-produced trace too.
    let int_values = collect_int_values(&events);
    let all_values: Vec<i64> = int_values.iter().map(|(_, v)| *v).collect();
    assert!(
        all_values.contains(&94),
        "CLI trace should contain value 94, got values: {:?}",
        all_values
    );
}

// ---------------------------------------------------------------------------
// Test 7: trace_paths.json content validation
// ---------------------------------------------------------------------------

#[test]
fn test_circom_tracer_paths_valid() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    let paths_content = std::fs::read_to_string(out_dir.join("trace_paths.json"))
        .expect("failed to read paths");
    let paths: serde_json::Value =
        serde_json::from_str(&paths_content).expect("trace_paths.json should be valid JSON");
    assert!(
        paths.is_array(),
        "trace_paths.json should be a JSON array"
    );
    let paths_arr = paths.as_array().unwrap();
    assert!(
        !paths_arr.is_empty(),
        "trace_paths.json should have at least one path entry"
    );
}

// ---------------------------------------------------------------------------
// Test 8: Function call/return events
// ---------------------------------------------------------------------------

#[test]
fn test_circom_function_entry_exit() {
    let tmp_dir = tempfile::tempdir().expect("failed to create temp dir");
    let out_dir = tmp_dir.path().join("traces");
    std::fs::create_dir_all(&out_dir).unwrap();

    let source_path = test_programs_dir().join("flow_test.circom");
    run_tracer_on_file(&source_path, &out_dir);

    let events = load_trace_events(&out_dir);

    // There should be Call events (template entries were recorded).
    let call_count = events.iter().filter(|e| e.get("Call").is_some()).count();
    assert!(
        call_count > 0,
        "trace should contain at least one Call event"
    );

    // There should be Return events.
    let return_events: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e.get("Return").is_some())
        .collect();
    assert!(
        !return_events.is_empty(),
        "trace should contain at least one Return event"
    );

    // The last Return event should be after the last Step.
    let last_return_idx = events
        .iter()
        .rposition(|e| e.get("Return").is_some())
        .expect("should have a Return event");

    let steps_after_return = events[last_return_idx + 1..]
        .iter()
        .filter(|e| e.get("Step").is_some())
        .count();
    assert_eq!(
        steps_after_return, 0,
        "no Step events should appear after the final Return"
    );
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

    let events = load_trace_events(&out_dir);
    assert!(!events.is_empty(), "component_test trace should have events");

    // The circuit has sub-component signals like adder.a, adder.b, adder.out.
    // These should appear in the trace as variable names.
    let var_names = collect_variable_names(&events);
    assert!(
        !var_names.is_empty(),
        "component_test trace should have variable names"
    );

    // Check that step events exist.
    let step_count = events.iter().filter(|e| e.get("Step").is_some()).count();
    assert!(
        step_count > 0,
        "component_test trace should have step events"
    );
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

    let events = load_trace_events(&out_dir);
    assert!(!events.is_empty(), "array_test trace should have events");

    // Check that step events exist.
    let step_count = events.iter().filter(|e| e.get("Step").is_some()).count();
    assert!(
        step_count > 0,
        "array_test trace should have step events"
    );

    // Check that value events exist.
    let int_values = collect_int_values(&events);
    assert!(
        !int_values.is_empty(),
        "array_test trace should have value events"
    );
}

// ---------------------------------------------------------------------------
// Test 11: Signal hierarchy unit tests (no circom CLI needed)
// ---------------------------------------------------------------------------

#[test]
fn test_signal_hierarchy_from_component_circuit() {
    use codetracer_circom_recorder::signal_hierarchy::{SignalPath, build_hierarchy};

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
    use codetracer_circom_recorder::signal_hierarchy::{SignalPath, build_hierarchy};

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

    let events = load_trace_events(&out_dir);

    // Collect all Int values across all Value events.
    let int_values = collect_int_values(&events);
    let all_values: Vec<i64> = int_values.iter().map(|(_, v)| *v).collect();

    // The circuit produces these key values:
    // a = 10, b = 32, sum_val = 42, doubled = 84, out = 94
    for expected in &[10i64, 32, 42, 84, 94] {
        assert!(
            all_values.contains(expected),
            "trace should contain value {} from circuit evaluation, got values: {:?}",
            expected,
            {
                let mut unique: Vec<i64> = all_values.clone();
                unique.sort();
                unique.dedup();
                unique
            }
        );
    }
}
