//! Tracer implementation for Circom circuits.
//!
//! Compiles a Circom source file using the `circom` compiler, runs the
//! generated WASM witness calculator via Wasmtime, extracts signal values
//! from the witness, and emits CodeTracer trace events.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use codetracer_trace_types::{Line, TypeKind, ValueRecord, NONE_VALUE};
use codetracer_trace_writer::trace_writer::TraceWriter;
use codetracer_trace_writer::{TraceEventsFileFormat, create_trace_writer};
use eyre::{Context, Result, eyre};
use num_bigint::BigUint;
use wasmtime::{Engine, Func, Linker, Module, Store, Val};

use crate::source_map::SourceMap;

/// Convert a wasmtime error to an eyre error.
/// Wasmtime's Error type doesn't implement std::error::Error,
/// so we convert through its Display impl.
fn wasm_err(e: wasmtime::Error) -> eyre::Report {
    eyre!("{}", e)
}

// ---------------------------------------------------------------------------
// Circom witness calculator (real implementation via Wasmtime)
// ---------------------------------------------------------------------------

/// A signal entry parsed from the .sym file.
#[derive(Debug, Clone)]
struct SymbolEntry {
    /// Witness index for this signal.
    witness_index: usize,
    /// Signal name without the "main." prefix (e.g. "a", "out").
    name: String,
    /// Full qualified name (e.g. "main.a").
    #[allow(dead_code)]
    full_name: String,
}

/// Parse a .sym file produced by `circom --sym`.
///
/// Format: `witness_index,constraint_index,component_index,signal_name`
fn parse_sym_file(sym_path: &Path) -> Result<Vec<SymbolEntry>> {
    let content = std::fs::read_to_string(sym_path)
        .with_context(|| format!("failed to read .sym file: {}", sym_path.display()))?;

    let mut entries = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ',').collect();
        if parts.len() < 4 {
            continue;
        }
        let witness_index: usize = parts[0]
            .parse()
            .with_context(|| format!("invalid witness index in .sym line: {line}"))?;
        let full_name = parts[3].to_string();
        // Strip "main." prefix for display.
        let name = full_name
            .strip_prefix("main.")
            .unwrap_or(&full_name)
            .to_string();
        entries.push(SymbolEntry {
            witness_index,
            name,
            full_name,
        });
    }
    Ok(entries)
}

/// FNV-1a hash (64-bit) matching Circom's JavaScript implementation.
///
/// Used to hash signal names for `setInputSignal(hMSB, hLSB, index)`.
fn fnv_hash(name: &str) -> u64 {
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for byte in name.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x0100_0000_01B3);
    }
    hash
}

/// Helper to call a WASM function that takes no args and returns one i32.
fn call_i32(func: &Func, store: &mut Store<()>) -> Result<i32> {
    let mut results = [Val::I32(0)];
    func.call(store, &[], &mut results).map_err(wasm_err)?;
    match results[0] {
        Val::I32(v) => Ok(v),
        _ => Err(eyre!("expected i32 return value")),
    }
}

/// Run the circom WASM witness generator and return all witness values.
///
/// This implements the same protocol as Circom's JavaScript witness_calculator:
/// 1. Load the WASM module via Wasmtime
/// 2. Call `init(0)` to initialize
/// 3. For each input signal, hash the name, write values to shared memory,
///    and call `setInputSignal(hMSB, hLSB, index)`
/// 4. Read back all witness values via `getWitness(i)` + `readSharedRWMemory(j)`
fn calculate_witness(
    wasm_path: &Path,
    inputs: &HashMap<String, Vec<String>>,
) -> Result<Vec<BigUint>> {
    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("failed to read WASM file: {}", wasm_path.display()))?;

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm_bytes).map_err(wasm_err)?;

    let mut store = Store::new(&engine, ());
    let mut linker = Linker::new(&engine);

    // Register runtime callbacks that the circom WASM module imports.
    linker
        .func_wrap("runtime", "exceptionHandler", |_code: i32| {})
        .map_err(wasm_err)?;
    linker
        .func_wrap("runtime", "printErrorMessage", || {})
        .map_err(wasm_err)?;
    linker
        .func_wrap("runtime", "writeBufferMessage", || {})
        .map_err(wasm_err)?;
    linker
        .func_wrap("runtime", "showSharedRWMemory", || {})
        .map_err(wasm_err)?;

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(wasm_err)?;

    // Get exported functions.
    let mut get_fn = |name: &str| -> Result<Func> {
        instance
            .get_func(&mut store, name)
            .ok_or_else(|| eyre!("missing WASM export: {name}"))
    };

    let get_version = get_fn("getVersion")?;
    let get_field_num_len32 = get_fn("getFieldNumLen32")?;
    let get_witness_size = get_fn("getWitnessSize")?;
    let init = get_fn("init")?;
    let get_input_signal_size = get_fn("getInputSignalSize")?;
    let set_input_signal = get_fn("setInputSignal")?;
    let get_witness = get_fn("getWitness")?;
    let read_shared_rw_memory = get_fn("readSharedRWMemory")?;
    let write_shared_rw_memory = get_fn("writeSharedRWMemory")?;
    let get_input_size = get_fn("getInputSize")?;
    let get_raw_prime = get_fn("getRawPrime")?;

    // Query field parameters.
    let _version = call_i32(&get_version, &mut store)?;
    let n32 = call_i32(&get_field_num_len32, &mut store)? as usize;
    let witness_size = call_i32(&get_witness_size, &mut store)? as usize;
    let total_input_size = call_i32(&get_input_size, &mut store)? as usize;

    eprintln!(
        "WASM witness calculator: n32={}, witness_size={}, total_inputs={}",
        n32, witness_size, total_input_size
    );

    // Get the prime to normalize inputs.
    get_raw_prime
        .call(&mut store, &[], &mut [])
        .map_err(wasm_err)?;
    let mut prime_arr = vec![0u32; n32];
    for j in 0..n32 {
        let mut results = [Val::I32(0)];
        read_shared_rw_memory
            .call(&mut store, &[Val::I32(j as i32)], &mut results)
            .map_err(wasm_err)?;
        prime_arr[j] = results[0].unwrap_i32() as u32;
    }
    let prime = from_array32_le(&prime_arr);
    eprintln!("Circuit prime: {}", prime);

    // Initialize the witness calculator.
    init.call(&mut store, &[Val::I32(0)], &mut [])
        .map_err(wasm_err)?;

    // Set input signals.
    let mut input_counter = 0usize;
    for (signal_name, values) in inputs {
        let h = fnv_hash(signal_name);
        let h_msb = (h >> 32) as i32;
        let h_lsb = (h & 0xFFFF_FFFF) as i32;

        let mut results = [Val::I32(0)];
        get_input_signal_size
            .call(
                &mut store,
                &[Val::I32(h_msb), Val::I32(h_lsb)],
                &mut results,
            )
            .map_err(wasm_err)?;
        let signal_size = results[0].unwrap_i32() as usize;

        if values.len() != signal_size {
            return Err(eyre!(
                "Signal '{}' expects {} values, got {}",
                signal_name,
                signal_size,
                values.len()
            ));
        }

        for (i, val_str) in values.iter().enumerate() {
            let val: BigUint = val_str.parse().with_context(|| {
                format!("invalid input value for signal '{signal_name}': {val_str}")
            })?;
            let val = val % &prime;
            let arr = to_array32_le(&val, n32);

            for j in 0..n32 {
                write_shared_rw_memory
                    .call(
                        &mut store,
                        &[Val::I32(j as i32), Val::I32(arr[j] as i32)],
                        &mut [],
                    )
                    .map_err(wasm_err)?;
            }

            set_input_signal
                .call(
                    &mut store,
                    &[Val::I32(h_msb), Val::I32(h_lsb), Val::I32(i as i32)],
                    &mut [],
                )
                .map_err(wasm_err)?;
            input_counter += 1;
        }
    }

    if input_counter < total_input_size {
        return Err(eyre!(
            "Not all inputs set: {} out of {}",
            input_counter,
            total_input_size
        ));
    }

    // Read witness values.
    let mut witness = Vec::with_capacity(witness_size);
    for i in 0..witness_size {
        get_witness
            .call(&mut store, &[Val::I32(i as i32)], &mut [])
            .map_err(wasm_err)?;
        let mut arr = vec![0u32; n32];
        for j in 0..n32 {
            let mut results = [Val::I32(0)];
            read_shared_rw_memory
                .call(&mut store, &[Val::I32(j as i32)], &mut results)
                .map_err(wasm_err)?;
            arr[j] = results[0].unwrap_i32() as u32;
        }
        witness.push(from_array32_le(&arr));
    }

    Ok(witness)
}

/// Convert little-endian u32 limbs to BigUint.
///
/// The WASM shared memory stores field elements as u32 limbs in
/// little-endian order (limb 0 = least significant).
fn from_array32_le(arr: &[u32]) -> BigUint {
    let mut bytes = Vec::with_capacity(arr.len() * 4);
    for &limb in arr {
        bytes.extend_from_slice(&limb.to_le_bytes());
    }
    BigUint::from_bytes_le(&bytes)
}

/// Convert BigUint to little-endian u32 limbs of given size.
fn to_array32_le(val: &BigUint, size: usize) -> Vec<u32> {
    let bytes = val.to_bytes_le();
    let mut result = vec![0u32; size];
    for (i, chunk) in bytes.chunks(4).enumerate() {
        if i >= size {
            break;
        }
        let mut buf = [0u8; 4];
        buf[..chunk.len()].copy_from_slice(chunk);
        result[i] = u32::from_le_bytes(buf);
    }
    result
}

// ---------------------------------------------------------------------------
// Circom source parser helpers (kept for source-line mapping in trace events)
// ---------------------------------------------------------------------------

/// A parsed signal declaration.
#[derive(Debug, Clone)]
struct SignalDecl {
    /// Signal name (e.g. "a", "out").
    name: String,
    /// Signal kind: input, output, or intermediate.
    kind: SignalKind,
    /// 1-based line number where this declaration appears.
    line: u32,
}

/// Kind of a Circom signal.
#[derive(Debug, Clone, PartialEq)]
enum SignalKind {
    Input,
    Output,
    Intermediate,
}

/// A parsed signal assignment (`signal <== expression`).
#[derive(Debug, Clone)]
struct SignalAssignment {
    /// Target signal name.
    target: String,
    /// 1-based line number where this assignment appears.
    line: u32,
}

/// A parsed template definition.
#[derive(Debug, Clone)]
struct TemplateDef {
    /// Template name.
    name: String,
    /// 1-based line number of the `template` keyword.
    line: u32,
}

// ---------------------------------------------------------------------------
// The main tracer
// ---------------------------------------------------------------------------

/// The main tracer struct that captures Circom execution traces.
pub struct CircomTracer {
    writer: Box<dyn TraceWriter + Send>,
    /// Field element type id (registered once).
    field_type_id: Option<codetracer_trace_types::TypeId>,
}

impl CircomTracer {
    /// Trace a Circom circuit and write CodeTracer output files.
    ///
    /// 1. Compiles the .circom source using the `circom` CLI to produce
    ///    a WASM witness generator and a .sym symbol table.
    /// 2. Runs the WASM witness generator via Wasmtime to compute all signal values.
    /// 3. Maps signal names to witness values using the .sym file.
    /// 4. Emits Step, Call, Return, and Value trace events at the correct source lines.
    pub fn trace_program(
        source_path: &Path,
        source_code: &str,
        out_dir: &Path,
        format: TraceEventsFileFormat,
    ) -> Result<()> {
        // -- 1. Compile the Circom source --------------------------------------------------
        let compile_dir = tempfile::tempdir()
            .with_context(|| "failed to create temp dir for circom compilation")?;

        let circom_bin = std::env::var("CIRCOM_BIN").unwrap_or_else(|_| "circom".to_string());

        let compile_output = Command::new(&circom_bin)
            .arg(source_path)
            .arg("--wasm")
            .arg("--sym")
            .arg("--O0") // Disable optimization to preserve all signals in the witness.
            .arg("-o")
            .arg(compile_dir.path())
            .output()
            .with_context(|| format!("failed to run circom compiler ('{circom_bin}')"))?;

        if !compile_output.status.success() {
            let stderr = String::from_utf8_lossy(&compile_output.stderr);
            let stdout = String::from_utf8_lossy(&compile_output.stdout);
            return Err(eyre!(
                "circom compilation failed:\nstdout: {stdout}\nstderr: {stderr}"
            ));
        }

        eprintln!("Circom compilation succeeded");

        // Find the generated files. The WASM goes into <stem>_js/<stem>.wasm.
        let stem = source_path
            .file_stem()
            .ok_or_else(|| eyre!("source path has no file stem"))?
            .to_string_lossy();

        let wasm_path = compile_dir
            .path()
            .join(format!("{stem}_js"))
            .join(format!("{stem}.wasm"));
        let sym_path = compile_dir.path().join(format!("{stem}.sym"));

        if !wasm_path.exists() {
            return Err(eyre!(
                "circom did not produce expected WASM file: {}",
                wasm_path.display()
            ));
        }
        if !sym_path.exists() {
            return Err(eyre!(
                "circom did not produce expected .sym file: {}",
                sym_path.display()
            ));
        }

        // -- 2. Parse the .sym file -------------------------------------------------------
        let symbols = parse_sym_file(&sym_path)?;
        eprintln!("Parsed {} symbols from .sym file", symbols.len());

        // -- 3. Prepare inputs ------------------------------------------------------------
        let signal_decls = parse_signal_declarations(source_code);
        let mut inputs: HashMap<String, Vec<String>> = HashMap::new();
        for sig in &signal_decls {
            if sig.kind == SignalKind::Input {
                // Default input value is "0". In a real usage, inputs would come
                // from a JSON file; for tracing purposes we use 0.
                inputs.insert(sig.name.clone(), vec!["0".to_string()]);
            }
        }

        // -- 4. Run the witness generator -------------------------------------------------
        let witness = calculate_witness(&wasm_path, &inputs)?;
        eprintln!("Computed witness with {} elements", witness.len());

        // -- 5. Map symbol names to values ------------------------------------------------
        let mut values: HashMap<String, i64> = HashMap::new();
        for sym in &symbols {
            if sym.witness_index < witness.len() {
                let val = &witness[sym.witness_index];
                let val_i64 = bigint_to_i64(val);
                values.insert(sym.name.clone(), val_i64);
            }
        }

        eprintln!("Mapped {} signal values from witness", values.len());
        for (name, val) in &values {
            eprintln!("  {name} = {val}");
        }

        // -- 6. Parse source for trace event emission -------------------------------------
        let source_map = SourceMap::from_source(source_path, source_code);
        let assignments = parse_signal_assignments(source_code);
        let templates = parse_template_definitions(source_code);

        // -- 7. Create the trace writer ---------------------------------------------------
        let program_str = source_path.to_string_lossy();
        let mut tracer = CircomTracer {
            writer: create_trace_writer(&program_str, &[], format),
            field_type_id: None,
        };

        // -- 8. Initialise output files ---------------------------------------------------
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("cannot create output dir: {}", out_dir.display()))?;

        let events_path = out_dir.join("trace.bin");
        let metadata_path = out_dir.join("trace_metadata.json");
        let paths_path = out_dir.join("trace_paths.json");

        TraceWriter::begin_writing_trace_events(&mut *tracer.writer, &events_path)
            .map_err(|e| eyre!("{e}"))?;
        TraceWriter::begin_writing_trace_metadata(&mut *tracer.writer, &metadata_path)
            .map_err(|e| eyre!("{e}"))?;
        TraceWriter::begin_writing_trace_paths(&mut *tracer.writer, &paths_path)
            .map_err(|e| eyre!("{e}"))?;

        // -- 9. Start the trace -----------------------------------------------------------
        TraceWriter::start(&mut *tracer.writer, source_path, Line(1));

        let field_type_id =
            TraceWriter::ensure_type_id(&mut *tracer.writer, TypeKind::Int, "field");
        tracer.field_type_id = Some(field_type_id);

        // -- 10. Emit trace events --------------------------------------------------------
        tracer.emit_source_trace(
            source_path,
            &source_map,
            &signal_decls,
            &assignments,
            &templates,
            &values,
        )?;

        // -- 11. Finish writing -----------------------------------------------------------
        TraceWriter::finish_writing_trace_events(&mut *tracer.writer)
            .map_err(|e| eyre!("{e}"))?;
        TraceWriter::finish_writing_trace_metadata(&mut *tracer.writer)
            .map_err(|e| eyre!("{e}"))?;
        TraceWriter::finish_writing_trace_paths(&mut *tracer.writer)
            .map_err(|e| eyre!("{e}"))?;

        Ok(())
    }

    /// Emit trace events by walking through the source code.
    fn emit_source_trace(
        &mut self,
        source_path: &Path,
        _source_map: &SourceMap,
        signals: &[SignalDecl],
        assignments: &[SignalAssignment],
        templates: &[TemplateDef],
        values: &HashMap<String, i64>,
    ) -> Result<()> {
        let field_type_id = self.field_type_id.unwrap();

        // Emit a Call for each template.
        for template in templates {
            let fn_id = TraceWriter::ensure_function_id(
                &mut *self.writer,
                &template.name,
                source_path,
                Line(template.line as i64),
            );
            TraceWriter::register_call(&mut *self.writer, fn_id, vec![]);
        }

        // Emit Step events for signal declarations.
        for sig in signals {
            TraceWriter::register_step(
                &mut *self.writer,
                source_path,
                Line(sig.line as i64),
            );
        }

        // Emit Step + Value events for signal assignments.
        for assign in assignments {
            TraceWriter::register_step(
                &mut *self.writer,
                source_path,
                Line(assign.line as i64),
            );

            if let Some(&val) = values.get(&assign.target) {
                let value = ValueRecord::Int {
                    i: val,
                    type_id: field_type_id,
                };
                TraceWriter::register_variable_with_full_value(
                    &mut *self.writer,
                    &assign.target,
                    value,
                );
            }
        }

        // Emit Return for each template.
        for _template in templates {
            TraceWriter::register_return(&mut *self.writer, NONE_VALUE);
        }

        Ok(())
    }
}

/// Convert a BigUint witness value to i64 for trace output.
fn bigint_to_i64(val: &BigUint) -> i64 {
    let bytes = val.to_bytes_le();
    if bytes.len() <= 8 {
        let mut buf = [0u8; 8];
        buf[..bytes.len()].copy_from_slice(&bytes);
        let raw = u64::from_le_bytes(buf);
        if raw <= i64::MAX as u64 {
            raw as i64
        } else {
            0
        }
    } else {
        if bytes[8..].iter().all(|&b| b == 0) {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            let raw = u64::from_le_bytes(buf);
            if raw <= i64::MAX as u64 {
                raw as i64
            } else {
                0
            }
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Circom source parser helpers
// ---------------------------------------------------------------------------

/// Parse signal declarations from Circom source code.
fn parse_signal_declarations(source: &str) -> Vec<SignalDecl> {
    let mut signals = Vec::new();

    for (line_idx, line_text) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let trimmed = line_text.trim();

        if !trimmed.starts_with("signal ") {
            continue;
        }

        let after_signal = trimmed[7..].trim();

        let (kind, rest) = if after_signal.starts_with("input ") {
            (SignalKind::Input, after_signal[6..].trim())
        } else if after_signal.starts_with("output ") {
            (SignalKind::Output, after_signal[7..].trim())
        } else {
            (SignalKind::Intermediate, after_signal)
        };

        let name = rest.trim_end_matches(';').trim().to_string();
        if !name.is_empty() {
            signals.push(SignalDecl {
                name,
                kind,
                line: line_num,
            });
        }
    }

    signals
}

/// Parse signal assignments from Circom source code.
fn parse_signal_assignments(source: &str) -> Vec<SignalAssignment> {
    let mut assignments = Vec::new();

    for (line_idx, line_text) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let trimmed = line_text.trim();

        if let Some(arrow_pos) = trimmed.find("<==") {
            let target = trimmed[..arrow_pos].trim().to_string();
            if !target.is_empty() {
                assignments.push(SignalAssignment {
                    target,
                    line: line_num,
                });
            }
        }
    }

    assignments
}

/// Parse template definitions from Circom source code.
fn parse_template_definitions(source: &str) -> Vec<TemplateDef> {
    let mut templates = Vec::new();

    for (line_idx, line_text) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let trimmed = line_text.trim();

        if !trimmed.starts_with("template ") {
            continue;
        }

        let after_template = &trimmed[9..];
        if let Some(paren_pos) = after_template.find('(') {
            let name = after_template[..paren_pos].trim().to_string();
            if !name.is_empty() {
                templates.push(TemplateDef {
                    name,
                    line: line_num,
                });
            }
        }
    }

    templates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fnv_hash_consistency() {
        let h = fnv_hash("in");
        assert_ne!(h, 0, "FNV hash should be non-zero");
        assert_eq!(fnv_hash("in"), fnv_hash("in"));
        assert_ne!(fnv_hash("in"), fnv_hash("out"));
    }

    #[test]
    fn test_bigint_conversions() {
        let val = BigUint::from(42u64);
        let arr = to_array32_le(&val, 8);
        let roundtrip = from_array32_le(&arr);
        assert_eq!(val, roundtrip);

        let zero = BigUint::from(0u64);
        let arr = to_array32_le(&zero, 8);
        let roundtrip = from_array32_le(&arr);
        assert_eq!(zero, roundtrip);

        let large = BigUint::from(u64::MAX);
        let arr = to_array32_le(&large, 8);
        let roundtrip = from_array32_le(&arr);
        assert_eq!(large, roundtrip);
    }

    #[test]
    fn test_bigint_to_i64() {
        assert_eq!(bigint_to_i64(&BigUint::from(0u64)), 0);
        assert_eq!(bigint_to_i64(&BigUint::from(42u64)), 42);
        assert_eq!(bigint_to_i64(&BigUint::from(94u64)), 94);
        assert_eq!(bigint_to_i64(&BigUint::from(i64::MAX as u64)), i64::MAX);
    }

    #[test]
    fn test_parse_signal_declarations() {
        let source = r#"
template FlowTest() {
    signal input in;
    signal a;
    signal b;
    signal output out;
}
"#;
        let signals = parse_signal_declarations(source);
        assert_eq!(signals.len(), 4);
        assert_eq!(signals[0].name, "in");
        assert_eq!(signals[0].kind, SignalKind::Input);
        assert_eq!(signals[1].name, "a");
        assert_eq!(signals[1].kind, SignalKind::Intermediate);
        assert_eq!(signals[2].name, "b");
        assert_eq!(signals[2].kind, SignalKind::Intermediate);
        assert_eq!(signals[3].name, "out");
        assert_eq!(signals[3].kind, SignalKind::Output);
    }

    #[test]
    fn test_parse_signal_assignments() {
        let source = r#"
    a <== 10;
    b <== 32;
    sum_val <== a + b;
    doubled <== sum_val * 2;
    out <== doubled + a;
"#;
        let assignments = parse_signal_assignments(source);
        assert_eq!(assignments.len(), 5);
        assert_eq!(assignments[0].target, "a");
        assert_eq!(assignments[1].target, "b");
        assert_eq!(assignments[2].target, "sum_val");
        assert_eq!(assignments[3].target, "doubled");
        assert_eq!(assignments[4].target, "out");
    }

    #[test]
    fn test_parse_template_definitions() {
        let source = "template FlowTest() {\n}\n";
        let templates = parse_template_definitions(source);
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].name, "FlowTest");
        assert_eq!(templates[0].line, 1);
    }

    #[test]
    fn test_parse_sym_file() {
        let dir = tempfile::tempdir().unwrap();
        let sym_path = dir.path().join("test.sym");
        std::fs::write(
            &sym_path,
            "1,1,0,main.out\n2,-1,0,main.in\n3,-1,0,main.a\n",
        )
        .unwrap();

        let entries = parse_sym_file(&sym_path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].witness_index, 1);
        assert_eq!(entries[0].name, "out");
        assert_eq!(entries[1].witness_index, 2);
        assert_eq!(entries[1].name, "in");
        assert_eq!(entries[2].witness_index, 3);
        assert_eq!(entries[2].name, "a");
    }
}
