//! Tracer implementation for Circom circuits.
//!
//! Compiles a Circom source file using the `circom` compiler, runs the
//! generated WASM witness calculator via Wasmtime, extracts signal values
//! from the witness, and emits CodeTracer trace events.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use codetracer_trace_types::{EventLogKind, FunctionId, Line, TypeKind, ValueRecord, NONE_VALUE};
use codetracer_trace_writer_nim::trace_writer::TraceWriter;
use codetracer_trace_writer_nim::{create_trace_writer, TraceEventsFileFormat};
use eyre::{eyre, Context, Result};
use num_bigint::BigUint;
use wasmtime::{Caller, Engine, Func, Linker, Module, Store, Val};

use crate::cpp_witness::{self, CompilerSourceMap};
use crate::evaluator::{self as eval_mod, EvalContext, EvalEventKind, Template as ETemplate};
use crate::signal_hierarchy::{build_hierarchy, SignalPath};
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

/// Parse a signal name into a hierarchical `SignalPath`.
///
/// This handles:
/// - Simple signals: `"main.out"` -> `["main", "out"]`
/// - Sub-component signals: `"main.adder.out"` -> `["main", "adder", "out"]`
/// - Array signals: `"main.values[0]"` -> `["main", "values[0]"]`
/// - Combined: `"main.comp.arr[3]"` -> `["main", "comp", "arr[3]"]`
pub fn parse_signal_hierarchy(name: &str) -> SignalPath {
    SignalPath::parse(name)
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
fn call_i32<T>(func: &Func, store: &mut Store<T>) -> Result<i32> {
    let mut results = [Val::I32(0)];
    func.call(store, &[], &mut results).map_err(wasm_err)?;
    match results[0] {
        Val::I32(v) => Ok(v),
        _ => Err(eyre!("expected i32 return value")),
    }
}

#[derive(Default)]
struct WitnessRuntime {
    log_buffer: String,
    logs: Vec<String>,
}

struct WitnessCalculation {
    witness: Vec<BigUint>,
    logs: Vec<String>,
}

fn read_message_from_caller(caller: &mut Caller<'_, WitnessRuntime>) -> Option<String> {
    let get_message_char = caller
        .get_export("getMessageChar")
        .and_then(|export| export.into_func())?;

    let mut message = String::new();
    loop {
        let mut results = [Val::I32(0)];
        get_message_char
            .call(&mut *caller, &[], &mut results)
            .ok()?;
        let ch = results[0].unwrap_i32();
        if ch == 0 {
            break;
        }
        message.push(char::from_u32(ch as u32).unwrap_or(char::REPLACEMENT_CHARACTER));
    }
    Some(message)
}

fn shared_rw_memory_value_from_caller(caller: &mut Caller<'_, WitnessRuntime>) -> Option<BigUint> {
    let get_field_num_len32 = caller
        .get_export("getFieldNumLen32")
        .and_then(|export| export.into_func())?;
    let read_shared_rw_memory = caller
        .get_export("readSharedRWMemory")
        .and_then(|export| export.into_func())?;

    let mut n32_result = [Val::I32(0)];
    get_field_num_len32
        .call(&mut *caller, &[], &mut n32_result)
        .ok()?;
    let n32 = n32_result[0].unwrap_i32() as usize;

    let mut limbs = vec![0u32; n32];
    for (j, limb) in limbs.iter_mut().enumerate() {
        let mut results = [Val::I32(0)];
        read_shared_rw_memory
            .call(&mut *caller, &[Val::I32(j as i32)], &mut results)
            .ok()?;
        *limb = results[0].unwrap_i32() as u32;
    }

    Some(from_array32_le(&limbs))
}

fn append_log_part(runtime: &mut WitnessRuntime, part: &str) {
    if !runtime.log_buffer.is_empty() {
        runtime.log_buffer.push(' ');
    }
    runtime.log_buffer.push_str(part);
}

/// Run the circom WASM witness generator and return all witness values and
/// `log()` directive output captured through the generated runtime callbacks.
///
/// Circom `log()` is documented as witness-generation debug output:
/// https://docs.circom.io/circom-language/code-quality/debugging-operations/
///
/// This implements the same protocol as Circom's JavaScript witness_calculator:
/// 1. Load the WASM module via Wasmtime
/// 2. Call `init(0)` to initialize
/// 3. For each input signal, hash the name, write values to shared memory,
///    and call `setInputSignal(hMSB, hLSB, index)`
/// 4. Read back all witness values via `getWitness(i)` + `readSharedRWMemory(j)`
#[allow(clippy::needless_range_loop)]
fn calculate_witness(
    wasm_path: &Path,
    inputs: &HashMap<String, Vec<String>>,
) -> Result<WitnessCalculation> {
    let wasm_bytes = std::fs::read(wasm_path)
        .with_context(|| format!("failed to read WASM file: {}", wasm_path.display()))?;

    let engine = Engine::default();
    let module = Module::new(&engine, &wasm_bytes).map_err(wasm_err)?;

    let mut store = Store::new(&engine, WitnessRuntime::default());
    let mut linker = Linker::new(&engine);

    // Register runtime callbacks that the circom WASM module imports.
    linker
        .func_wrap("runtime", "exceptionHandler", |_code: i32| {})
        .map_err(wasm_err)?;
    linker
        .func_wrap(
            "runtime",
            "printErrorMessage",
            |mut caller: Caller<'_, WitnessRuntime>| {
                let _ = read_message_from_caller(&mut caller);
            },
        )
        .map_err(wasm_err)?;
    linker
        .func_wrap(
            "runtime",
            "writeBufferMessage",
            |mut caller: Caller<'_, WitnessRuntime>| {
                if let Some(message) = read_message_from_caller(&mut caller) {
                    if message == "\n" {
                        let runtime = caller.data_mut();
                        if !runtime.log_buffer.is_empty() {
                            runtime.logs.push(std::mem::take(&mut runtime.log_buffer));
                        }
                    } else {
                        append_log_part(caller.data_mut(), &message);
                    }
                }
            },
        )
        .map_err(wasm_err)?;
    linker
        .func_wrap(
            "runtime",
            "showSharedRWMemory",
            |mut caller: Caller<'_, WitnessRuntime>| {
                if let Some(value) = shared_rw_memory_value_from_caller(&mut caller) {
                    append_log_part(caller.data_mut(), &value.to_string());
                }
            },
        )
        .map_err(wasm_err)?;

    let instance = linker.instantiate(&mut store, &module).map_err(wasm_err)?;

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

    let mut runtime = store.into_data();
    if !runtime.log_buffer.is_empty() {
        runtime.logs.push(runtime.log_buffer);
    }

    Ok(WitnessCalculation {
        witness,
        logs: runtime.logs,
    })
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
#[allow(dead_code)]
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

/// A parsed component instantiation (`component name = Template(...)`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ComponentInstance {
    /// Component instance name relative to `main` (e.g. `adder`).
    name: String,
    /// Template being instantiated (e.g. `Adder`).
    template_name: String,
    /// 1-based line number where the component is instantiated.
    line: u32,
    /// Name of the template body this component is declared inside, or
    /// `None` if it appears at file scope (i.e. `component main = ...`).
    /// Used to build the nesting tree so the recorder can emit
    /// `register_call` events in nesting order (root → leaf) rather than
    /// in raw source-line order.  Required to surface a 3-deep template
    /// chain (`NestedTemplate -> Middle -> Inner`) as three calls in
    /// nesting order — see
    /// `tests/test_tracer.rs::test_nested_template_test_three_deep_call_sequence`.
    parent_template: Option<String>,
    /// Numeric template arguments captured from the instantiation site
    /// (`component main = Num2Bits(4)` -> `vec![4]`).  Best-effort
    /// integer-literal parsing; non-literal arguments (which Circom
    /// evaluates at compile time) yield `0` so the trace still
    /// produces *something* sensible.  This is what enables top-level
    /// `Template(N)` parameterisation through the structured
    /// evaluator's `generic_args` slot.
    template_args: Vec<i64>,
}

/// A parsed template definition.
#[derive(Debug, Clone)]
struct TemplateDef {
    /// Template name.
    name: String,
    /// 1-based line number of the `template` keyword.
    line: u32,
    /// Names of `signal input` declarations inside this template, in source
    /// order.  Used as the formal-parameter list when staging `register_call`
    /// arguments through `writer.arg(name, value)` (audit checklist (c)).
    /// Circom templates do not have a conventional parameter list at the AST
    /// level for their *signal* inputs (only their generic `template T(N)`
    /// numeric parameters do, and those are compile-time); the recorder
    /// surfaces the input-signal names because they are the analogue users
    /// see in the calltrace pane (`adder.a`, `adder.b` etc.).
    input_signals: Vec<String>,
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
    ///
    /// The output format is fixed to CTFS — see
    /// `Recorder-CLI-Conventions.md` §4 in `codetracer-specs`.  Use
    /// `ct print` (from `codetracer-trace-format-nim`) to convert the
    /// produced bundle to JSON or other text forms.
    pub fn trace_program(
        source_path: &Path,
        source_code: &str,
        out_dir: &Path,
    ) -> Result<()> {
        Self::trace_program_with_backend(source_path, source_code, out_dir, false)
    }

    /// Trace using the C++ witness generator backend (faster for large circuits).
    pub fn trace_program_cpp(
        source_path: &Path,
        source_code: &str,
        out_dir: &Path,
    ) -> Result<()> {
        Self::trace_program_with_backend(source_path, source_code, out_dir, true)
    }

    fn trace_program_with_backend(
        source_path: &Path,
        source_code: &str,
        out_dir: &Path,
        use_cpp: bool,
    ) -> Result<()> {
        // CTFS-only.  Pre-2026-05-08 the recorder accepted a format
        // parameter (`TraceEventsFileFormat::{Json,Binary,Ctfs}`) and the
        // CLI exposed a `--format` flag.  The convention now mandates
        // CTFS exclusively.
        let mut tracer = Self::start_trace(source_path, out_dir)?;

        // -- 1. Compile the Circom source --------------------------------------------------
        let compile_dir = tempfile::tempdir()
            .with_context(|| "failed to create temp dir for circom compilation")?;

        let circom_bin = std::env::var("CIRCOM_BIN").unwrap_or_else(|_| "circom".to_string());

        let mut compile_cmd = Command::new(&circom_bin);
        compile_cmd
            .arg(source_path)
            .arg("--wasm")
            .arg("--sym")
            .arg("--O0") // Disable optimization to preserve all signals in the witness.
            .arg("-o")
            .arg(compile_dir.path());

        // Also compile C++ output when using the C++ backend
        if use_cpp {
            compile_cmd.arg("--c");
        }

        // Request source map if the compiler supports it (forked circom)
        compile_cmd.arg("--srcmap");

        let compile_output = match compile_cmd.output() {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("failed to run circom compiler ('{circom_bin}'): {err}");
                tracer.finish_with_error("circom_compile_error", &msg)?;
                return Err(eyre!(msg));
            }
        };

        if !compile_output.status.success() {
            let stderr = String::from_utf8_lossy(&compile_output.stderr);
            // If --srcmap failed (stock circom), retry without it
            if stderr.contains("srcmap") || stderr.contains("unrecognized") {
                eprintln!("Compiler doesn't support --srcmap, retrying without it");
                return Self::trace_program_no_srcmap_with_tracer(
                    tracer,
                    source_path,
                    source_code,
                    out_dir,
                    use_cpp,
                );
            }
            let stdout = String::from_utf8_lossy(&compile_output.stdout);
            let msg = format!("circom compilation failed:\nstdout: {stdout}\nstderr: {stderr}");
            tracer.finish_with_error("circom_compile_error", &msg)?;
            return Err(eyre!(msg));
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
        let srcmap_path = compile_dir.path().join(format!("{stem}.srcmap.json"));

        if !wasm_path.exists() {
            let msg = format!(
                "circom did not produce expected WASM file: {}",
                wasm_path.display()
            );
            tracer.finish_with_error("wasm_witness_error", &msg)?;
            return Err(eyre!(msg));
        }
        if !sym_path.exists() {
            let msg = format!(
                "circom did not produce expected .sym file: {}",
                sym_path.display()
            );
            tracer.finish_with_error("wasm_witness_error", &msg)?;
            return Err(eyre!(msg));
        }

        // Load compiler source map if available
        let compiler_srcmap = if srcmap_path.exists() {
            match CompilerSourceMap::load(&srcmap_path) {
                Ok(map) => {
                    eprintln!(
                        "Loaded compiler source map: {} entries, {} files",
                        map.mappings.len(),
                        map.files.len()
                    );
                    Some(map)
                }
                Err(e) => {
                    eprintln!("Warning: failed to load source map: {e}");
                    None
                }
            }
        } else {
            eprintln!("No compiler source map found (using heuristic mapping)");
            None
        };

        // -- 2. Parse the .sym file -------------------------------------------------------
        let symbols = match parse_sym_file(&sym_path) {
            Ok(symbols) => symbols,
            Err(err) => {
                let msg = format!("failed to parse circom .sym witness map: {err}");
                tracer.finish_with_error("wasm_witness_error", &msg)?;
                return Err(eyre!(msg));
            }
        };
        eprintln!("Parsed {} symbols from .sym file", symbols.len());

        // -- 3. Prepare inputs ------------------------------------------------------------
        // Only set inputs for the main component's template (not sub-component templates).
        let signal_decls = parse_signal_declarations(source_code);
        let main_template_name = find_main_template_name(source_code);
        let main_template_args = find_main_template_args(source_code);
        let main_input_decls =
            find_template_input_decls(source_code, main_template_name.as_deref());
        let main_generic_params =
            find_template_generic_params(source_code, main_template_name.as_deref());
        let main_generic_env = bind_generic_args(&main_generic_params, &main_template_args);
        let inputs = build_witness_inputs(&main_input_decls, &main_generic_env);

        // -- 4. Run the witness generator -------------------------------------------------
        let witness_result = if use_cpp {
            // C++ backend: compile and run the C++ witness generator
            let binary = match cpp_witness::compile_cpp_witness(compile_dir.path(), &stem) {
                Ok(binary) => binary,
                Err(err) => {
                    let msg = format!("C++ witness generator compilation failed: {err}");
                    tracer.finish_with_error("cpp_witness_error", &msg)?;
                    return Err(eyre!(msg));
                }
            };
            let input_json = compile_dir.path().join("input.json");
            let wtns_path = compile_dir.path().join("witness.wtns");
            if let Err(err) = cpp_witness::write_input_json(&input_json, &inputs) {
                let msg = format!("failed to write C++ witness input JSON: {err}");
                tracer.finish_with_error("cpp_witness_error", &msg)?;
                return Err(eyre!(msg));
            }
            match cpp_witness::run_cpp_witness(&binary, &input_json, &wtns_path) {
                Ok(witness) => WitnessCalculation {
                    witness,
                    logs: Vec::new(),
                },
                Err(err) => {
                    let msg = format!("C++ witness generator failed: {err}");
                    tracer.finish_with_error("cpp_witness_error", &msg)?;
                    return Err(eyre!(msg));
                }
            }
        } else {
            // WASM backend: use wasmtime
            match calculate_witness(&wasm_path, &inputs) {
                Ok(result) => result,
                Err(err) => {
                    let msg = format!("wasmtime witness generation failed: {err}");
                    tracer.finish_with_error("wasmtime_witness_error", &msg)?;
                    return Err(eyre!(msg));
                }
            }
        };
        let WitnessCalculation { witness, logs } = witness_result;
        eprintln!("Computed witness with {} elements", witness.len());
        tracer.emit_circom_logs(&logs);

        // -- 5. Map symbol names to values ------------------------------------------------
        let mut values: HashMap<String, i64> = HashMap::new();
        let mut full_name_values: Vec<(String, i64)> = Vec::new();
        for sym in &symbols {
            if sym.witness_index < witness.len() {
                let val = &witness[sym.witness_index];
                let val_i64 = bigint_to_i64(val);
                values.insert(sym.name.clone(), val_i64);
                full_name_values.push((sym.full_name.clone(), val_i64));
            }
        }

        // Build the signal hierarchy for component-aware querying.
        let hierarchy = build_hierarchy(&full_name_values);

        eprintln!("Mapped {} signal values from witness", values.len());
        let child_components = hierarchy.get_child_components(&["main"]);
        if !child_components.is_empty() {
            eprintln!(
                "Signal hierarchy: main has {} sub-component(s): {:?}",
                child_components.len(),
                child_components
            );
        }
        for (name, val) in &values {
            let path = parse_signal_hierarchy(&format!("main.{name}"));
            eprintln!("  {name} = {val} (depth={})", path.depth());
        }

        // -- 6. Parse source for trace event emission -------------------------------------
        let source_map = SourceMap::from_source(source_path, source_code);
        let assignments = parse_signal_assignments(source_code);
        let templates = parse_template_definitions(source_code);
        let component_instances = parse_component_instances(source_code);

        // -- 7. Emit trace events --------------------------------------------------------
        tracer.emit_source_trace(
            source_path,
            &source_map,
            &signal_decls,
            &assignments,
            &templates,
            &component_instances,
            &values,
            compiler_srcmap.as_ref(),
        )?;

        // Close the <toplevel> call that start() opened.
        TraceWriter::register_return(&mut *tracer.writer, NONE_VALUE);

        // -- 8. Finish writing -----------------------------------------------------------
        tracer.finish_trace()?;

        Ok(())
    }

    fn start_trace(source_path: &Path, out_dir: &Path) -> Result<Self> {
        // CTFS-only.  Pre-2026-05-08 this method accepted a
        // `TraceEventsFileFormat` parameter and switched the events
        // filename on it; now it pins to the canonical CTFS multi-stream
        // container.
        let format = TraceEventsFileFormat::Ctfs;
        let program_str = source_path.to_string_lossy();
        let mut tracer = CircomTracer {
            writer: create_trace_writer(&program_str, &[], format),
            field_type_id: None,
        };

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

        TraceWriter::start(&mut *tracer.writer, source_path, Line(1));

        let field_type_id =
            TraceWriter::ensure_type_id(&mut *tracer.writer, TypeKind::Int, "field");
        tracer.field_type_id = Some(field_type_id);

        Ok(tracer)
    }

    fn finish_trace(&mut self) -> Result<()> {
        TraceWriter::finish_writing_trace_events(&mut *self.writer).map_err(|e| eyre!("{e}"))?;
        TraceWriter::finish_writing_trace_metadata(&mut *self.writer).map_err(|e| eyre!("{e}"))?;
        TraceWriter::finish_writing_trace_paths(&mut *self.writer).map_err(|e| eyre!("{e}"))?;
        self.writer.close().map_err(|e| eyre!("{e}"))?;
        Ok(())
    }

    fn finish_with_error(&mut self, metadata: &str, message: &str) -> Result<()> {
        TraceWriter::register_special_event(
            &mut *self.writer,
            EventLogKind::Error,
            metadata,
            message,
        );
        TraceWriter::register_return(&mut *self.writer, NONE_VALUE);
        self.finish_trace()
    }

    fn emit_circom_logs(&mut self, logs: &[String]) {
        for message in logs {
            TraceWriter::register_special_event(
                &mut *self.writer,
                EventLogKind::EvmEvent,
                "circom_log",
                message,
            );
        }
    }

    /// Fallback when --srcmap is not supported by the compiler.
    fn trace_program_no_srcmap_with_tracer(
        mut tracer: CircomTracer,
        source_path: &Path,
        source_code: &str,
        _out_dir: &Path,
        use_cpp: bool,
    ) -> Result<()> {
        let compile_dir = tempfile::tempdir()
            .with_context(|| "failed to create temp dir for circom compilation")?;

        let circom_bin = std::env::var("CIRCOM_BIN").unwrap_or_else(|_| "circom".to_string());

        let mut compile_cmd = Command::new(&circom_bin);
        compile_cmd
            .arg(source_path)
            .arg("--wasm")
            .arg("--sym")
            .arg("--O0")
            .arg("-o")
            .arg(compile_dir.path());

        if use_cpp {
            compile_cmd.arg("--c");
        }

        let compile_output = match compile_cmd.output() {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("failed to run circom compiler ('{circom_bin}'): {err}");
                tracer.finish_with_error("circom_compile_error", &msg)?;
                return Err(eyre!(msg));
            }
        };

        if !compile_output.status.success() {
            let stderr = String::from_utf8_lossy(&compile_output.stderr);
            let stdout = String::from_utf8_lossy(&compile_output.stdout);
            let msg = format!("circom compilation failed:\nstdout: {stdout}\nstderr: {stderr}");
            tracer.finish_with_error("circom_compile_error", &msg)?;
            return Err(eyre!(msg));
        }

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
            let msg = format!(
                "circom did not produce expected WASM file: {}",
                wasm_path.display()
            );
            tracer.finish_with_error("wasm_witness_error", &msg)?;
            return Err(eyre!(msg));
        }

        let symbols = match parse_sym_file(&sym_path) {
            Ok(symbols) => symbols,
            Err(err) => {
                let msg = format!("failed to parse circom .sym witness map: {err}");
                tracer.finish_with_error("wasm_witness_error", &msg)?;
                return Err(eyre!(msg));
            }
        };
        let signal_decls = parse_signal_declarations(source_code);
        let main_template_name = find_main_template_name(source_code);
        let main_template_args = find_main_template_args(source_code);
        let main_input_decls =
            find_template_input_decls(source_code, main_template_name.as_deref());
        let main_generic_params =
            find_template_generic_params(source_code, main_template_name.as_deref());
        let main_generic_env = bind_generic_args(&main_generic_params, &main_template_args);
        let inputs = build_witness_inputs(&main_input_decls, &main_generic_env);

        let witness_result = if use_cpp {
            let binary = match cpp_witness::compile_cpp_witness(compile_dir.path(), &stem) {
                Ok(binary) => binary,
                Err(err) => {
                    let msg = format!("C++ witness generator compilation failed: {err}");
                    tracer.finish_with_error("cpp_witness_error", &msg)?;
                    return Err(eyre!(msg));
                }
            };
            let input_json = compile_dir.path().join("input.json");
            let wtns_path = compile_dir.path().join("witness.wtns");
            if let Err(err) = cpp_witness::write_input_json(&input_json, &inputs) {
                let msg = format!("failed to write C++ witness input JSON: {err}");
                tracer.finish_with_error("cpp_witness_error", &msg)?;
                return Err(eyre!(msg));
            }
            match cpp_witness::run_cpp_witness(&binary, &input_json, &wtns_path) {
                Ok(witness) => WitnessCalculation {
                    witness,
                    logs: Vec::new(),
                },
                Err(err) => {
                    let msg = format!("C++ witness generator failed: {err}");
                    tracer.finish_with_error("cpp_witness_error", &msg)?;
                    return Err(eyre!(msg));
                }
            }
        } else {
            match calculate_witness(&wasm_path, &inputs) {
                Ok(result) => result,
                Err(err) => {
                    let msg = format!("wasmtime witness generation failed: {err}");
                    tracer.finish_with_error("wasmtime_witness_error", &msg)?;
                    return Err(eyre!(msg));
                }
            }
        };
        let WitnessCalculation { witness, logs } = witness_result;
        tracer.emit_circom_logs(&logs);

        let mut values: HashMap<String, i64> = HashMap::new();
        let mut full_name_values: Vec<(String, i64)> = Vec::new();
        for sym in &symbols {
            if sym.witness_index < witness.len() {
                let val = &witness[sym.witness_index];
                let val_i64 = bigint_to_i64(val);
                values.insert(sym.name.clone(), val_i64);
                full_name_values.push((sym.full_name.clone(), val_i64));
            }
        }
        let _hierarchy = build_hierarchy(&full_name_values);

        let source_map = SourceMap::from_source(source_path, source_code);
        let assignments = parse_signal_assignments(source_code);
        let templates = parse_template_definitions(source_code);
        let component_instances = parse_component_instances(source_code);

        tracer.emit_source_trace(
            source_path,
            &source_map,
            &signal_decls,
            &assignments,
            &templates,
            &component_instances,
            &values,
            None,
        )?;

        // Close the <toplevel> call that start() opened.
        TraceWriter::register_return(&mut *tracer.writer, NONE_VALUE);

        tracer.finish_trace()?;

        Ok(())
    }

    /// Emit trace events by evaluating the parsed Circom source.
    ///
    /// 2026-05-13: this used to be a flat brace-tracking parser that
    /// emitted *all* component calls first, then *all* signal-decl
    /// steps, then *all* assignment steps, then *all* call-exits — and
    /// took every signal value from the witness regardless of whether
    /// the witness had been driven by user-visible inputs.  The result
    /// was that circuits without `signal input` declarations surfaced
    /// every output as 0, `for`/`if` body lines never produced step
    /// events, `===` constraint-assertion lines were silently dropped,
    /// and sub-template intermediate outputs were invisible.
    ///
    /// The new flow uses the structured `evaluator` module: parse each
    /// template body into `Stmt`s, walk the main template in source
    /// order, recurse into sub-component instantiations as
    /// `ComponentEnter` events surface, and emit step / variable
    /// events from the evaluator's per-line trace.  Sub-template
    /// signal names are prefixed with their component path so the
    /// trace surfaces `add5.y`, `inner.out`, etc. as the user-visible
    /// signal names — and the values are the evaluator's
    /// compile-time-folded results, not the witness's "every signal is
    /// 0" output for inputless circuits.
    #[allow(clippy::too_many_arguments)]
    fn emit_source_trace(
        &mut self,
        source_path: &Path,
        _source_map: &SourceMap,
        _signals: &[SignalDecl],
        _assignments: &[SignalAssignment],
        templates: &[TemplateDef],
        component_instances: &[ComponentInstance],
        values: &HashMap<String, i64>,
        _compiler_srcmap: Option<&CompilerSourceMap>,
    ) -> Result<()> {
        let field_type_id = self.field_type_id.unwrap();

        // Register function metadata for each template *defined* in the
        // file.  The function table is what `ct print` surfaces, so we
        // must register every user-defined template name regardless of
        // whether it gets called from `main` (cross-recorder convention
        // for `functions[]` ordering).
        let mut template_fns: HashMap<String, FunctionId> = HashMap::new();
        for template in templates {
            let fn_id = TraceWriter::ensure_function_id(
                &mut *self.writer,
                &template.name,
                source_path,
                Line(template.line as i64),
            );
            template_fns.insert(template.name.clone(), fn_id);
        }

        // The `component main = X()` instance is the entry point.
        // Without it there is no chain to evaluate; degrade to the
        // legacy flat flow so circuits that lack a main component
        // still produce *some* trace output.
        let Some(main_inst) = component_instances
            .iter()
            .find(|c| c.parent_template.is_none())
        else {
            return self.emit_legacy_flat(
                source_path,
                _signals,
                _assignments,
                templates,
                component_instances,
                values,
            );
        };

        // Parse every template body using the evaluator's structured
        // parser.  Template definitions that the evaluator can't parse
        // (e.g. they use language constructs the evaluator doesn't
        // model) won't appear in the map; we'll degrade to a flat
        // signal-decl/assignment dump for those.
        let source_code = std::fs::read_to_string(source_path)
            .with_context(|| format!("failed to re-read {}", source_path.display()))?;
        let parsed: Vec<ETemplate> = eval_mod::parse_templates(&source_code);
        let mut tmpl_map: HashMap<String, ETemplate> = HashMap::new();
        for t in parsed {
            tmpl_map.insert(t.name.clone(), t);
        }

        // ------------------------------------------------------------
        // Step 1 — main component step (visible at file scope).
        // ------------------------------------------------------------
        TraceWriter::register_step(
            &mut *self.writer,
            source_path,
            Line(main_inst.line as i64),
        );

        // ------------------------------------------------------------
        // Step 2 — main template's input signal values.  Today the
        // recorder defaults all main inputs to 0 (no JSON wiring).
        // The witness map (`values`) is the source of truth here.
        // ------------------------------------------------------------
        let main_input_values: HashMap<String, i64> = if let Some(t) = tmpl_map.get(&main_inst.template_name) {
            t.input_signals
                .iter()
                .map(|name| (name.clone(), values.get(name).copied().unwrap_or(0)))
                .collect()
        } else {
            HashMap::new()
        };

        // ------------------------------------------------------------
        // Step 3 — emit call_entry for main, recurse, emit call_exit.
        // ------------------------------------------------------------
        let Some(&main_fn_id) = template_fns.get(&main_inst.template_name) else {
            return self.emit_legacy_flat(
                source_path,
                _signals,
                _assignments,
                templates,
                component_instances,
                values,
            );
        };

        // Stage main's input signal arguments before register_call.
        if let Some(t) = tmpl_map.get(&main_inst.template_name) {
            for input_name in &t.input_signals {
                let v = main_input_values.get(input_name).copied().unwrap_or(0);
                let value = ValueRecord::Int {
                    i: v,
                    type_id: field_type_id,
                };
                let _ = TraceWriter::arg(&mut *self.writer, input_name, value);
            }
        }
        TraceWriter::register_call(&mut *self.writer, main_fn_id, vec![]);

        if tmpl_map.contains_key(&main_inst.template_name) {
            self.evaluate_and_emit(
                source_path,
                &main_inst.template_name,
                "", // main has no name prefix for its signals
                &main_input_values,
                main_inst.template_args.clone(),
                &tmpl_map,
                &template_fns,
            );
        }

        // Close the call_entry above for `main`.
        TraceWriter::register_return(&mut *self.writer, NONE_VALUE);

        Ok(())
    }

    /// Recursively evaluate a template instantiation and emit trace
    /// events for every step / variable / sub-component call.  Returns
    /// the map of output-signal values (in the *unprefixed* sub-template
    /// signal namespace) so the caller can resolve `comp.signal`
    /// references.
    ///
    /// `signal_prefix` is the component path under which this template
    /// is being called (e.g. `add5.`, `middle.inner.`).  Empty for the
    /// outermost (main) frame.
    #[allow(clippy::too_many_arguments)]
    fn evaluate_and_emit(
        &mut self,
        source_path: &Path,
        template_name: &str,
        signal_prefix: &str,
        input_signals: &HashMap<String, i64>,
        generic_args: Vec<i64>,
        tmpl_map: &HashMap<String, ETemplate>,
        template_fns: &HashMap<String, FunctionId>,
    ) -> HashMap<String, i64> {
        let field_type_id = self.field_type_id.unwrap();
        let Some(template) = tmpl_map.get(template_name) else {
            return HashMap::new();
        };

        // Pre-walk: collect wires per sub-component so we know each
        // sub-component's input values *before* its call_entry fires.
        // A wire is `comp.signal <== expr` (or `<--`); we evaluate the
        // RHS in the parent's environment, with the inputs already
        // bound and any prior var/signal updates applied.
        //
        // Pre-evaluating the parent body to harvest wires would
        // double-evaluate, so we instead run the evaluator end-to-end
        // and *replay* its event stream into the writer.  When a
        // ComponentEnter event fires we look ahead through the
        // evaluator stream for the sub-component's wires to compute
        // its input values.

        let ctx = EvalContext {
            templates: tmpl_map,
            input_signals: input_signals.clone(),
            generic_args,
        };
        let result = eval_mod::evaluate_template(template, &ctx);

        // Build a per-component wire map by scanning the evaluator
        // events that follow each ComponentEnter — the next
        // ComponentEnter (or end of stream) terminates that
        // component's wire set.
        //
        // We then emit events in source order, recursing into
        // sub-components when we hit their ComponentEnter event.
        let events = &result.events;

        // Pre-compute per-component input values from the Wire events
        // anywhere in the stream (wires can appear after the
        // ComponentEnter line).  A wire's `value` field is already the
        // RHS evaluated in the parent's env (see Stmt::Assign in the
        // evaluator), so we just collect them here.
        let mut comp_inputs: HashMap<String, HashMap<String, i64>> = HashMap::new();
        for ev in events {
            if let EvalEventKind::Wire {
                comp_name,
                signal_name,
                value,
            } = &ev.kind
            {
                comp_inputs
                    .entry(comp_name.clone())
                    .or_default()
                    .insert(signal_name.clone(), *value);
            }
        }

        // Per-component output map, populated as sub-components
        // finish.  Used to resolve `comp.signal` reads if the
        // evaluator's lookahead misses them.
        let mut comp_outputs: HashMap<String, HashMap<String, i64>> = HashMap::new();

        for ev in events {
            match &ev.kind {
                EvalEventKind::Step => {
                    TraceWriter::register_step(
                        &mut *self.writer,
                        source_path,
                        Line(ev.line as i64),
                    );
                }
                EvalEventKind::Variable { name, value } => {
                    TraceWriter::register_step(
                        &mut *self.writer,
                        source_path,
                        Line(ev.line as i64),
                    );
                    let printable = if signal_prefix.is_empty() {
                        name.clone()
                    } else {
                        // Wires already use the form `comp.signal` —
                        // don't double-prefix them.  A prefixed form is
                        // only desirable for *plain* signal names
                        // (`y` -> `add5.y`); names that already contain
                        // a `.` belong to a sub-component the parent is
                        // wiring and should be emitted as-is from the
                        // recurse-down call (where signal_prefix
                        // empty).  Inside a recursed call, the prefix
                        // captures the component path from main.
                        format!("{signal_prefix}{name}")
                    };
                    let value_record = ValueRecord::Int {
                        i: *value,
                        type_id: field_type_id,
                    };
                    TraceWriter::register_variable_with_full_value(
                        &mut *self.writer,
                        &printable,
                        value_record,
                    );
                }
                EvalEventKind::Wire { .. } => {
                    // Wire events are bookkeeping only — the
                    // accompanying Variable event (emitted from the
                    // evaluator on the same line) carries the user-
                    // visible step + variable for the parent frame.
                }
                EvalEventKind::ComponentEnter {
                    comp_name,
                    template: child_template,
                    args,
                } => {
                    // Step at the component-decl line.
                    TraceWriter::register_step(
                        &mut *self.writer,
                        source_path,
                        Line(ev.line as i64),
                    );
                    let Some(&child_fn_id) = template_fns.get(child_template) else {
                        continue;
                    };
                    let child_inputs = comp_inputs.remove(comp_name).unwrap_or_default();
                    if let Some(child_tmpl) = tmpl_map.get(child_template) {
                        for input_name in &child_tmpl.input_signals {
                            let v = child_inputs.get(input_name).copied().unwrap_or(0);
                            let value = ValueRecord::Int {
                                i: v,
                                type_id: field_type_id,
                            };
                            let _ = TraceWriter::arg(&mut *self.writer, input_name, value);
                        }
                    }
                    TraceWriter::register_call(&mut *self.writer, child_fn_id, vec![]);

                    // Recurse with a *single-level* signal prefix —
                    // every recorder consumer (calltrace pane, locals
                    // pane) names sub-template signals relative to
                    // their immediate parent, e.g. `inner.out` rather
                    // than `middle.inner.out`.  Accumulating the full
                    // path makes signal names balloon and breaks
                    // round-trips with `.sym` lookups.
                    let child_prefix = format!("{comp_name}.");
                    let outputs = self.evaluate_and_emit(
                        source_path,
                        child_template,
                        &child_prefix,
                        &child_inputs,
                        args.clone(),
                        tmpl_map,
                        template_fns,
                    );
                    comp_outputs.insert(comp_name.clone(), outputs);

                    TraceWriter::register_return(&mut *self.writer, NONE_VALUE);
                }
            }
        }

        result.outputs
    }

    /// Legacy fallback flow used when the structured evaluator can't
    /// model the source program (e.g. no `component main`, or the
    /// main template body fails to parse).  This is the
    /// pre-2026-05-13 emit logic preserved so degenerate inputs still
    /// produce *some* trace.
    #[allow(clippy::too_many_arguments)]
    fn emit_legacy_flat(
        &mut self,
        source_path: &Path,
        signals: &[SignalDecl],
        assignments: &[SignalAssignment],
        templates: &[TemplateDef],
        component_instances: &[ComponentInstance],
        values: &HashMap<String, i64>,
    ) -> Result<()> {
        let field_type_id = self.field_type_id.unwrap();
        let mut template_fns: HashMap<String, FunctionId> = HashMap::new();
        let templates_by_name: HashMap<&str, &TemplateDef> = templates
            .iter()
            .map(|template| (template.name.as_str(), template))
            .collect();
        for template in templates {
            let fn_id = TraceWriter::ensure_function_id(
                &mut *self.writer,
                &template.name,
                source_path,
                Line(template.line as i64),
            );
            template_fns.insert(template.name.clone(), fn_id);
        }

        let ordered_components: Vec<&ComponentInstance> =
            order_components_by_nesting(component_instances);

        let mut emitted_component_calls = 0usize;
        for component in &ordered_components {
            let Some(template) = templates_by_name.get(component.template_name.as_str()) else {
                continue;
            };
            let Some(&fn_id) = template_fns.get(&component.template_name) else {
                continue;
            };

            TraceWriter::register_step(
                &mut *self.writer,
                source_path,
                Line(component.line as i64),
            );
            let is_main = component.name == "main";
            for input_name in &template.input_signals {
                let lookup_key: String = if is_main {
                    input_name.clone()
                } else {
                    format!("{}.{}", component.name, input_name)
                };
                let value = values
                    .get(&lookup_key)
                    .map(|&val| ValueRecord::Int {
                        i: val,
                        type_id: field_type_id,
                    })
                    .unwrap_or(NONE_VALUE);
                let _ = TraceWriter::arg(&mut *self.writer, input_name, value);
            }
            TraceWriter::register_call(&mut *self.writer, fn_id, vec![]);
            emitted_component_calls += 1;
        }

        for sig in signals {
            TraceWriter::register_step(&mut *self.writer, source_path, Line(sig.line as i64));
        }
        for assign in assignments {
            TraceWriter::register_step(&mut *self.writer, source_path, Line(assign.line as i64));
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
        for _ in 0..emitted_component_calls {
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

        let after_signal = if let Some(rest) = trimmed.strip_prefix("signal ") {
            rest.trim()
        } else {
            continue;
        };

        let (kind, rest) = if let Some(rest) = after_signal.strip_prefix("input ") {
            (SignalKind::Input, rest.trim())
        } else if let Some(rest) = after_signal.strip_prefix("output ") {
            (SignalKind::Output, rest.trim())
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

/// Order component instances depth-first by template-nesting so each
/// parent precedes every component declared inside that parent's
/// template body.
///
/// The root is the file-scope `component main = TemplateX()` declaration
/// (`parent_template == None`); from there we walk every component whose
/// `parent_template` matches the parent's *template_name*, recursively.
/// Within a single template body, sub-components stay in source-line
/// order — which matches the convention of every other recorder in the
/// CodeTracer family that emits sibling calls in source-instantiation
/// order (`signal_hierarchy_test.circom` keeps `[Add5, Mul2]` because
/// they are declared in that order in `SignalHierarchy`'s body).
///
/// Components whose parent template is missing from the input slice
/// (defensive against malformed sources) are appended at the end in
/// source order so the recorder still surfaces them.
fn order_components_by_nesting(components: &[ComponentInstance]) -> Vec<&ComponentInstance> {
    let mut out: Vec<&ComponentInstance> = Vec::with_capacity(components.len());
    let mut emitted = vec![false; components.len()];

    // Locate the file-scope `main` component (parent_template == None).
    // There is at most one in a well-formed Circom program.
    let Some(main_idx) = components.iter().position(|c| c.parent_template.is_none()) else {
        // No `component main` line — fall back to source order so the
        // recorder still emits *something* sensible.
        return components.iter().collect();
    };

    // Depth-first walk starting at main.  At each node we visit every
    // component whose `parent_template` equals the current node's
    // *template_name* (i.e. the components declared inside the current
    // node's template body), in source-line order.
    fn dfs<'a>(
        idx: usize,
        components: &'a [ComponentInstance],
        emitted: &mut [bool],
        out: &mut Vec<&'a ComponentInstance>,
    ) {
        if emitted[idx] {
            return;
        }
        emitted[idx] = true;
        out.push(&components[idx]);
        let parent_template_name = components[idx].template_name.as_str();
        // Children are every component whose declaring template body is
        // `parent_template_name`.  Source-line order is preserved because
        // we scan `components` in input order (which `parse_component_instances`
        // builds in source-line order).
        for (child_idx, child) in components.iter().enumerate() {
            if emitted[child_idx] {
                continue;
            }
            if let Some(parent) = &child.parent_template {
                if parent == parent_template_name {
                    dfs(child_idx, components, emitted, out);
                }
            }
        }
    }

    dfs(main_idx, components, &mut emitted, &mut out);

    // Append any leftover components (orphans whose parent template is
    // missing or unreachable from `main`) in source order.
    for (i, c) in components.iter().enumerate() {
        if !emitted[i] {
            out.push(c);
        }
    }

    out
}

/// Parse component instantiations from Circom source code.
///
/// Tracks the *parent* template body each component is declared inside so
/// the recorder can later walk the resulting tree in nesting order.
/// Components declared at file scope (the `component main = ...` line)
/// receive `parent_template = None`.
fn parse_component_instances(source: &str) -> Vec<ComponentInstance> {
    let mut components = Vec::new();
    // The template body currently in scope (or `None` at file scope) and
    // the brace depth inside it.  Circom does not allow nested template
    // definitions, so a single-entry stack is sufficient.
    let mut current_template: Option<String> = None;
    let mut brace_depth: i32 = 0;

    for (line_idx, line_text) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let trimmed = line_text.trim();

        // Detect a template-header line *before* updating brace depth so
        // the body's opening `{` on the same line is counted toward that
        // template.
        if current_template.is_none() {
            if let Some(after_template) = trimmed.strip_prefix("template ") {
                if let Some(paren_pos) = after_template.find('(') {
                    let name = after_template[..paren_pos].trim().to_string();
                    if !name.is_empty() {
                        current_template = Some(name);
                        brace_depth = 0;
                    }
                }
            }
        }

        // Detect a component instantiation on this line.  The recorded
        // parent is the template body we're currently inside (if any).
        if let Some(after_component) = trimmed.strip_prefix("component ") {
            if let Some(eq_pos) = after_component.find('=') {
                let name = after_component[..eq_pos].trim();
                let after_eq = after_component[eq_pos + 1..].trim();
                if let Some(paren_pos) = after_eq.find('(') {
                    let template_name = after_eq[..paren_pos].trim();
                    // Extract integer-literal template args from
                    // `Template(N, M, ...)` between the matching parens.
                    // Non-literal args fall back to `0`; this matches
                    // the evaluator's own degraded behaviour for
                    // unresolved generic arguments and keeps the trace
                    // producing concrete values for the common
                    // `template Foo(N) { ... }` instantiation idiom.
                    let template_args: Vec<i64> =
                        if let Some(close_paren) = after_eq[paren_pos + 1..].find(')') {
                            let inner = &after_eq[paren_pos + 1..paren_pos + 1 + close_paren];
                            inner
                                .split(',')
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .map(|s| s.parse::<i64>().unwrap_or(0))
                                .collect()
                        } else {
                            Vec::new()
                        };
                    if !name.is_empty() && !template_name.is_empty() {
                        components.push(ComponentInstance {
                            name: name.to_string(),
                            template_name: template_name.to_string(),
                            line: line_num,
                            parent_template: current_template.clone(),
                            template_args,
                        });
                    }
                }
            }
        }

        // Update brace depth and pop the current template when its body
        // closes.
        if current_template.is_some() {
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        if brace_depth <= 0 {
                            current_template = None;
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    components
}

/// Parse template definitions from Circom source code.
///
/// In addition to the template name and source line, this also captures the
/// list of `signal input` declarations inside each template body in source
/// order — these are surfaced as formal parameters when staging
/// `register_call` arguments (audit checklist (c) for the Circom recorder).
fn parse_template_definitions(source: &str) -> Vec<TemplateDef> {
    let mut templates = Vec::new();
    let mut current: Option<(TemplateDef, i32)> = None; // (template, brace_depth)

    for (line_idx, line_text) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32;
        let trimmed = line_text.trim();

        // Detect template-definition headers.  We only treat the line as a
        // template start when there is no template currently in scope; nested
        // templates are not legal in Circom.
        if current.is_none() {
            if let Some(after_template) = trimmed.strip_prefix("template ") {
                if let Some(paren_pos) = after_template.find('(') {
                    let name = after_template[..paren_pos].trim().to_string();
                    if !name.is_empty() {
                        current = Some((
                            TemplateDef {
                                name,
                                line: line_num,
                                input_signals: Vec::new(),
                            },
                            0,
                        ));
                    }
                }
            }
        }

        // Inside the current template, scan for `signal input` declarations
        // and track brace depth so we know when the body ends.
        if let Some((tmpl, depth)) = current.as_mut() {
            if let Some(rest) = trimmed.strip_prefix("signal input ") {
                let name = rest.trim().trim_end_matches(';').trim().to_string();
                if !name.is_empty() {
                    tmpl.input_signals.push(name);
                }
            }

            // Update brace depth.  We do this *after* the input-signal scan
            // so the `template Foo() {` header line itself counts as +1
            // and a closing `}` on its own line correctly drops depth to 0.
            for ch in trimmed.chars() {
                match ch {
                    '{' => *depth += 1,
                    '}' => {
                        *depth -= 1;
                        if *depth <= 0 {
                            // Body closed — emit the template and reset.
                            let (tmpl, _) = current.take().unwrap();
                            templates.push(tmpl);
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // If parsing ended mid-template (malformed source), still surface what we
    // collected so the recorder degrades gracefully.
    if let Some((tmpl, _)) = current {
        templates.push(tmpl);
    }

    templates
}

/// Find the name of the template instantiated as `component main = TemplateName()`.
///
/// Returns `None` if no main component line is found.
fn find_main_template_name(source: &str) -> Option<String> {
    for line_text in source.lines() {
        let trimmed = line_text.trim();
        // Match patterns like: component main = TemplateName();
        // or: component main = TemplateName(args);
        if trimmed.starts_with("component main") {
            if let Some(eq_pos) = trimmed.find('=') {
                let after_eq = trimmed[eq_pos + 1..].trim();
                // Extract the template name (everything before the first '(')
                if let Some(paren_pos) = after_eq.find('(') {
                    let name = after_eq[..paren_pos].trim().to_string();
                    if !name.is_empty() {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

/// A parsed `signal input` declaration with its array dimensions and
/// the source identifier of each dim (for parameterised templates).
#[derive(Debug, Clone, PartialEq, Eq)]
struct InputSignalDecl {
    /// Bare signal name (without trailing `[N]` brackets).
    name: String,
    /// Each `[expr]` dimension token from the declaration, with the
    /// raw expression source preserved so the caller can substitute
    /// template-arg values (e.g. `[N]` -> `[3]` when `N=3`).  Scalar
    /// signals carry an empty `dims` vector.
    dims: Vec<String>,
}

/// Find input signal declarations for a specific template, capturing
/// each declaration's name and its array dimensions (raw expression
/// strings).  When the template has array-typed inputs, callers need
/// the dimension expressions so they can compute the witness-size for
/// each input given the template's actual generic arguments.
///
/// If `template_name` is `None`, falls back to collecting all input
/// signals from the entire source (backward-compatible behaviour for
/// single-template files used in early-2026 fixtures).
fn find_template_input_decls(source: &str, template_name: Option<&str>) -> Vec<InputSignalDecl> {
    let mut inputs = Vec::new();
    let mut in_target_template = template_name.is_none();
    let mut brace_depth = 0i32;

    for line_text in source.lines() {
        let trimmed = line_text.trim();

        // Track when we enter/exit the target template.
        if let Some(target) = template_name {
            if trimmed.starts_with("template ") {
                if let Some(paren_pos) = trimmed.find('(') {
                    let name = trimmed[9..paren_pos].trim();
                    if name == target {
                        in_target_template = true;
                        brace_depth = 0;
                    }
                }
            }
        }

        if in_target_template {
            // Track brace depth to know when the template ends.
            for ch in trimmed.chars() {
                match ch {
                    '{' => brace_depth += 1,
                    '}' => {
                        brace_depth -= 1;
                        if brace_depth <= 0 && template_name.is_some() {
                            in_target_template = false;
                        }
                    }
                    _ => {}
                }
            }

            // Parse signal input declarations within this template.
            if let Some(rest) = trimmed.strip_prefix("signal input ") {
                let raw = rest.trim().trim_end_matches(';').trim();
                if !raw.is_empty() {
                    let (name, dims) = split_array_dims(raw);
                    inputs.push(InputSignalDecl { name, dims });
                }
            }
        }
    }

    inputs
}

/// Extract integer-literal arguments from `component main = Foo(...)`.
/// Non-literal args (rare for `main`, since circom's compile-time
/// folding requires them to be constant) yield 0.  Returns an empty
/// vector when no `component main` line exists.
fn find_main_template_args(source: &str) -> Vec<i64> {
    for line_text in source.lines() {
        let trimmed = line_text.trim();
        if !trimmed.starts_with("component main") {
            continue;
        }
        let Some(eq_pos) = trimmed.find('=') else {
            continue;
        };
        let after_eq = trimmed[eq_pos + 1..].trim();
        let Some(open_paren) = after_eq.find('(') else {
            continue;
        };
        let Some(close_paren) = after_eq[open_paren + 1..].find(')') else {
            continue;
        };
        let inner = &after_eq[open_paren + 1..open_paren + 1 + close_paren];
        return inner
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<i64>().unwrap_or(0))
            .collect();
    }
    Vec::new()
}

/// Extract the generic-parameter names of `template Foo(N, M, ...)`
/// for `template_name == Some("Foo")`.  Returns the parameters in
/// declaration order.  Yields an empty vec if the template has no
/// generic params or `template_name` is `None`.
fn find_template_generic_params(source: &str, template_name: Option<&str>) -> Vec<String> {
    let Some(target) = template_name else {
        return Vec::new();
    };
    for line_text in source.lines() {
        let trimmed = line_text.trim();
        if !trimmed.starts_with("template ") {
            continue;
        }
        let Some(open_paren) = trimmed.find('(') else {
            continue;
        };
        let name = trimmed[9..open_paren].trim();
        if name != target {
            continue;
        }
        let Some(close_paren) = trimmed[open_paren + 1..].find(')') else {
            return Vec::new();
        };
        let inner = &trimmed[open_paren + 1..open_paren + 1 + close_paren];
        return inner
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    Vec::new()
}

/// Bind generic-parameter names to their corresponding template-arg
/// values: `Sum(N) ... main = Sum(3)` -> `{"N" -> 3}`.  Extra args (or
/// extra params without a matching arg) are silently dropped.
fn bind_generic_args(params: &[String], args: &[i64]) -> HashMap<String, i64> {
    params
        .iter()
        .zip(args.iter())
        .map(|(p, a)| (p.clone(), *a))
        .collect()
}

/// Build the witness-input map (name -> Vec<value-string>) from the
/// main template's input-signal declarations.  Each scalar input gets
/// a single `"0"` element; each array input gets `N` `"0"` elements
/// where `N` is the resolved first dimension.  This shape is what the
/// circom WASM witness calculator's `setInputSignal` ABI expects.
fn build_witness_inputs(
    decls: &[InputSignalDecl],
    generic_env: &HashMap<String, i64>,
) -> HashMap<String, Vec<String>> {
    let mut inputs = HashMap::new();
    for d in decls {
        // Total signal size = product of all dimensions (multi-dim
        // arrays are flattened by circom into a single contiguous
        // input buffer).  Scalars have `dims == []` so the product
        // yields 1.
        let mut size = 1usize;
        for dim_expr in &d.dims {
            size *= resolve_dim(dim_expr, generic_env).max(1);
        }
        inputs.insert(d.name.clone(), vec!["0".to_string(); size]);
    }
    inputs
}

/// Split `name[d1][d2]...` into `(name, [d1, d2, ...])`.  Each
/// dimension is captured verbatim as a source-string slice (no parsing
/// of the inner expression — that's the caller's job, since the
/// dimension may reference template generic parameters).
fn split_array_dims(decl: &str) -> (String, Vec<String>) {
    let bytes = decl.as_bytes();
    let mut i = 0;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    let name = std::str::from_utf8(&bytes[..i]).unwrap_or("").to_string();
    let mut dims = Vec::new();
    while i < bytes.len() && bytes[i] == b'[' {
        let start = i + 1;
        let mut depth = 1i32;
        i += 1;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'[' => depth += 1,
                b']' => depth -= 1,
                _ => {}
            }
            i += 1;
        }
        // i now points one past the matching ']'; dim text is bytes[start..i-1]
        let end = i.saturating_sub(1);
        let dim = std::str::from_utf8(&bytes[start..end])
            .unwrap_or("")
            .trim()
            .to_string();
        dims.push(dim);
    }
    (name, dims)
}

/// Resolve a dimension expression to an integer using the
/// (template_param_name -> value) map.  Returns 1 on parse failure so
/// the witness calculator at least gets a valid array shape (a real
/// program will surface the error elsewhere).
fn resolve_dim(expr: &str, generic_env: &HashMap<String, i64>) -> usize {
    let expr = expr.trim();
    if let Ok(n) = expr.parse::<i64>() {
        return (n.max(0)) as usize;
    }
    if let Some(&v) = generic_env.get(expr) {
        return (v.max(0)) as usize;
    }
    1
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
        // Empty body — no `signal input` declarations.
        assert!(templates[0].input_signals.is_empty());
    }

    #[test]
    fn test_parse_template_definitions_collects_input_signals() {
        // The parser must surface each `signal input <name>;` declaration
        // inside a template body, in source order, so audit checklist (c)'s
        // `writer.arg(name, value)` staging path has data to emit.
        // This mirrors the structure of `component_test.circom` where
        // `Adder` has two input signals (`a`, `b`).
        let source = "template Adder() {\n\
                      \x20\x20\x20\x20signal input a;\n\
                      \x20\x20\x20\x20signal input b;\n\
                      \x20\x20\x20\x20signal output out;\n\
                      \x20\x20\x20\x20out <== a + b;\n\
                      }\n\
                      template Outer() {\n\
                      \x20\x20\x20\x20signal input x;\n\
                      \x20\x20\x20\x20signal output y;\n\
                      \x20\x20\x20\x20y <== x;\n\
                      }\n";
        let templates = parse_template_definitions(source);
        assert_eq!(templates.len(), 2);
        assert_eq!(templates[0].name, "Adder");
        assert_eq!(
            templates[0].input_signals,
            vec!["a".to_string(), "b".to_string()]
        );
        assert_eq!(templates[1].name, "Outer");
        assert_eq!(templates[1].input_signals, vec!["x".to_string()]);
    }

    #[test]
    fn test_parse_component_instances() {
        let source = "template ComponentTest() {\n\
                      \x20\x20\x20\x20component adder = Adder();\n\
                      }\n\
                      component main = ComponentTest();\n";
        let components = parse_component_instances(source);
        assert_eq!(
            components,
            vec![
                ComponentInstance {
                    name: "adder".to_string(),
                    template_name: "Adder".to_string(),
                    line: 2,
                    // `adder` is declared inside the `ComponentTest`
                    // template body, so its parent_template tracks that.
                    parent_template: Some("ComponentTest".to_string()),
                    template_args: Vec::new(),
                },
                ComponentInstance {
                    name: "main".to_string(),
                    template_name: "ComponentTest".to_string(),
                    line: 4,
                    // `component main = ...` is at file scope, so it has
                    // no parent template body — it's the root.
                    parent_template: None,
                    template_args: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn test_order_components_by_nesting_three_deep_chain() {
        // Mirror the nesting structure of nested_template_test.circom:
        // file scope:  component main = NestedTemplate()  (line 35)
        // NestedTemplate body: component middle = Middle()  (line 31)
        // Middle body:         component inner = Inner()    (line 24)
        //
        // The parser visits them in source-line order [inner, middle, main],
        // but `order_components_by_nesting` must reshape that into nesting
        // order [main (NestedTemplate), middle, inner] so the recorder
        // emits an N-deep template chain as N nested call_entry events.
        let inner = ComponentInstance {
            name: "inner".to_string(),
            template_name: "Inner".to_string(),
            line: 24,
            parent_template: Some("Middle".to_string()),
            template_args: Vec::new(),
        };
        let middle = ComponentInstance {
            name: "middle".to_string(),
            template_name: "Middle".to_string(),
            line: 31,
            parent_template: Some("NestedTemplate".to_string()),
            template_args: Vec::new(),
        };
        let main = ComponentInstance {
            name: "main".to_string(),
            template_name: "NestedTemplate".to_string(),
            line: 35,
            parent_template: None,
            template_args: Vec::new(),
        };
        let components = vec![inner.clone(), middle.clone(), main.clone()];

        let ordered = order_components_by_nesting(&components);
        let names: Vec<&str> = ordered.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["main", "middle", "inner"]);
    }

    #[test]
    fn test_order_components_by_nesting_two_siblings() {
        // Mirror signal_hierarchy_test.circom: `main = SignalHierarchy()`
        // contains two siblings `add5` and `mul2`, in source order.  The
        // nesting-order traversal must preserve sibling source order so
        // recorders emit the calls in the order users see them in the
        // file (`[SignalHierarchy, add5, mul2]`).
        let add5 = ComponentInstance {
            name: "add5".to_string(),
            template_name: "Add5".to_string(),
            line: 33,
            parent_template: Some("SignalHierarchy".to_string()),
            template_args: Vec::new(),
        };
        let mul2 = ComponentInstance {
            name: "mul2".to_string(),
            template_name: "Mul2".to_string(),
            line: 34,
            parent_template: Some("SignalHierarchy".to_string()),
            template_args: Vec::new(),
        };
        let main = ComponentInstance {
            name: "main".to_string(),
            template_name: "SignalHierarchy".to_string(),
            line: 41,
            parent_template: None,
            template_args: Vec::new(),
        };
        let components = vec![add5.clone(), mul2.clone(), main.clone()];

        let ordered = order_components_by_nesting(&components);
        let names: Vec<&str> = ordered.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["main", "add5", "mul2"]);
    }

    #[test]
    fn test_parse_sym_file() {
        let dir = tempfile::tempdir().unwrap();
        let sym_path = dir.path().join("test.sym");
        std::fs::write(&sym_path, "1,1,0,main.out\n2,-1,0,main.in\n3,-1,0,main.a\n").unwrap();

        let entries = parse_sym_file(&sym_path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].witness_index, 1);
        assert_eq!(entries[0].name, "out");
        assert_eq!(entries[1].witness_index, 2);
        assert_eq!(entries[1].name, "in");
        assert_eq!(entries[2].witness_index, 3);
        assert_eq!(entries[2].name, "a");
    }

    #[test]
    fn test_parse_sym_file_with_sub_components() {
        let dir = tempfile::tempdir().unwrap();
        let sym_path = dir.path().join("test.sym");
        std::fs::write(
            &sym_path,
            "1,1,0,main.out\n2,-1,0,main.adder.a\n3,-1,0,main.adder.b\n4,2,0,main.adder.out\n",
        )
        .unwrap();

        let entries = parse_sym_file(&sym_path).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name, "out");
        assert_eq!(entries[0].full_name, "main.out");
        assert_eq!(entries[1].name, "adder.a");
        assert_eq!(entries[1].full_name, "main.adder.a");
        assert_eq!(entries[2].name, "adder.b");
        assert_eq!(entries[2].full_name, "main.adder.b");
        assert_eq!(entries[3].name, "adder.out");
        assert_eq!(entries[3].full_name, "main.adder.out");
    }

    #[test]
    fn test_parse_sym_file_with_arrays() {
        let dir = tempfile::tempdir().unwrap();
        let sym_path = dir.path().join("test.sym");
        std::fs::write(
            &sym_path,
            "1,-1,0,main.values[0]\n2,-1,0,main.values[1]\n3,-1,0,main.values[2]\n4,1,0,main.out\n",
        )
        .unwrap();

        let entries = parse_sym_file(&sym_path).unwrap();
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name, "values[0]");
        assert_eq!(entries[1].name, "values[1]");
        assert_eq!(entries[2].name, "values[2]");
        assert_eq!(entries[3].name, "out");
    }

    #[test]
    fn test_parse_signal_hierarchy_simple() {
        let path = parse_signal_hierarchy("main.out");
        assert_eq!(path.depth(), 2);
        assert_eq!(path.leaf_name(), "out");
    }

    #[test]
    fn test_parse_signal_hierarchy_sub_component() {
        let path = parse_signal_hierarchy("main.adder.out");
        assert_eq!(path.depth(), 3);
        assert_eq!(path.components[1].name, "adder");
        assert_eq!(path.leaf_name(), "out");
        let comp_path = path.component_path();
        assert_eq!(comp_path.len(), 1);
        assert_eq!(comp_path[0].name, "adder");
    }

    #[test]
    fn test_parse_signal_hierarchy_array() {
        let path = parse_signal_hierarchy("main.values[0]");
        assert_eq!(path.depth(), 2);
        assert_eq!(path.leaf_name(), "values");
        assert_eq!(path.leaf_index(), Some(0));
    }

    #[test]
    fn test_parse_signal_hierarchy_deep() {
        let path = parse_signal_hierarchy("main.component.sub_signal");
        assert_eq!(path.depth(), 3);
        assert_eq!(path.components[0].name, "main");
        assert_eq!(path.components[1].name, "component");
        assert_eq!(path.components[2].name, "sub_signal");
        assert_eq!(path.full_name(), "main.component.sub_signal");
    }

    #[test]
    fn test_build_hierarchy_from_sym_entries() {
        use crate::signal_hierarchy::build_hierarchy;

        let signals = vec![
            ("main.in".to_string(), 5),
            ("main.adder.a".to_string(), 10),
            ("main.adder.b".to_string(), 20),
            ("main.adder.out".to_string(), 30),
            ("main.out".to_string(), 30),
        ];
        let hierarchy = build_hierarchy(&signals);

        let main_sigs = hierarchy.get_signals_for_component(&["main"]);
        assert_eq!(main_sigs.len(), 2);

        let adder_sigs = hierarchy.get_signals_for_component(&["main", "adder"]);
        assert_eq!(adder_sigs.len(), 3);

        let children = hierarchy.get_child_components(&["main"]);
        assert!(children.contains(&"adder".to_string()));
    }

    #[test]
    fn test_build_hierarchy_with_arrays() {
        use crate::signal_hierarchy::build_hierarchy;

        let signals = vec![
            ("main.values[0]".to_string(), 100),
            ("main.values[1]".to_string(), 200),
            ("main.values[2]".to_string(), 300),
            ("main.out".to_string(), 600),
        ];
        let hierarchy = build_hierarchy(&signals);

        let arr = hierarchy.get_array_signals(&["main"], "values");
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], (0, 100));
        assert_eq!(arr[1], (1, 200));
        assert_eq!(arr[2], (2, 300));
    }
}
