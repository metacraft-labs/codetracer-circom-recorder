//! CLI entry point for the CodeTracer Circom recorder.
//!
//! Supports the `record` subcommand which takes a Circom source file,
//! parses and evaluates signal assignments, and writes CodeTracer trace
//! output files.
//!
//! # Usage
//!
//! ```text
//! codetracer-circom-recorder record <circom-file> \
//!     --out-dir <output-dir> \
//!     [--format ctfs|binary|json]
//! ```
//!
//! The default output format is `ctfs` — the canonical CodeTracer
//! multi-stream container that the Nim `ct_reader_*` FFI and the
//! db-backend's `CTFSTraceReader` consume directly.  `binary`
//! (legacy CBOR + Zstd) and `json` (human-readable) are kept for
//! compatibility / debugging.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use codetracer_trace_writer_nim::TraceEventsFileFormat;
use eyre::{Context, Result};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// CodeTracer Circom recorder -- record Circom circuit execution traces.
#[derive(Debug, Parser)]
#[command(
    name = "codetracer-circom-recorder",
    version,
    about = "Record Circom circuit execution traces for CodeTracer"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Record execution of a Circom circuit.
    ///
    /// Parses the given .circom source file, evaluates signal assignments,
    /// captures the execution trace, and writes CodeTracer trace files
    /// to `--out-dir`.
    Record(RecordArgs),

    /// Print version information.
    Version,
}

/// Output format for the trace files.
///
/// `Ctfs` is the canonical CodeTracer multi-stream container (the
/// format the Nim `ct_reader_*` FFI and the db-backend's
/// `CTFSTraceReader` consume directly) and is the default.  `Binary`
/// is the legacy CBOR + Zstd container kept for compatibility with
/// older readers.  `Json` is a slower, human-readable form useful
/// for debugging.
///
/// Same shape as the audited recorders (EVM 1.39, Solana 1.44, Move
/// 1.46, Cardano 1.48, Cairo 1.50, Flow 1.52, Fuel 1.53, PolkaVM
/// 1.55, Miden 1.56, TON 1.57) so `From<OutputFormat>` collapses each
/// dispatch site to `args.format.into()`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Canonical CodeTracer multi-stream container (recommended; default).
    Ctfs,
    /// Legacy CBOR + Zstd binary format.
    Binary,
    /// Human-readable JSON (slower; useful for debugging).
    Json,
}

impl From<OutputFormat> for TraceEventsFileFormat {
    fn from(fmt: OutputFormat) -> Self {
        match fmt {
            OutputFormat::Ctfs => TraceEventsFileFormat::Ctfs,
            OutputFormat::Binary => TraceEventsFileFormat::Binary,
            OutputFormat::Json => TraceEventsFileFormat::Json,
        }
    }
}

impl OutputFormat {
    /// Stable string representation suitable for `trace_metadata.json`'s
    /// `format` field.  Wired here for forward compatibility with the
    /// audit-aligned metadata emission path used by other recorders;
    /// not yet consumed by the writer plumbing in this crate.
    #[allow(dead_code)]
    fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Ctfs => "ctfs",
            OutputFormat::Binary => "binary",
            OutputFormat::Json => "json",
        }
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum WitnessBackend {
    /// Use the WASM witness generator via Wasmtime (default).
    Wasm,
    /// Use the C++ witness generator (faster for large circuits).
    Cpp,
}

#[derive(Debug, clap::Args)]
struct RecordArgs {
    /// Path to the Circom source (.circom) file.
    program: PathBuf,

    /// Directory where the trace files will be written.
    ///
    /// The directory will be created if it does not exist.
    #[arg(short = 'o', long, default_value = "./ct-traces/")]
    out_dir: PathBuf,

    /// Output format for the trace data.
    #[arg(short = 'f', long, default_value = "ctfs")]
    format: OutputFormat,

    /// Witness generator backend to use.
    ///
    /// The C++ backend is faster for large circuits but requires
    /// gcc/make in the dev shell.
    #[arg(short = 'b', long, default_value = "wasm")]
    backend: WitnessBackend,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Record(args) => record(args),
        Commands::Version => {
            println!("codetracer-circom-recorder {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// `record` implementation
// ---------------------------------------------------------------------------

/// Execute the `record` subcommand.
fn record(args: RecordArgs) -> Result<()> {
    // 1. Validate the source file exists
    let source_path = args
        .program
        .canonicalize()
        .with_context(|| format!("source file not found: {}", args.program.display()))?;

    eprintln!("Source file: {}", source_path.display());

    let format: TraceEventsFileFormat = args.format.into();

    let use_cpp = matches!(args.backend, WitnessBackend::Cpp);
    if use_cpp {
        eprintln!("Using C++ witness generator backend");
    }

    // 2. Create the output directory
    let out_dir = &args.out_dir;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create output dir: {}", out_dir.display()))?;

    // 3. Run the recorder
    codetracer_circom_recorder::recorder::record(&source_path, out_dir, format, use_cpp)?;

    eprintln!("Trace files written to {}", out_dir.display());

    Ok(())
}
