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
//!     [--format binary|json]
//! ```

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use codetracer_trace_writer::TraceEventsFileFormat;
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

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Binary,
    Json,
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
    #[arg(short = 'f', long, default_value = "binary")]
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
            println!(
                "codetracer-circom-recorder {}",
                env!("CARGO_PKG_VERSION")
            );
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

    let format = match args.format {
        OutputFormat::Binary => TraceEventsFileFormat::Binary,
        OutputFormat::Json => TraceEventsFileFormat::Json,
    };

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
