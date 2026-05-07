//! CLI entry point for the CodeTracer Circom recorder.
//!
//! Supports the `record` subcommand which takes a Circom source file,
//! compiles it via the upstream `circom` compiler, runs the generated
//! witness calculator (WASM or C++ backend), and writes a CodeTracer
//! CTFS trace bundle.
//!
//! # Usage
//!
//! ```text
//! codetracer-circom-recorder record <circom-file> --out-dir <output-dir>
//! ```
//!
//! The recorder always writes traces in the canonical CodeTracer multi-stream
//! CTFS format (see `Recorder-CLI-Conventions.md` §4 in `codetracer-specs`).
//! No `--format` flag is exposed: human-readable conversion is handled
//! out-of-band by `ct print` (shipped with `codetracer-trace-format-nim`).
//!
//! # Environment variables
//!
//! * `CODETRACER_CIRCOM_RECORDER_OUT_DIR` — fallback for `--out-dir` when the
//!   flag is not given. The CLI flag always wins.
//! * `CODETRACER_CIRCOM_RECORDER_DISABLED` — set to `1` or `true` to skip
//!   recording entirely. The Circom recorder doesn't run a separate target
//!   subprocess (it parses, compiles, and witness-generates the source
//!   itself), so "disabled" simply means "don't write any trace artefacts".
//! * `CODETRACER_CIRCOM_RECORDER_LOG_LEVEL` — recorder log verbosity (advisory;
//!   the Circom recorder currently logs to stderr unconditionally).
//! * `CIRCOM_BIN` — path to the upstream `circom` compiler binary
//!   (Circom-specific; not part of the standard recorder env-var set).

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use eyre::{Context, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Environment variable used as a fallback for `--out-dir` when the CLI
/// flag is omitted.  Convention: see `Recorder-CLI-Conventions.md` §5.
const ENV_OUT_DIR: &str = "CODETRACER_CIRCOM_RECORDER_OUT_DIR";

/// Environment variable that, when set to `1`/`true`, disables tracing
/// entirely — the recorder runs as a transparent pass-through.
const ENV_DISABLED: &str = "CODETRACER_CIRCOM_RECORDER_DISABLED";

/// Default output directory used when neither `--out-dir` nor
/// `CODETRACER_CIRCOM_RECORDER_OUT_DIR` is set.
const DEFAULT_OUT_DIR: &str = "./ct-traces/";

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// CodeTracer Circom recorder -- record Circom circuit execution traces.
///
/// Traces are always written in the canonical CTFS multi-stream format.
/// To convert a recorded `.ct` bundle to JSON / text for inspection, use
/// `ct print` from `codetracer-trace-format-nim`.
#[derive(Debug, Parser)]
#[command(
    name = "codetracer-circom-recorder",
    version,
    about = "Record Circom circuit execution traces for CodeTracer (CTFS-only). \
            Use `ct print` from codetracer-trace-format-nim for human-readable conversion.",
    long_about = "Record Circom circuit execution traces for CodeTracer.\n\
                  \n\
                  Output is always written in the canonical CodeTracer CTFS\n\
                  multi-stream format. Use `ct print` (shipped with the\n\
                  codetracer-trace-format-nim sibling) to convert a recorded\n\
                  `.ct` bundle to JSON or other human-readable forms.\n\
                  \n\
                  Environment variables:\n\
                    CODETRACER_CIRCOM_RECORDER_OUT_DIR    fallback for --out-dir\n\
                    CODETRACER_CIRCOM_RECORDER_DISABLED   set to 1/true to skip recording\n\
                    CODETRACER_CIRCOM_RECORDER_LOG_LEVEL  log verbosity (advisory)\n\
                    CIRCOM_BIN                            path to the upstream circom compiler"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Record execution of a Circom circuit.
    ///
    /// Compiles the given .circom source file, runs the generated witness
    /// calculator, captures the execution trace, and writes a CTFS bundle
    /// to `--out-dir`.
    Record(RecordArgs),

    /// Print version information.
    Version,
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
    /// The directory will be created if it does not exist.  Falls back to
    /// the `CODETRACER_CIRCOM_RECORDER_OUT_DIR` environment variable when
    /// the flag is omitted.
    #[arg(short = 'o', long)]
    out_dir: Option<PathBuf>,

    /// Witness generator backend to use.
    ///
    /// The C++ backend is faster for large circuits but requires
    /// gcc/make in the dev shell.
    #[arg(short = 'b', long, default_value = "wasm")]
    backend: WitnessBackend,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the effective output directory:
///   1. `--out-dir` if given on the CLI.
///   2. `CODETRACER_CIRCOM_RECORDER_OUT_DIR` env var.
///   3. `DEFAULT_OUT_DIR` ("./ct-traces/").
fn resolve_out_dir(cli_out_dir: Option<PathBuf>) -> PathBuf {
    if let Some(path) = cli_out_dir {
        return path;
    }
    if let Some(value) = std::env::var_os(ENV_OUT_DIR) {
        if !value.is_empty() {
            return PathBuf::from(value);
        }
    }
    PathBuf::from(DEFAULT_OUT_DIR)
}

/// Whether the recorder is disabled via env var.  When true, the CLI
/// must execute its target operation in pass-through mode without
/// emitting any trace artefacts.
fn recording_disabled() -> bool {
    match std::env::var(ENV_DISABLED) {
        Ok(value) => {
            let v = value.trim();
            v == "1" || v.eq_ignore_ascii_case("true")
        }
        Err(_) => false,
    }
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

    if recording_disabled() {
        // Pass-through: the Circom recorder doesn't run a separate target
        // process — it shells out to `circom` and runs the witness
        // calculator itself — so disabling recording simply means "don't
        // emit any trace artefacts".
        eprintln!("{ENV_DISABLED} is set; skipping trace recording (no output written).");
        return Ok(());
    }

    let use_cpp = matches!(args.backend, WitnessBackend::Cpp);
    if use_cpp {
        eprintln!("Using C++ witness generator backend");
    }

    // 2. Resolve and create the output directory
    let out_dir = resolve_out_dir(args.out_dir);
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("cannot create output dir: {}", out_dir.display()))?;

    // 3. Run the recorder (CTFS only)
    codetracer_circom_recorder::recorder::record(&source_path, &out_dir, use_cpp)?;

    eprintln!("Trace files written to {}", out_dir.display());

    Ok(())
}
