//! Recording logic for Circom execution traces.
//!
//! This module provides the top-level `record` function that reads a Circom
//! source file, drives the upstream `circom` compiler, runs the generated
//! witness calculator, captures the trace, and writes a CodeTracer CTFS
//! trace bundle.
//!
//! The output format is fixed to CTFS — see
//! `Recorder-CLI-Conventions.md` §4 in `codetracer-specs`.  Use `ct print`
//! (from `codetracer-trace-format-nim`) for human-readable conversion of
//! the produced bundle.

use std::path::Path;

use eyre::{Context, Result};

use crate::tracer::CircomTracer;

/// Record a Circom execution trace.
///
/// Reads the Circom source file at `source_path`, parses signal declarations
/// and assignments, evaluates them, captures the trace, and writes a CTFS
/// bundle to `out_dir`.
pub fn record(source_path: &Path, out_dir: &Path, use_cpp: bool) -> Result<()> {
    let source_code = std::fs::read_to_string(source_path)
        .with_context(|| format!("failed to read source file: {}", source_path.display()))?;

    if use_cpp {
        CircomTracer::trace_program_cpp(source_path, &source_code, out_dir)
    } else {
        CircomTracer::trace_program(source_path, &source_code, out_dir)
    }
}
