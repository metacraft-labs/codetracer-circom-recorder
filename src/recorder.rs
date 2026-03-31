//! Recording logic for Circom execution traces.
//!
//! This module provides the top-level `record` function that reads a Circom
//! source file, evaluates signal assignments, captures the trace, and writes
//! CodeTracer output.

use std::path::Path;

use codetracer_trace_writer::TraceEventsFileFormat;
use eyre::{Context, Result};

use crate::tracer::CircomTracer;

/// Record a Circom execution trace.
///
/// Reads the Circom source file at `source_path`, parses signal declarations
/// and assignments, evaluates them, captures the trace, and writes CodeTracer
/// trace files to `out_dir`.
pub fn record(
    source_path: &Path,
    out_dir: &Path,
    format: TraceEventsFileFormat,
) -> Result<()> {
    let source_code = std::fs::read_to_string(source_path)
        .with_context(|| format!("failed to read source file: {}", source_path.display()))?;

    CircomTracer::trace_program(source_path, &source_code, out_dir, format)
}
