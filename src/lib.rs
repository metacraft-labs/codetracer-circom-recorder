//! CodeTracer recorder for Circom circuit programs.
//!
//! This crate captures execution traces from Circom circuits by parsing
//! signal declarations and assignments, evaluating them in order, and
//! converting the results into the CodeTracer trace format for debugging
//! and analysis.

pub mod recorder;
pub mod source_map;
pub mod tracer;
