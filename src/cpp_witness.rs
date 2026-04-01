//! C++ witness generator support for Circom circuits.
//!
//! When circom compiles with `--c`, it produces C++ source code for witness
//! generation that is significantly faster than the WASM path for large
//! circuits. This module handles:
//!
//! 1. Compiling the generated C++ code with debug symbols
//! 2. Running the compiled witness generator
//! 3. Parsing the witness output
//! 4. Optionally loading a `.srcmap.json` from the forked circom compiler
//!    for precise source-level mapping

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use eyre::{Context, Result, eyre};
use num_bigint::BigUint;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Compiler source map (from forked circom with --srcmap)
// ---------------------------------------------------------------------------

/// A source map entry from the forked circom compiler's `.srcmap.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct SrcMapEntry {
    /// Template name (e.g., "FlowTest").
    pub template_name: String,
    /// Signal name if this entry corresponds to a signal assignment.
    pub signal_name: Option<String>,
    /// File ID (index into the files array).
    pub file_id: usize,
    /// 1-based source line number.
    pub source_line: usize,
    /// 1-based source column number.
    pub source_column: usize,
    /// Name of the generated function (for WASM/C++).
    pub generated_function: Option<String>,
    /// Statement type (e.g., "substitution", "constraint", "declaration").
    pub statement_type: Option<String>,
}

/// A file entry in the source map.
#[derive(Debug, Clone, Deserialize)]
pub struct SrcMapFile {
    /// File ID.
    pub id: usize,
    /// File path (relative or absolute).
    pub path: String,
}

/// The complete source map from the forked circom compiler.
#[derive(Debug, Clone, Deserialize)]
pub struct CompilerSourceMap {
    /// Source map format version.
    pub version: u32,
    /// Source files referenced by the mappings.
    pub files: Vec<SrcMapFile>,
    /// Source map entries.
    pub mappings: Vec<SrcMapEntry>,
}

impl CompilerSourceMap {
    /// Load a source map from a `.srcmap.json` file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read source map: {}", path.display()))?;
        let map: CompilerSourceMap = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse source map: {}", path.display()))?;
        Ok(map)
    }

    /// Look up the source location for a signal by template and signal name.
    pub fn find_signal(
        &self,
        template_name: &str,
        signal_name: &str,
    ) -> Option<&SrcMapEntry> {
        self.mappings.iter().find(|e| {
            e.template_name == template_name
                && e.signal_name.as_deref() == Some(signal_name)
        })
    }

    /// Get all entries for a given template.
    pub fn entries_for_template(&self, template_name: &str) -> Vec<&SrcMapEntry> {
        self.mappings
            .iter()
            .filter(|e| e.template_name == template_name)
            .collect()
    }

    /// Resolve a file ID to a file path.
    pub fn file_path(&self, file_id: usize) -> Option<&str> {
        self.files.iter().find(|f| f.id == file_id).map(|f| f.path.as_str())
    }
}

// ---------------------------------------------------------------------------
// C++ witness generator compilation and execution
// ---------------------------------------------------------------------------

/// Compile the circom-generated C++ witness generator.
///
/// The circom `--c` flag produces:
/// - `<stem>_cpp/<stem>.cpp` — main circuit code
/// - `<stem>_cpp/main.cpp` — entry point
/// - `<stem>_cpp/calcwit.cpp` / `calcwit.hpp` — witness calculator runtime
/// - `<stem>_cpp/circom.hpp` — circom types
/// - `<stem>_cpp/fr.hpp` / `fr.cpp` / `fr.asm` — field arithmetic
/// - `<stem>_cpp/Makefile` — build script
///
/// We compile with `-g` for debug symbols and `-O0` to preserve structure.
pub fn compile_cpp_witness(
    compile_dir: &Path,
    stem: &str,
) -> Result<PathBuf> {
    let cpp_dir = compile_dir.join(format!("{stem}_cpp"));

    if !cpp_dir.exists() {
        return Err(eyre!(
            "C++ witness generator directory not found: {}",
            cpp_dir.display()
        ));
    }

    // Check if Makefile exists
    let makefile = cpp_dir.join("Makefile");
    if !makefile.exists() {
        return Err(eyre!(
            "Makefile not found in C++ witness directory: {}",
            cpp_dir.display()
        ));
    }

    // Build using make with debug flags
    let output = Command::new("make")
        .arg("-C")
        .arg(&cpp_dir)
        .env("CFLAGS", "-g -O0")
        .env("CXXFLAGS", "-g -O0")
        .output()
        .with_context(|| "failed to run make for C++ witness generator")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(eyre!(
            "C++ witness generator compilation failed:\nstdout: {stdout}\nstderr: {stderr}"
        ));
    }

    // The compiled binary is <stem>
    let binary = cpp_dir.join(stem);
    if !binary.exists() {
        return Err(eyre!(
            "compiled witness binary not found: {}",
            binary.display()
        ));
    }

    eprintln!("C++ witness generator compiled: {}", binary.display());
    Ok(binary)
}

/// Run the C++ witness generator and parse the output witness.
///
/// The C++ witness generator reads input from a JSON file and writes
/// the witness to a `.wtns` file. We parse the witness values from the
/// binary `.wtns` file format.
pub fn run_cpp_witness(
    binary_path: &Path,
    input_json_path: &Path,
    output_wtns_path: &Path,
) -> Result<Vec<BigUint>> {
    let output = Command::new(binary_path)
        .arg(input_json_path)
        .arg(output_wtns_path)
        .output()
        .with_context(|| format!("failed to run C++ witness generator: {}", binary_path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(eyre!(
            "C++ witness generator failed:\n{}",
            stderr
        ));
    }

    // Parse the .wtns file
    parse_wtns_file(output_wtns_path)
}

/// Parse a `.wtns` (witness) binary file.
///
/// Format:
/// - 4 bytes: magic "wtns"
/// - 4 bytes: version (u32 LE)
/// - 4 bytes: number of sections (u32 LE)
///
/// Section 1 (field info):
/// - 4 bytes: section type (1)
/// - 8 bytes: section size (u64 LE)
/// - 4 bytes: field element size in bytes (n8)
/// - n8 bytes: prime (LE)
/// - 4 bytes: witness count (u32 LE)
///
/// Section 2 (witness values):
/// - 4 bytes: section type (2)
/// - 8 bytes: section size (u64 LE)
/// - witness_count * n8 bytes: field elements (LE)
fn parse_wtns_file(path: &Path) -> Result<Vec<BigUint>> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read .wtns file: {}", path.display()))?;

    if data.len() < 12 {
        return Err(eyre!(".wtns file too small"));
    }

    // Check magic
    if &data[0..4] != b"wtns" {
        return Err(eyre!(".wtns file has invalid magic"));
    }

    let _version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let num_sections = u32::from_le_bytes(data[8..12].try_into().unwrap());

    let mut pos = 12;
    let mut n8: usize = 0;
    let mut witness_count: usize = 0;
    let mut witness_data_start: usize = 0;

    for _ in 0..num_sections {
        if pos + 12 > data.len() {
            return Err(eyre!(".wtns file truncated at section header"));
        }

        let section_type = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());
        let section_size =
            u64::from_le_bytes(data[pos + 4..pos + 12].try_into().unwrap()) as usize;
        pos += 12;

        if section_type == 1 {
            // Field info section
            if section_size < 4 {
                return Err(eyre!(".wtns field info section too small"));
            }
            n8 = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            // Skip prime (n8 bytes)
            if pos + 4 + n8 + 4 > data.len() {
                return Err(eyre!(".wtns field info truncated"));
            }
            witness_count = u32::from_le_bytes(
                data[pos + 4 + n8..pos + 4 + n8 + 4].try_into().unwrap(),
            ) as usize;
        } else if section_type == 2 {
            // Witness data section
            witness_data_start = pos;
        }

        pos += section_size;
    }

    if n8 == 0 || witness_count == 0 || witness_data_start == 0 {
        return Err(eyre!(".wtns file missing required sections"));
    }

    // Parse witness values
    let mut witness = Vec::with_capacity(witness_count);
    let mut wpos = witness_data_start;
    for _ in 0..witness_count {
        if wpos + n8 > data.len() {
            return Err(eyre!(".wtns witness data truncated"));
        }
        let val = BigUint::from_bytes_le(&data[wpos..wpos + n8]);
        witness.push(val);
        wpos += n8;
    }

    Ok(witness)
}

/// Write an input JSON file for the witness generator.
///
/// Format: `{"signal_name": ["value", ...], ...}`
pub fn write_input_json(
    path: &Path,
    inputs: &HashMap<String, Vec<String>>,
) -> Result<()> {
    let json = serde_json::to_string_pretty(inputs)
        .with_context(|| "failed to serialize input JSON")?;
    std::fs::write(path, json)
        .with_context(|| format!("failed to write input JSON: {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_source_map_deserialize() {
        let json = r#"{
            "version": 1,
            "files": [
                {"id": 0, "path": "flow_test.circom"}
            ],
            "mappings": [
                {
                    "template_name": "FlowTest",
                    "signal_name": "a",
                    "file_id": 0,
                    "source_line": 5,
                    "source_column": 4,
                    "generated_function": "FlowTest_0_run",
                    "statement_type": "substitution"
                },
                {
                    "template_name": "FlowTest",
                    "signal_name": "out",
                    "file_id": 0,
                    "source_line": 9,
                    "source_column": 4,
                    "generated_function": "FlowTest_0_run",
                    "statement_type": "substitution"
                }
            ]
        }"#;

        let map: CompilerSourceMap = serde_json::from_str(json).unwrap();
        assert_eq!(map.version, 1);
        assert_eq!(map.files.len(), 1);
        assert_eq!(map.files[0].path, "flow_test.circom");
        assert_eq!(map.mappings.len(), 2);

        let entry = map.find_signal("FlowTest", "a").unwrap();
        assert_eq!(entry.source_line, 5);

        let entries = map.entries_for_template("FlowTest");
        assert_eq!(entries.len(), 2);

        assert_eq!(map.file_path(0), Some("flow_test.circom"));
        assert_eq!(map.file_path(99), None);
    }

    #[test]
    fn test_compiler_source_map_find_missing() {
        let json = r#"{
            "version": 1,
            "files": [],
            "mappings": []
        }"#;
        let map: CompilerSourceMap = serde_json::from_str(json).unwrap();
        assert!(map.find_signal("Foo", "bar").is_none());
        assert!(map.entries_for_template("Foo").is_empty());
    }

    #[test]
    fn test_write_input_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.json");

        let mut inputs = HashMap::new();
        inputs.insert("a".to_string(), vec!["10".to_string()]);
        inputs.insert("b".to_string(), vec!["32".to_string()]);

        write_input_json(&path, &inputs).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: HashMap<String, Vec<String>> = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["a"], vec!["10"]);
        assert_eq!(parsed["b"], vec!["32"]);
    }

    #[test]
    fn test_parse_wtns_missing_file() {
        let result = parse_wtns_file(Path::new("/nonexistent/witness.wtns"));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wtns_invalid_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.wtns");
        std::fs::write(&path, b"baad\x01\x00\x00\x00\x02\x00\x00\x00").unwrap();
        let result = parse_wtns_file(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid magic"));
    }

    #[test]
    fn test_parse_wtns_valid() {
        // Construct a minimal valid .wtns file with 2 witness values
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wtns");

        let n8: u32 = 4; // 4-byte field elements for testing
        let witness_count: u32 = 2;
        let prime: u32 = 0xFFFF_FFFD; // Fake prime

        let mut data = Vec::new();
        // Header
        data.extend_from_slice(b"wtns");
        data.extend_from_slice(&2u32.to_le_bytes()); // version
        data.extend_from_slice(&2u32.to_le_bytes()); // num_sections

        // Section 1: field info
        data.extend_from_slice(&1u32.to_le_bytes()); // section type
        let section1_size = 4 + n8 as u64 + 4;
        data.extend_from_slice(&section1_size.to_le_bytes()); // section size
        data.extend_from_slice(&n8.to_le_bytes()); // n8
        data.extend_from_slice(&prime.to_le_bytes()); // prime
        data.extend_from_slice(&witness_count.to_le_bytes()); // witness count

        // Section 2: witness data
        data.extend_from_slice(&2u32.to_le_bytes()); // section type
        let section2_size = (witness_count * n8) as u64;
        data.extend_from_slice(&section2_size.to_le_bytes()); // section size
        data.extend_from_slice(&42u32.to_le_bytes()); // witness[0] = 42
        data.extend_from_slice(&94u32.to_le_bytes()); // witness[1] = 94

        std::fs::write(&path, &data).unwrap();

        let witness = parse_wtns_file(&path).unwrap();
        assert_eq!(witness.len(), 2);
        assert_eq!(witness[0], BigUint::from(42u64));
        assert_eq!(witness[1], BigUint::from(94u64));
    }
}
