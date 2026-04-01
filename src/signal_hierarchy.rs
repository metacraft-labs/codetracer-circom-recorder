//! Signal hierarchy support for complex Circom circuits.
//!
//! Circom `.sym` files produce signal names like `main.adder.out` or
//! `main.values[0]`. This module provides types and functions to parse
//! these dotted, possibly array-indexed signal paths into a hierarchical
//! representation suitable for structured trace output.

use std::collections::HashMap;

/// A single component in a signal path, e.g. `"adder"` or `"values[2]"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathComponent {
    /// The base name without any array index (e.g. `"values"`).
    pub name: String,
    /// Optional array index (e.g. `Some(2)` for `"values[2]"`).
    pub index: Option<usize>,
}

impl std::fmt::Display for PathComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(idx) = self.index {
            write!(f, "[{}]", idx)?;
        }
        Ok(())
    }
}

/// A parsed hierarchical signal path.
///
/// For example, `"main.adder.out"` becomes `["main", "adder", "out"]`
/// and `"main.values[0]"` becomes `["main", "values[0]"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalPath {
    /// The components of the path, from root to leaf.
    pub components: Vec<PathComponent>,
}

impl SignalPath {
    /// Parse a dotted signal name into a `SignalPath`.
    ///
    /// Examples:
    /// - `"main.out"` -> components: `[main, out]`
    /// - `"main.adder.out"` -> components: `[main, adder, out]`
    /// - `"main.values[0]"` -> components: `[main, values[0]]`
    /// - `"main.comp.arr[3]"` -> components: `[main, comp, arr[3]]`
    pub fn parse(name: &str) -> Self {
        let parts: Vec<&str> = name.split('.').collect();
        let components = parts
            .iter()
            .map(|part| parse_path_component(part))
            .collect();
        SignalPath { components }
    }

    /// The depth of the path (number of components).
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// The leaf (last) component name, without array index.
    pub fn leaf_name(&self) -> &str {
        self.components
            .last()
            .map(|c| c.name.as_str())
            .unwrap_or("")
    }

    /// The leaf component's array index, if any.
    pub fn leaf_index(&self) -> Option<usize> {
        self.components.last().and_then(|c| c.index)
    }

    /// Return the parent path (all components except the last).
    /// Returns `None` if the path has only one component.
    pub fn parent(&self) -> Option<SignalPath> {
        if self.components.len() <= 1 {
            return None;
        }
        Some(SignalPath {
            components: self.components[..self.components.len() - 1].to_vec(),
        })
    }

    /// The full dotted string representation.
    pub fn full_name(&self) -> String {
        self.components
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Return the component path (all components except "main" prefix and the leaf signal).
    /// For `main.adder.out` this returns `["adder"]`.
    /// For `main.out` this returns `[]`.
    pub fn component_path(&self) -> Vec<&PathComponent> {
        if self.components.len() <= 2 {
            return vec![];
        }
        // Skip "main" (first) and signal name (last).
        self.components[1..self.components.len() - 1]
            .iter()
            .collect()
    }
}

/// Parse a single path component like `"values[2]"` into name + optional index.
fn parse_path_component(s: &str) -> PathComponent {
    if let Some(bracket_pos) = s.find('[') {
        let name = s[..bracket_pos].to_string();
        let index_str = &s[bracket_pos + 1..];
        let index = index_str.trim_end_matches(']').parse::<usize>().ok();
        PathComponent { name, index }
    } else {
        PathComponent {
            name: s.to_string(),
            index: None,
        }
    }
}

/// A node in the signal hierarchy tree.
#[derive(Debug, Clone)]
pub struct HierarchyNode {
    /// The component name at this level.
    pub name: String,
    /// Signals directly in this component (leaf name -> value).
    pub signals: Vec<(String, i64)>,
    /// Sub-components keyed by name.
    pub children: HashMap<String, HierarchyNode>,
}

impl HierarchyNode {
    fn new(name: &str) -> Self {
        HierarchyNode {
            name: name.to_string(),
            signals: Vec::new(),
            children: HashMap::new(),
        }
    }
}

/// A hierarchical grouping of signals by component.
///
/// Built from a flat list of `(signal_name, value)` pairs where signal names
/// use dotted notation (e.g. `"main.adder.out"`).
#[derive(Debug, Clone)]
pub struct SignalHierarchy {
    /// The root node (typically "main").
    pub root: HierarchyNode,
}

impl SignalHierarchy {
    /// Query all signals under a given component path.
    ///
    /// For example, `get_signals_for_component(&["main", "adder"])` returns
    /// all signals directly in the `adder` sub-component.
    pub fn get_signals_for_component(&self, path: &[&str]) -> Vec<(String, i64)> {
        let mut node = &self.root;
        for (i, &name) in path.iter().enumerate() {
            if i == 0 && node.name == name {
                continue;
            }
            match node.children.get(name) {
                Some(child) => node = child,
                None => return vec![],
            }
        }
        node.signals.clone()
    }

    /// Get all direct child component names under a given path.
    pub fn get_child_components(&self, path: &[&str]) -> Vec<String> {
        let mut node = &self.root;
        for (i, &name) in path.iter().enumerate() {
            if i == 0 && node.name == name {
                continue;
            }
            match node.children.get(name) {
                Some(child) => node = child,
                None => return vec![],
            }
        }
        node.children.keys().cloned().collect()
    }

    /// Get all signals whose leaf name matches an array pattern (same base name,
    /// different indices). Returns them sorted by index.
    pub fn get_array_signals(&self, path: &[&str], base_name: &str) -> Vec<(usize, i64)> {
        let signals = self.get_signals_for_component(path);
        let mut results: Vec<(usize, i64)> = signals
            .iter()
            .filter_map(|(name, val)| {
                if let Some(bracket_pos) = name.find('[') {
                    let n = &name[..bracket_pos];
                    if n == base_name {
                        let idx_str = &name[bracket_pos + 1..];
                        let idx = idx_str.trim_end_matches(']').parse::<usize>().ok()?;
                        return Some((idx, *val));
                    }
                }
                None
            })
            .collect();
        results.sort_by_key(|(idx, _)| *idx);
        results
    }

    /// Collect all signals in the hierarchy as flat `(full_path, value)` pairs.
    pub fn flatten(&self) -> Vec<(String, i64)> {
        let mut result = Vec::new();
        flatten_node(&self.root, &mut Vec::new(), &mut result);
        result
    }
}

fn flatten_node(node: &HierarchyNode, prefix: &mut Vec<String>, out: &mut Vec<(String, i64)>) {
    prefix.push(node.name.clone());
    for (sig_name, val) in &node.signals {
        let mut full = prefix.join(".");
        full.push('.');
        full.push_str(sig_name);
        out.push((full, *val));
    }
    for child in node.children.values() {
        flatten_node(child, prefix, out);
    }
    prefix.pop();
}

/// Build a signal hierarchy from a flat list of `(full_signal_name, value)` pairs.
///
/// Signal names are expected in dotted notation, e.g.:
/// - `"main.out"` (direct signal of main)
/// - `"main.adder.out"` (signal of a sub-component)
/// - `"main.values[0]"` (array signal)
pub fn build_hierarchy(signals: &[(String, i64)]) -> SignalHierarchy {
    let mut root = HierarchyNode::new("main");

    for (name, value) in signals {
        let path = SignalPath::parse(name);

        if path.components.is_empty() {
            continue;
        }

        // Navigate/create the hierarchy, treating all but the last component
        // as container nodes, and the last as the signal leaf.
        let mut node = &mut root;

        // Skip the first component if it's "main" (our root).
        let start = if path.components[0].name == "main" {
            1
        } else {
            0
        };

        if start >= path.components.len() {
            continue;
        }

        // All components except the last are intermediate nodes.
        let intermediate = &path.components[start..path.components.len() - 1];
        for comp in intermediate {
            node = node
                .children
                .entry(comp.name.clone())
                .or_insert_with(|| HierarchyNode::new(&comp.name));
        }

        // The last component is the signal itself.
        let leaf = &path.components[path.components.len() - 1];
        let sig_name = leaf.to_string();
        node.signals.push((sig_name, *value));
    }

    SignalHierarchy { root }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- SignalPath parsing tests --

    #[test]
    fn test_parse_simple_signal() {
        let path = SignalPath::parse("main.out");
        assert_eq!(path.depth(), 2);
        assert_eq!(path.components[0].name, "main");
        assert_eq!(path.components[0].index, None);
        assert_eq!(path.components[1].name, "out");
        assert_eq!(path.components[1].index, None);
        assert_eq!(path.leaf_name(), "out");
        assert_eq!(path.leaf_index(), None);
        assert_eq!(path.full_name(), "main.out");
    }

    #[test]
    fn test_parse_sub_component_signal() {
        let path = SignalPath::parse("main.adder.out");
        assert_eq!(path.depth(), 3);
        assert_eq!(path.components[0].name, "main");
        assert_eq!(path.components[1].name, "adder");
        assert_eq!(path.components[2].name, "out");
        assert_eq!(path.leaf_name(), "out");
        assert_eq!(path.full_name(), "main.adder.out");
    }

    #[test]
    fn test_parse_deep_hierarchy() {
        let path = SignalPath::parse("main.a.b.c.signal");
        assert_eq!(path.depth(), 5);
        assert_eq!(path.components[1].name, "a");
        assert_eq!(path.components[2].name, "b");
        assert_eq!(path.components[3].name, "c");
        assert_eq!(path.leaf_name(), "signal");
    }

    #[test]
    fn test_parse_array_signal() {
        let path = SignalPath::parse("main.values[0]");
        assert_eq!(path.depth(), 2);
        assert_eq!(path.components[1].name, "values");
        assert_eq!(path.components[1].index, Some(0));
        assert_eq!(path.leaf_name(), "values");
        assert_eq!(path.leaf_index(), Some(0));
        assert_eq!(path.full_name(), "main.values[0]");
    }

    #[test]
    fn test_parse_array_in_sub_component() {
        let path = SignalPath::parse("main.comp.arr[3]");
        assert_eq!(path.depth(), 3);
        assert_eq!(path.components[1].name, "comp");
        assert_eq!(path.components[1].index, None);
        assert_eq!(path.components[2].name, "arr");
        assert_eq!(path.components[2].index, Some(3));
    }

    #[test]
    fn test_parse_single_component() {
        let path = SignalPath::parse("out");
        assert_eq!(path.depth(), 1);
        assert_eq!(path.leaf_name(), "out");
        assert_eq!(path.parent(), None);
    }

    #[test]
    fn test_parent_path() {
        let path = SignalPath::parse("main.adder.out");
        let parent = path.parent().unwrap();
        assert_eq!(parent.full_name(), "main.adder");
        let grandparent = parent.parent().unwrap();
        assert_eq!(grandparent.full_name(), "main");
        assert_eq!(grandparent.parent(), None);
    }

    #[test]
    fn test_component_path() {
        let path = SignalPath::parse("main.adder.out");
        let comp_path = path.component_path();
        assert_eq!(comp_path.len(), 1);
        assert_eq!(comp_path[0].name, "adder");

        let path2 = SignalPath::parse("main.out");
        assert!(path2.component_path().is_empty());

        let path3 = SignalPath::parse("main.a.b.signal");
        let comp_path3 = path3.component_path();
        assert_eq!(comp_path3.len(), 2);
        assert_eq!(comp_path3[0].name, "a");
        assert_eq!(comp_path3[1].name, "b");
    }

    // -- SignalHierarchy tests --

    #[test]
    fn test_build_simple_hierarchy() {
        let signals = vec![
            ("main.a".to_string(), 10),
            ("main.b".to_string(), 20),
            ("main.out".to_string(), 30),
        ];
        let hierarchy = build_hierarchy(&signals);
        let sigs = hierarchy.get_signals_for_component(&["main"]);
        assert_eq!(sigs.len(), 3);
        assert!(sigs.contains(&("a".to_string(), 10)));
        assert!(sigs.contains(&("b".to_string(), 20)));
        assert!(sigs.contains(&("out".to_string(), 30)));
    }

    #[test]
    fn test_build_hierarchy_with_sub_components() {
        let signals = vec![
            ("main.in".to_string(), 5),
            ("main.adder.a".to_string(), 10),
            ("main.adder.b".to_string(), 20),
            ("main.adder.out".to_string(), 30),
            ("main.out".to_string(), 30),
        ];
        let hierarchy = build_hierarchy(&signals);

        // Main-level signals
        let main_sigs = hierarchy.get_signals_for_component(&["main"]);
        assert_eq!(main_sigs.len(), 2);
        assert!(main_sigs.contains(&("in".to_string(), 5)));
        assert!(main_sigs.contains(&("out".to_string(), 30)));

        // Adder sub-component signals
        let adder_sigs = hierarchy.get_signals_for_component(&["main", "adder"]);
        assert_eq!(adder_sigs.len(), 3);
        assert!(adder_sigs.contains(&("a".to_string(), 10)));
        assert!(adder_sigs.contains(&("b".to_string(), 20)));
        assert!(adder_sigs.contains(&("out".to_string(), 30)));

        // Child components of main
        let children = hierarchy.get_child_components(&["main"]);
        assert!(children.contains(&"adder".to_string()));
    }

    #[test]
    fn test_hierarchy_with_arrays() {
        let signals = vec![
            ("main.values[0]".to_string(), 100),
            ("main.values[1]".to_string(), 200),
            ("main.values[2]".to_string(), 300),
            ("main.out".to_string(), 600),
        ];
        let hierarchy = build_hierarchy(&signals);

        // Array signals should be queryable
        let arr = hierarchy.get_array_signals(&["main"], "values");
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], (0, 100));
        assert_eq!(arr[1], (1, 200));
        assert_eq!(arr[2], (2, 300));
    }

    #[test]
    fn test_hierarchy_nested_with_arrays() {
        let signals = vec![
            ("main.comp.items[0]".to_string(), 1),
            ("main.comp.items[1]".to_string(), 2),
            ("main.comp.result".to_string(), 3),
        ];
        let hierarchy = build_hierarchy(&signals);

        let comp_sigs = hierarchy.get_signals_for_component(&["main", "comp"]);
        assert_eq!(comp_sigs.len(), 3);

        let arr = hierarchy.get_array_signals(&["main", "comp"], "items");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0], (0, 1));
        assert_eq!(arr[1], (1, 2));
    }

    #[test]
    fn test_nonexistent_component() {
        let signals = vec![("main.a".to_string(), 1)];
        let hierarchy = build_hierarchy(&signals);
        let sigs = hierarchy.get_signals_for_component(&["main", "nonexistent"]);
        assert!(sigs.is_empty());
        let children = hierarchy.get_child_components(&["main", "nonexistent"]);
        assert!(children.is_empty());
    }

    #[test]
    fn test_flatten_hierarchy() {
        let signals = vec![
            ("main.a".to_string(), 10),
            ("main.adder.out".to_string(), 30),
        ];
        let hierarchy = build_hierarchy(&signals);
        let flat = hierarchy.flatten();
        assert_eq!(flat.len(), 2);
        // Check that flattened paths include the full dotted name
        let names: Vec<&str> = flat.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"main.a"));
        assert!(names.contains(&"main.adder.out"));
    }
}
