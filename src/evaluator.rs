//! Structured Circom evaluator.
//!
//! Parses Circom template bodies into a `Stmt`-typed AST and walks the
//! statements in order to (a) compute concrete `i64`-valued signal /
//! variable assignments (matching the language's compile-time witness
//! semantics for inputs that default to `0`), and (b) drive the
//! recorder's `register_step` / `register_variable_with_full_value` /
//! `register_call` calls so the trace contains a step per executed
//! line, a value per assignment, and a call per template instantiation.
//!
//! Scope: this evaluator handles the constructs exercised by the
//! shipped fixtures —
//!
//! * `var` declarations and reassignments,
//! * `signal {input,output,intermediate}` declarations,
//! * `<==`, `<--`, and `===` operators,
//! * `for (var i = init; i < N; i++) { ... }` (compile-time bounded),
//! * `if (cond) { ... } else { ... }` (cond on a `var`),
//! * arithmetic / comparison expressions over integer literals,
//! * `component name = Template(args);` and `name.signal <== expr;`
//!   wiring,
//! * member access `comp.signal` reading the wired sub-template's
//!   output value.
//!
//! Anything outside this set falls back to the legacy brace-tracking
//! parser in `tracer.rs`.

use std::cell::RefCell;
use std::collections::HashMap;

thread_local! {
    /// Active function table for the current evaluation.  Set by
    /// `evaluate_template` for the duration of its body so existing
    /// `eval_expr(...)` callers (which don't thread `fns` explicitly)
    /// still resolve `Expr::Call(name, args)` references against the
    /// surrounding program's `function` definitions.  Stored as a
    /// raw pointer because the lifetime is bounded by the
    /// `evaluate_template` call frame and the only consumers run on
    /// the same thread.
    static ACTIVE_FUNCTIONS: RefCell<*const HashMap<String, Function>> =
        const { RefCell::new(std::ptr::null()) };
}

/// RAII guard that installs a function table for the lifetime of the
/// guard, restoring the previous binding (typically a null pointer)
/// when dropped.  Used by `evaluate_template` so nested calls into
/// `eval_expr(...)` resolve `Expr::Call` references against the
/// surrounding program's `function` definitions.
struct FnsGuard {
    prev: *const HashMap<String, Function>,
}

impl FnsGuard {
    fn install(fns: &HashMap<String, Function>) -> Self {
        let prev = ACTIVE_FUNCTIONS.with(|cell| {
            let prev = *cell.borrow();
            *cell.borrow_mut() = fns as *const _;
            prev
        });
        Self { prev }
    }
}

impl Drop for FnsGuard {
    fn drop(&mut self) {
        ACTIVE_FUNCTIONS.with(|cell| {
            *cell.borrow_mut() = self.prev;
        });
    }
}

/// Run `f` with the active function table (if any) borrowed for the
/// duration of the closure.  Safe wrapper around the raw thread-local
/// pointer — the closure cannot outlive the `FnsGuard` that installed
/// the binding because it runs synchronously inside the same
/// `with(...)` callback.
fn with_active_fns<R>(f: impl FnOnce(Option<&HashMap<String, Function>>) -> R) -> R {
    ACTIVE_FUNCTIONS.with(|cell| {
        let p = *cell.borrow();
        let opt = if p.is_null() {
            None
        } else {
            // Safety: the pointer is valid for the lifetime of the
            // surrounding `FnsGuard` (installed by
            // `evaluate_template`), which always outlives this
            // synchronous closure.
            Some(unsafe { &*p })
        };
        f(opt)
    })
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// Kind of a signal declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalKind {
    Input,
    Output,
    Intermediate,
}

/// Operator on the left of an `=`-shaped assignment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignOp {
    /// `var x = expr;` or `x = expr;` (compile-time `var` mutation).
    VarAssign,
    /// `x <== expr;` — assignment + constraint.
    SignalAssignConstrain,
    /// `x <-- expr;` — assignment without constraint.
    SignalAssign,
}

#[derive(Debug, Clone)]
pub enum Expr {
    /// Integer literal (positive only — unary minus is `Unary`).
    Int(i64),
    /// Plain identifier (variable or signal in scope).
    Ident(String),
    /// Member access `a.b` (typically `component.signal`).
    Member(Box<Expr>, String),
    /// Indexed access `a[i]`.
    Index(Box<Expr>, Box<Expr>),
    /// Binary operator on two sub-expressions.
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// Unary operator on one sub-expression.
    Unary(UnaryOp, Box<Expr>),
    /// Conditional / ternary expression `cond ? then : else`.  Used by
    /// circomlib's IsZero pattern (`inv <-- in != 0 ? 1/in : 0;`).
    Ternary(Box<Expr>, Box<Expr>, Box<Expr>),
    /// Parenthesised expression.
    Paren(Box<Expr>),
    /// Call expression: `Foo(args...)`.  Used for component/template
    /// instantiation but never appears in normal expressions in the
    /// shipped fixtures (instantiations are lifted to `ComponentDecl`).
    Call(String, Vec<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOp {
    Neg,
    Not,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    /// `var x;` or `var x = expr;`.
    VarDecl {
        line: u32,
        name: String,
        init: Option<Expr>,
    },
    /// `signal x;` / `signal input x;` / `signal output x;`.  Optional
    /// dimensions for arrays, e.g. `signal x[3];`.
    SignalDecl {
        line: u32,
        name: String,
        kind: SignalKind,
        dims: Vec<Expr>,
    },
    /// `input BusName() var;` (Circom 2.2+ bus input declaration).
    /// The variable is bound to a `Value::Component`-shaped slot whose
    /// fields default to 0 (matching the witness calculator's default
    /// for unset inputs).  Field reads through `var.field` resolve via
    /// the existing `Expr::Member` path.
    InputBusDecl {
        line: u32,
        name: String,
        bus_type: String,
    },
    /// `lhs = expr;` or `lhs <== expr;` or `lhs <-- expr;`.
    Assign {
        line: u32,
        op: AssignOp,
        lhs: Expr,
        rhs: Expr,
    },
    /// `lhs === rhs;`.
    Constraint { line: u32, lhs: Expr, rhs: Expr },
    /// `if (cond) { then } else { else_block }`.
    If {
        line: u32,
        cond: Expr,
        then_block: Vec<Stmt>,
        else_block: Vec<Stmt>,
    },
    /// `for (init; cond; update) { body }`.
    For {
        line: u32,
        init: Box<Stmt>,
        cond: Expr,
        update: Box<Stmt>,
        body: Vec<Stmt>,
    },
    /// `component name = Template(args);`.
    ComponentDecl {
        line: u32,
        name: String,
        template: String,
        args: Vec<Expr>,
    },
    /// `component name[N];` — a component-array declaration, with each
    /// element instantiated separately (typically inside a for loop)
    /// via `name[i] = Template(args);`.  Stored separately from
    /// `ComponentDecl` so the structured evaluator can pre-allocate
    /// the array slot before the per-element instantiations land.
    ComponentArrayDecl {
        line: u32,
        name: String,
        dims: Vec<Expr>,
    },
    /// `name[i] = Template(args);` — element-wise component-array
    /// instantiation, typically inside a for loop.  The `index` is
    /// evaluated against the current env to pick the slot.
    ComponentArrayAssign {
        line: u32,
        name: String,
        index: Expr,
        template: String,
        args: Vec<Expr>,
    },
    /// Naked expression statement (e.g. `i++`).
    ExprStmt { line: u32, expr: Expr },
    /// `return expr;` (used for parsing for-loop update statements like
    /// `i++` which we model as an expression statement; this variant
    /// only appears for completeness).
    #[allow(dead_code)]
    Return { line: u32, value: Option<Expr> },
}

/// A parsed template definition.
#[derive(Debug, Clone)]
pub struct Template {
    pub name: String,
    /// 1-based source line of the `template` keyword.
    pub line: u32,
    /// Numeric / generic parameters declared in the template's header
    /// (e.g. `template T(N) { ... }` -> `["N"]`).  These bind into the
    /// `var` env when the template is evaluated.
    pub generic_params: Vec<String>,
    /// Statements inside the template body, in source order.
    pub body: Vec<Stmt>,
    /// Names of `signal input` declarations inside this template, in
    /// source order.  Mirrored from the body so callers don't have to
    /// re-walk it.
    pub input_signals: Vec<String>,
    /// Bus-typed input declarations (Circom 2.2+):
    ///   `input BusName() var;` -> `("var", "BusName")` pairs in source
    /// order.  Mirrored from the body's `Stmt::InputBusDecl` entries.
    pub input_buses: Vec<(String, String)>,
}

/// A parsed `function` definition (compile-time, no signals or
/// constraints).  Functions appear in the recorder's function table
/// distinct from templates — they have no input/output signals, never
/// touch the witness, and are called from `<==` RHS expressions or
/// from other functions.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    /// 1-based source line of the `function` keyword.
    pub line: u32,
    /// Formal parameters bound at call sites.
    pub params: Vec<String>,
    /// Body statements in source order; the last `return` carries the
    /// computed value back to the caller.
    pub body: Vec<Stmt>,
}

/// A parsed `bus NAME() { signal a; signal b; ... }` declaration
/// (Circom 2.2+ composite type).  Buses act as named records of
/// field-element signals that can be passed as a single `input`
/// parameter to a template.  The recorder surfaces a bus-typed input
/// arg as a `ValueRecord::Struct` whose `type_id` points at the
/// registered struct-kind type for `name`.
#[derive(Debug, Clone)]
pub struct Bus {
    pub name: String,
    /// 1-based source line of the `bus` keyword.
    pub line: u32,
    /// Field names declared inside the bus body, in source order.
    /// Only scalar `signal NAME;` fields are recognised — array fields
    /// and nested bus fields are not modelled by the recorder today.
    pub fields: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    Ident(String),
    Int(String), // Lexed as string so we can preserve large literals; we parse to i64 lazily.
    Punct(String),
    Eof,
}

#[derive(Debug, Clone)]
struct LexedTok {
    tok: Tok,
    line: u32,
}

fn tokenize(src: &str) -> Vec<LexedTok> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1u32;
    while i < bytes.len() {
        let b = bytes[i];
        // Whitespace
        if b == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        // Line comment
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                if bytes[i] == b'\n' {
                    line += 1;
                }
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        // Identifier
        if b.is_ascii_alphabetic() || b == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.push(LexedTok {
                tok: Tok::Ident(std::str::from_utf8(&bytes[start..i]).unwrap().to_string()),
                line,
            });
            continue;
        }
        // Integer
        if b.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            out.push(LexedTok {
                tok: Tok::Int(std::str::from_utf8(&bytes[start..i]).unwrap().to_string()),
                line,
            });
            continue;
        }
        // Multi-char punctuation (longest match first)
        let three = if i + 3 <= bytes.len() {
            std::str::from_utf8(&bytes[i..i + 3]).unwrap_or("")
        } else {
            ""
        };
        let two = if i + 2 <= bytes.len() {
            std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("")
        } else {
            ""
        };
        if matches!(three, "<==" | "===" | "<--" | "==>" | "-->" | ">>=" | "<<=") {
            out.push(LexedTok {
                tok: Tok::Punct(three.to_string()),
                line,
            });
            i += 3;
            continue;
        }
        if matches!(
            two,
            "==" | "!="
                | "<="
                | ">="
                | "&&"
                | "||"
                | "<<"
                | ">>"
                | "++"
                | "--"
                | "+="
                | "-="
                | "*="
                | "/="
        ) {
            out.push(LexedTok {
                tok: Tok::Punct(two.to_string()),
                line,
            });
            i += 2;
            continue;
        }
        // Single char
        out.push(LexedTok {
            tok: Tok::Punct((b as char).to_string()),
            line,
        });
        i += 1;
    }
    out.push(LexedTok {
        tok: Tok::Eof,
        line,
    });
    out
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<LexedTok>,
    pos: usize,
}

impl Parser {
    fn new(toks: Vec<LexedTok>) -> Self {
        Self { toks, pos: 0 }
    }

    fn peek(&self) -> &Tok {
        &self.toks[self.pos].tok
    }
    fn peek_line(&self) -> u32 {
        self.toks[self.pos].line
    }
    #[allow(dead_code)]
    fn peek_at(&self, n: usize) -> &Tok {
        &self.toks[(self.pos + n).min(self.toks.len() - 1)].tok
    }
    fn bump(&mut self) -> LexedTok {
        let t = self.toks[self.pos].clone();
        if self.pos + 1 < self.toks.len() {
            self.pos += 1;
        }
        t
    }
    fn eat_punct(&mut self, s: &str) -> bool {
        if let Tok::Punct(p) = self.peek() {
            if p == s {
                self.bump();
                return true;
            }
        }
        false
    }
    fn expect_punct(&mut self, s: &str) -> Result<(), String> {
        if self.eat_punct(s) {
            Ok(())
        } else {
            Err(format!(
                "expected `{}` at line {}, got {:?}",
                s,
                self.peek_line(),
                self.peek()
            ))
        }
    }
    fn eat_ident(&mut self, name: &str) -> bool {
        if let Tok::Ident(s) = self.peek() {
            if s == name {
                self.bump();
                return true;
            }
        }
        false
    }
    fn expect_ident(&mut self) -> Result<String, String> {
        let line = self.peek_line();
        if let Tok::Ident(s) = self.peek().clone() {
            self.bump();
            Ok(s)
        } else {
            Err(format!(
                "expected identifier at line {line}, got {:?}",
                self.peek()
            ))
        }
    }

    // ---- Expression parser (Pratt-style) ----

    fn parse_expr(&mut self) -> Result<Expr, String> {
        self.parse_ternary()
    }

    fn parse_ternary(&mut self) -> Result<Expr, String> {
        let cond = self.parse_or()?;
        if self.eat_punct("?") {
            let then_branch = self.parse_ternary()?;
            self.expect_punct(":")?;
            let else_branch = self.parse_ternary()?;
            return Ok(Expr::Ternary(
                Box::new(cond),
                Box::new(then_branch),
                Box::new(else_branch),
            ));
        }
        Ok(cond)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_and()?;
        while let Tok::Punct(p) = self.peek() {
            if p == "||" {
                self.bump();
                let rhs = self.parse_and()?;
                lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_bitor()?;
        while let Tok::Punct(p) = self.peek() {
            if p == "&&" {
                self.bump();
                let rhs = self.parse_bitor()?;
                lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn parse_bitor(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_bitxor()?;
        while let Tok::Punct(p) = self.peek() {
            if p == "|" {
                self.bump();
                let rhs = self.parse_bitxor()?;
                lhs = Expr::Binary(BinOp::BitOr, Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn parse_bitxor(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_bitand()?;
        while let Tok::Punct(p) = self.peek() {
            if p == "^" {
                self.bump();
                let rhs = self.parse_bitand()?;
                lhs = Expr::Binary(BinOp::BitXor, Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn parse_bitand(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_eq()?;
        while let Tok::Punct(p) = self.peek() {
            if p == "&" {
                self.bump();
                let rhs = self.parse_eq()?;
                lhs = Expr::Binary(BinOp::BitAnd, Box::new(lhs), Box::new(rhs));
            } else {
                break;
            }
        }
        Ok(lhs)
    }
    fn parse_eq(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_rel()?;
        while let Tok::Punct(p) = self.peek() {
            let op = match p.as_str() {
                "==" => BinOp::Eq,
                "!=" => BinOp::Ne,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_rel()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_rel(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_shift()?;
        while let Tok::Punct(p) = self.peek() {
            let op = match p.as_str() {
                "<" => BinOp::Lt,
                "<=" => BinOp::Le,
                ">" => BinOp::Gt,
                ">=" => BinOp::Ge,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_shift()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_shift(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_add()?;
        while let Tok::Punct(p) = self.peek() {
            let op = match p.as_str() {
                "<<" => BinOp::Shl,
                ">>" => BinOp::Shr,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_add()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_add(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_mul()?;
        while let Tok::Punct(p) = self.peek() {
            let op = match p.as_str() {
                "+" => BinOp::Add,
                "-" => BinOp::Sub,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_mul()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_mul(&mut self) -> Result<Expr, String> {
        let mut lhs = self.parse_unary()?;
        while let Tok::Punct(p) = self.peek() {
            let op = match p.as_str() {
                "*" => BinOp::Mul,
                "/" => BinOp::Div,
                "%" => BinOp::Mod,
                _ => break,
            };
            self.bump();
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
    fn parse_unary(&mut self) -> Result<Expr, String> {
        if let Tok::Punct(p) = self.peek().clone() {
            if p == "-" {
                self.bump();
                let inner = self.parse_unary()?;
                return Ok(Expr::Unary(UnaryOp::Neg, Box::new(inner)));
            }
            if p == "!" {
                self.bump();
                let inner = self.parse_unary()?;
                return Ok(Expr::Unary(UnaryOp::Not, Box::new(inner)));
            }
            if p == "+" {
                self.bump();
                return self.parse_unary();
            }
        }
        self.parse_postfix()
    }
    fn parse_postfix(&mut self) -> Result<Expr, String> {
        let mut e = self.parse_primary()?;
        loop {
            if self.eat_punct(".") {
                let name = self.expect_ident()?;
                e = Expr::Member(Box::new(e), name);
            } else if self.eat_punct("[") {
                let idx = self.parse_expr()?;
                self.expect_punct("]")?;
                e = Expr::Index(Box::new(e), Box::new(idx));
            } else {
                break;
            }
        }
        Ok(e)
    }
    fn parse_primary(&mut self) -> Result<Expr, String> {
        match self.peek().clone() {
            Tok::Int(s) => {
                self.bump();
                let n = s.parse::<i128>().unwrap_or(0);
                Ok(Expr::Int(n.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64))
            }
            Tok::Ident(name) => {
                self.bump();
                // Function call?
                if matches!(self.peek(), Tok::Punct(p) if p == "(") {
                    self.bump(); // (
                    let mut args = Vec::new();
                    if !matches!(self.peek(), Tok::Punct(p) if p == ")") {
                        loop {
                            args.push(self.parse_expr()?);
                            if !self.eat_punct(",") {
                                break;
                            }
                        }
                    }
                    self.expect_punct(")")?;
                    return Ok(Expr::Call(name, args));
                }
                Ok(Expr::Ident(name))
            }
            Tok::Punct(p) if p == "(" => {
                self.bump();
                let e = self.parse_expr()?;
                self.expect_punct(")")?;
                Ok(Expr::Paren(Box::new(e)))
            }
            t => Err(format!(
                "unexpected token {:?} at line {}",
                t,
                self.peek_line()
            )),
        }
    }

    // ---- Statement parser ----

    fn parse_block(&mut self) -> Result<Vec<Stmt>, String> {
        self.expect_punct("{")?;
        let mut stmts = Vec::new();
        while !matches!(self.peek(), Tok::Punct(p) if p == "}") && !matches!(self.peek(), Tok::Eof)
        {
            stmts.push(self.parse_stmt()?);
        }
        self.expect_punct("}")?;
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Stmt, String> {
        let line = self.peek_line();
        // var declaration
        if self.eat_ident("var") {
            let name = self.expect_ident()?;
            let init = if self.eat_punct("=") {
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.eat_punct(";");
            return Ok(Stmt::VarDecl { line, name, init });
        }
        // bus-typed input declaration (Circom 2.2+):
        //   `input BusName() var;`
        // Recognised as a separate statement so the structured evaluator
        // can seed the variable as a Component-shaped value (matching
        // how `comp.signal` reads resolve via `Expr::Member`) and so the
        // tracer can surface the parameter as a `ValueRecord::Struct`
        // arg on the template's call_entry.
        //
        // We only consume the tokens when the *exact* `Ident "input"`,
        // `Ident TYPE`, `Punct "("`, `Punct ")"`, `Ident NAME`, `Punct ";"`
        // sequence is present; on any deviation we fall through and let
        // the existing parser paths handle it (so we don't accidentally
        // swallow `input` used as a regular identifier in pre-2.2 code).
        if let Tok::Ident(s) = self.peek() {
            if s == "input" {
                let saved_pos = self.pos;
                self.bump(); // input
                if let Tok::Ident(bus_type) = self.peek().clone() {
                    self.bump(); // BusName
                    if matches!(self.peek(), Tok::Punct(p) if p == "(") && {
                        // Peek one ahead manually to confirm `()` (no args).
                        let next = self.toks.get(self.pos + 1).map(|t| t.tok.clone());
                        matches!(next, Some(Tok::Punct(ref q)) if q == ")")
                    } {
                        self.bump(); // (
                        self.bump(); // )
                        if let Tok::Ident(var_name) = self.peek().clone() {
                            self.bump(); // var name
                            self.eat_punct(";");
                            return Ok(Stmt::InputBusDecl {
                                line,
                                name: var_name,
                                bus_type,
                            });
                        }
                    }
                }
                // Roll back — the token sequence didn't match the
                // bus-input shape, so let the generic expr-stmt fallback
                // handle whatever this is.
                self.pos = saved_pos;
            }
        }
        // signal declaration
        if let Tok::Ident(s) = self.peek() {
            if s == "signal" {
                self.bump(); // signal
                let kind = if self.eat_ident("input") {
                    SignalKind::Input
                } else if self.eat_ident("output") {
                    SignalKind::Output
                } else {
                    SignalKind::Intermediate
                };
                // Optional Circom 2.1+ signal tag block:
                // `signal input {tag} a;` or
                // `signal input {tag=value, other=expr} a;`.  Skip the
                // entire `{ ... }` block — the tracer surfaces tags via
                // its own source-level scan in `find_signal_tags`.
                if self.eat_punct("{") {
                    while !matches!(self.peek(), Tok::Punct(p) if p == "}")
                        && !matches!(self.peek(), Tok::Eof)
                    {
                        self.bump();
                    }
                    self.eat_punct("}");
                }
                let name = self.expect_ident()?;
                let mut dims = Vec::new();
                while self.eat_punct("[") {
                    dims.push(self.parse_expr()?);
                    self.expect_punct("]")?;
                }
                self.eat_punct(";");
                return Ok(Stmt::SignalDecl {
                    line,
                    name,
                    kind,
                    dims,
                });
            }
        }
        // component declaration: either a scalar
        //   `component name = Template(args);`
        // or an array
        //   `component name[N];` (with per-element instantiation
        //   `name[i] = Template(args);` lifted into Stmt::Assign or
        //   Stmt::ComponentArrayAssign by the assignment parser
        //   below).
        if self.eat_ident("component") {
            let name = self.expect_ident()?;
            // Component-array declaration (no `=` follows; instead one
            // or more `[expr]` index dimensions).
            if matches!(self.peek(), Tok::Punct(p) if p == "[") {
                let mut dims = Vec::new();
                while self.eat_punct("[") {
                    dims.push(self.parse_expr()?);
                    self.expect_punct("]")?;
                }
                self.eat_punct(";");
                return Ok(Stmt::ComponentArrayDecl { line, name, dims });
            }
            self.expect_punct("=")?;
            let template = self.expect_ident()?;
            self.expect_punct("(")?;
            let mut args = Vec::new();
            if !matches!(self.peek(), Tok::Punct(p) if p == ")") {
                loop {
                    args.push(self.parse_expr()?);
                    if !self.eat_punct(",") {
                        break;
                    }
                }
            }
            self.expect_punct(")")?;
            self.eat_punct(";");
            return Ok(Stmt::ComponentDecl {
                line,
                name,
                template,
                args,
            });
        }
        // if
        if self.eat_ident("if") {
            self.expect_punct("(")?;
            let cond = self.parse_expr()?;
            self.expect_punct(")")?;
            let then_block = if matches!(self.peek(), Tok::Punct(p) if p == "{") {
                self.parse_block()?
            } else {
                vec![self.parse_stmt()?]
            };
            let else_block = if self.eat_ident("else") {
                if matches!(self.peek(), Tok::Punct(p) if p == "{") {
                    self.parse_block()?
                } else {
                    vec![self.parse_stmt()?]
                }
            } else {
                Vec::new()
            };
            return Ok(Stmt::If {
                line,
                cond,
                then_block,
                else_block,
            });
        }
        // for
        if self.eat_ident("for") {
            self.expect_punct("(")?;
            let init = self.parse_stmt()?;
            let cond = self.parse_expr()?;
            self.expect_punct(";")?;
            // The update is a single statement-shaped clause without a
            // trailing `;`, e.g. `i++` or `i = i + 1`.  Parse it
            // manually so we don't consume past the `)`.
            let update = self.parse_for_update()?;
            self.expect_punct(")")?;
            let body = if matches!(self.peek(), Tok::Punct(p) if p == "{") {
                self.parse_block()?
            } else {
                vec![self.parse_stmt()?]
            };
            return Ok(Stmt::For {
                line,
                init: Box::new(init),
                cond,
                update: Box::new(update),
                body,
            });
        }
        // return (rare in template bodies but supported in function defs)
        if self.eat_ident("return") {
            let value = if !matches!(self.peek(), Tok::Punct(p) if p == ";") {
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.eat_punct(";");
            return Ok(Stmt::Return { line, value });
        }
        // expression-led statement: lhs followed by an assignment / constraint operator.
        let lhs = self.parse_expr()?;
        let line_of_op = self.peek_line();
        let stmt = if self.eat_punct("<==") {
            let rhs = self.parse_expr()?;
            self.eat_punct(";");
            Stmt::Assign {
                line: line_of_op.min(line),
                op: AssignOp::SignalAssignConstrain,
                lhs,
                rhs,
            }
        } else if self.eat_punct("<--") {
            let rhs = self.parse_expr()?;
            self.eat_punct(";");
            Stmt::Assign {
                line: line_of_op.min(line),
                op: AssignOp::SignalAssign,
                lhs,
                rhs,
            }
        } else if self.eat_punct("===") {
            let rhs = self.parse_expr()?;
            self.eat_punct(";");
            Stmt::Constraint {
                line: line_of_op.min(line),
                lhs,
                rhs,
            }
        } else if self.eat_punct("=") {
            let rhs = self.parse_expr()?;
            self.eat_punct(";");
            // Recognise the component-array element-instantiation
            // pattern `name[i] = Template(args);` and lift it to a
            // dedicated statement so the structured evaluator can wire
            // it into the per-element call frame for that slot.
            if let (Expr::Index(box_name, box_idx), Expr::Call(tmpl, args)) = (&lhs, &rhs) {
                if let Expr::Ident(arr_name) = box_name.as_ref() {
                    return Ok(Stmt::ComponentArrayAssign {
                        line,
                        name: arr_name.clone(),
                        index: (**box_idx).clone(),
                        template: tmpl.clone(),
                        args: args.clone(),
                    });
                }
            }
            Stmt::Assign {
                line,
                op: AssignOp::VarAssign,
                lhs,
                rhs,
            }
        } else if let Tok::Punct(p) = self.peek().clone() {
            if p == "++" {
                self.bump();
                self.eat_punct(";");
                // Model `i++` as `i = i + 1`.
                let rhs = Expr::Binary(BinOp::Add, Box::new(lhs.clone()), Box::new(Expr::Int(1)));
                Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs,
                }
            } else if p == "--" {
                self.bump();
                self.eat_punct(";");
                let rhs = Expr::Binary(BinOp::Sub, Box::new(lhs.clone()), Box::new(Expr::Int(1)));
                Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs,
                }
            } else if p == "+=" || p == "-=" || p == "*=" || p == "/=" {
                let op_kind = match p.as_str() {
                    "+=" => BinOp::Add,
                    "-=" => BinOp::Sub,
                    "*=" => BinOp::Mul,
                    _ => BinOp::Div,
                };
                self.bump();
                let rhs = self.parse_expr()?;
                self.eat_punct(";");
                let new_rhs = Expr::Binary(op_kind, Box::new(lhs.clone()), Box::new(rhs));
                Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs: new_rhs,
                }
            } else {
                self.eat_punct(";");
                Stmt::ExprStmt { line, expr: lhs }
            }
        } else {
            self.eat_punct(";");
            Stmt::ExprStmt { line, expr: lhs }
        };
        Ok(stmt)
    }

    fn parse_for_update(&mut self) -> Result<Stmt, String> {
        let line = self.peek_line();
        let lhs = self.parse_expr()?;
        if let Tok::Punct(p) = self.peek().clone() {
            if p == "++" {
                self.bump();
                let rhs = Expr::Binary(BinOp::Add, Box::new(lhs.clone()), Box::new(Expr::Int(1)));
                return Ok(Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs,
                });
            }
            if p == "--" {
                self.bump();
                let rhs = Expr::Binary(BinOp::Sub, Box::new(lhs.clone()), Box::new(Expr::Int(1)));
                return Ok(Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs,
                });
            }
            if p == "=" {
                self.bump();
                let rhs = self.parse_expr()?;
                return Ok(Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs,
                });
            }
            if p == "+=" || p == "-=" || p == "*=" || p == "/=" {
                let op_kind = match p.as_str() {
                    "+=" => BinOp::Add,
                    "-=" => BinOp::Sub,
                    "*=" => BinOp::Mul,
                    _ => BinOp::Div,
                };
                self.bump();
                let rhs = self.parse_expr()?;
                let new_rhs = Expr::Binary(op_kind, Box::new(lhs.clone()), Box::new(rhs));
                return Ok(Stmt::Assign {
                    line,
                    op: AssignOp::VarAssign,
                    lhs,
                    rhs: new_rhs,
                });
            }
        }
        Ok(Stmt::ExprStmt { line, expr: lhs })
    }

    fn parse_function(&mut self) -> Result<Function, String> {
        // assumes `function` keyword already consumed
        let line = self.peek_line();
        let name = self.expect_ident()?;
        self.expect_punct("(")?;
        let mut params = Vec::new();
        if !matches!(self.peek(), Tok::Punct(p) if p == ")") {
            loop {
                params.push(self.expect_ident()?);
                if !self.eat_punct(",") {
                    break;
                }
            }
        }
        self.expect_punct(")")?;
        let body = self.parse_block()?;
        Ok(Function {
            name,
            line,
            params,
            body,
        })
    }

    fn parse_template(&mut self) -> Result<Template, String> {
        // assumes `template` keyword already consumed
        let line = self.peek_line();
        // `template custom NAME` (Circom 2.0.6+ pragma custom_templates)
        // and `template parallel NAME` (Circom 2.0+ parallel modifier)
        // — skip either modifier (or both) so the rest of the parser
        // still sees `NAME(...)`.  The tracer surfaces the `custom`
        // flag via `find_custom_templates` and the `parallel` flag via
        // `find_parallel_templates` (independent source-level scans).
        loop {
            match self.peek() {
                Tok::Ident(n) if n == "custom" || n == "parallel" => {
                    self.bump();
                }
                _ => break,
            }
        }
        let name = self.expect_ident()?;
        self.expect_punct("(")?;
        let mut generic_params = Vec::new();
        if !matches!(self.peek(), Tok::Punct(p) if p == ")") {
            loop {
                generic_params.push(self.expect_ident()?);
                if !self.eat_punct(",") {
                    break;
                }
            }
        }
        self.expect_punct(")")?;
        let body = self.parse_block()?;
        let input_signals: Vec<String> = body
            .iter()
            .filter_map(|s| match s {
                Stmt::SignalDecl {
                    name,
                    kind: SignalKind::Input,
                    ..
                } => Some(name.clone()),
                _ => None,
            })
            .collect();
        let input_buses: Vec<(String, String)> = body
            .iter()
            .filter_map(|s| match s {
                Stmt::InputBusDecl { name, bus_type, .. } => Some((name.clone(), bus_type.clone())),
                _ => None,
            })
            .collect();
        Ok(Template {
            name,
            line,
            generic_params,
            body,
            input_signals,
            input_buses,
        })
    }
}

/// Parse a Circom source file into its templates.  Skips top-level
/// `pragma`, top-level `include`, top-level `function`, and the
/// `component main = ...` declaration (those are handled separately).
pub fn parse_templates(src: &str) -> Vec<Template> {
    parse_program(src).0
}

/// Parse a Circom source file into its templates AND functions.
/// Returns `(templates, functions)` so callers can register both in
/// the recorder's function table and resolve `Expr::Call(f, args)`
/// references inside template / function bodies.
pub fn parse_program(src: &str) -> (Vec<Template>, Vec<Function>) {
    let (templates, functions, _) = parse_program_with_buses(src);
    (templates, functions)
}

/// Like `parse_program`, but also returns the `bus` definitions
/// (Circom 2.2+ composite types).  Kept as a separate entry point so
/// the existing `parse_program` callers don't have to thread the
/// (currently empty for ~99% of fixtures) bus list through.
pub fn parse_program_with_buses(src: &str) -> (Vec<Template>, Vec<Function>, Vec<Bus>) {
    let toks = tokenize(src);
    let mut parser = Parser::new(toks);
    let mut templates = Vec::new();
    let mut functions = Vec::new();
    let mut buses = Vec::new();
    loop {
        match parser.peek().clone() {
            Tok::Eof => break,
            Tok::Ident(name) if name == "bus" => {
                let line = parser.peek_line();
                parser.bump(); // bus
                               // Bus name.
                let bus_name = match parser.peek().clone() {
                    Tok::Ident(n) => {
                        parser.bump();
                        n
                    }
                    _ => continue,
                };
                // Optional `()` — buses can declare generic params but
                // the recorder only models the no-arg form today.
                if matches!(parser.peek(), Tok::Punct(p) if p == "(") {
                    let mut depth = 0i32;
                    loop {
                        match parser.peek().clone() {
                            Tok::Punct(p) if p == "(" => {
                                depth += 1;
                                parser.bump();
                            }
                            Tok::Punct(p) if p == ")" => {
                                depth -= 1;
                                parser.bump();
                                if depth <= 0 {
                                    break;
                                }
                            }
                            Tok::Eof => break,
                            _ => {
                                parser.bump();
                            }
                        }
                    }
                }
                // `{ signal X; signal Y; ... }` — collect each scalar
                // `signal NAME;` declaration as a field.  Anything more
                // complex (nested buses, array fields) is silently
                // skipped — the recorder doesn't model those today.
                let mut fields = Vec::new();
                if matches!(parser.peek(), Tok::Punct(p) if p == "{") {
                    parser.bump(); // {
                    let mut depth = 1i32;
                    while depth > 0 {
                        match parser.peek().clone() {
                            Tok::Eof => break,
                            Tok::Punct(p) if p == "{" => {
                                depth += 1;
                                parser.bump();
                            }
                            Tok::Punct(p) if p == "}" => {
                                depth -= 1;
                                parser.bump();
                            }
                            Tok::Ident(n) if n == "signal" && depth == 1 => {
                                parser.bump(); // signal
                                if let Tok::Ident(field_name) = parser.peek().clone() {
                                    parser.bump();
                                    fields.push(field_name);
                                    // Skip any trailing `[dim]` or other
                                    // tokens until `;`.
                                    while !matches!(parser.peek(), Tok::Punct(p) if p == ";")
                                        && !matches!(parser.peek(), Tok::Eof)
                                    {
                                        parser.bump();
                                    }
                                    parser.eat_punct(";");
                                }
                            }
                            _ => {
                                parser.bump();
                            }
                        }
                    }
                }
                buses.push(Bus {
                    name: bus_name,
                    line,
                    fields,
                });
            }
            Tok::Ident(name) if name == "pragma" => {
                // Eat until ';'
                while !matches!(parser.peek(), Tok::Punct(p) if p == ";")
                    && !matches!(parser.peek(), Tok::Eof)
                {
                    parser.bump();
                }
                parser.eat_punct(";");
            }
            Tok::Ident(name) if name == "include" => {
                while !matches!(parser.peek(), Tok::Punct(p) if p == ";")
                    && !matches!(parser.peek(), Tok::Eof)
                {
                    parser.bump();
                }
                parser.eat_punct(";");
            }
            Tok::Ident(name) if name == "template" => {
                parser.bump();
                match parser.parse_template() {
                    Ok(t) => templates.push(t),
                    Err(e) => {
                        eprintln!("circom evaluator: template parse error: {e}");
                        // skip to next `template` keyword to continue
                        while !matches!(parser.peek(), Tok::Eof) {
                            if let Tok::Ident(n) = parser.peek() {
                                if n == "template" || n == "function" || n == "component" {
                                    break;
                                }
                            }
                            parser.bump();
                        }
                    }
                }
            }
            Tok::Ident(name) if name == "function" => {
                parser.bump();
                match parser.parse_function() {
                    Ok(f) => functions.push(f),
                    Err(e) => {
                        eprintln!("circom evaluator: function parse error: {e}");
                        // skip to next top-level keyword to continue
                        while !matches!(parser.peek(), Tok::Eof) {
                            if let Tok::Ident(n) = parser.peek() {
                                if n == "template" || n == "function" || n == "component" {
                                    break;
                                }
                            }
                            parser.bump();
                        }
                    }
                }
            }
            Tok::Ident(name) if name == "component" => {
                // Top-level `component main = ...` — eat to `;`.
                while !matches!(parser.peek(), Tok::Punct(p) if p == ";")
                    && !matches!(parser.peek(), Tok::Eof)
                {
                    parser.bump();
                }
                parser.eat_punct(";");
            }
            _ => {
                parser.bump();
            }
        }
    }
    (templates, functions, buses)
}

// ---------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------

/// A computed value carried in the evaluation environment.
#[derive(Debug, Clone)]
pub enum Value {
    Int(i64),
    /// A signal that has been declared but not yet assigned.  Default
    /// value is 0 (matches the witness behaviour for unconstrained
    /// inputs).
    UnsetSignal,
    /// A sub-component instance with a (signal-name -> value) map for
    /// its outputs.  Reading `comp.signal` looks up the inner map.
    Component {
        template: String,
        signals: HashMap<String, i64>,
    },
    /// An array — used for `signal x[N]` declarations.
    Array(Vec<Value>),
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            Value::UnsetSignal => Some(0),
            _ => None,
        }
    }
}

/// The recorded effect of evaluating a template.
#[derive(Debug, Clone)]
pub struct EvalEvent {
    pub line: u32,
    pub kind: EvalEventKind,
}

#[derive(Debug, Clone)]
pub enum EvalEventKind {
    /// A bare step at this line (no variable update).
    Step,
    /// A signal / variable update.  `name` is the printable name
    /// (e.g. `total`, `add5.x`, `inner.out`); `value` is the i64.
    /// `is_bool` is true when the signal is constrained to {0,1} via
    /// the canonical `signal * (signal - 1) === 0` Boolean
    /// constraint — the recorder surfaces such variables as
    /// `ValueRecord::Bool` rather than as generic `ValueRecord::Int`.
    Variable {
        name: String,
        value: i64,
        is_bool: bool,
    },
    /// Component instantiation — recurse into the named template.
    /// `args` contains numeric template arguments captured from the
    /// instantiation site (e.g. `Sub(N)` with N=4 -> `vec![4]`).
    ComponentEnter {
        comp_name: String,
        template: String,
        args: Vec<i64>,
    },
    /// Wire a value into a sub-component's input signal.  Emitted as
    /// part of evaluating `comp.in <== expr;` so the recorder can
    /// surface the wire as a step + variable event under the parent
    /// frame, then propagate the value into the sub-component's input
    /// env.
    Wire {
        comp_name: String,
        signal_name: String,
        value: i64,
    },
    /// A `===` constraint that the structured evaluator detects does
    /// NOT hold under the current evaluation env (LHS != RHS).  The
    /// recorder surfaces this as a tagged constraint-violation
    /// special event so debugger consumers can flag the offending
    /// line without waiting for the witness calculator to fail.
    /// Used by the range-proof fixture to detect out-of-range inputs
    /// at evaluator time.
    ConstraintViolation {
        lhs_value: i64,
        rhs_value: i64,
        text: String,
    },
}

/// Evaluation context for a single template.
pub struct EvalContext<'a> {
    pub templates: &'a HashMap<String, Template>,
    /// Input-signal values passed in by the caller (already wired via
    /// the parent's `comp.in <== expr;` sites).
    pub input_signals: HashMap<String, i64>,
    /// Numeric template arguments (e.g. `Sub(N)` with N bound to 4).
    pub generic_args: Vec<i64>,
    /// Compile-time `function` definitions, used to resolve
    /// `Expr::Call(name, args)` references inside template / function
    /// bodies.  Empty when the program has no functions.
    pub functions: &'a HashMap<String, Function>,
    /// Bus type definitions keyed by bus name.  Looked up when the
    /// evaluator hits a `Stmt::InputBusDecl` so it can seed the bus
    /// variable as a `Value::Component { template: <bus_name>, signals }`
    /// with each declared field defaulted to 0.  Field reads (`p.x`)
    /// then resolve through the existing `Expr::Member` ->
    /// `Value::Component` lookup path.  Empty when the program has no
    /// bus definitions (the common case for pre-2.2 fixtures).
    pub buses: &'a HashMap<String, Bus>,
}

/// Evaluation result for a template body — both the events produced
/// and the final output-signal values that the parent can read back
/// via `comp.signal`.
pub struct EvalResult {
    pub events: Vec<EvalEvent>,
    pub outputs: HashMap<String, i64>,
}

/// Scan a template body for `signal * (signal - 1) === 0` constraint
/// patterns and return the set of signal names so constrained.  This
/// is the canonical Boolean constraint used by circomlib's
/// comparator / IsZero / IsEqual templates — the recorder surfaces
/// such signals as `ValueRecord::Bool` rather than as generic
/// `ValueRecord::Int`.  Recognises both `s * (s - 1) === 0` and the
/// commuted form `(s - 1) * s === 0`.
pub fn collect_boolean_signals(stmts: &[Stmt]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    walk_for_boolean(stmts, &mut out);
    out
}

fn walk_for_boolean(stmts: &[Stmt], out: &mut std::collections::HashSet<String>) {
    for s in stmts {
        match s {
            Stmt::Constraint { lhs, rhs, .. } => {
                // Recognise `signal * (signal - 1) === 0` (or the
                // commuted forms).  rhs must be the literal `0`.
                let rhs_zero = matches!(rhs, Expr::Int(0))
                    || matches!(rhs, Expr::Paren(b) if matches!(b.as_ref(), Expr::Int(0)));
                if !rhs_zero {
                    continue;
                }
                if let Some(name) = bool_signal_from_mul_minus_one(lhs) {
                    out.insert(name);
                }
            }
            Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                walk_for_boolean(then_block, out);
                walk_for_boolean(else_block, out);
            }
            Stmt::For { body, .. } => {
                walk_for_boolean(body, out);
            }
            _ => {}
        }
    }
}

/// Walk a `<==` RHS expression and, if it directly reads back a
/// sub-component's named output (`comp.out`, optionally wrapped in
/// `Paren`), return the *last segment* of the read so the caller can
/// look it up in the bool-signals set.  This is what propagates the
/// Bool-ness from a sub-component's output through a parent's wire
/// site `parent_out <== sub.boolsig;`.
fn rhs_bool_signal_name(rhs: &Expr) -> Option<String> {
    match rhs {
        Expr::Member(_, name) => Some(name.clone()),
        Expr::Paren(b) => rhs_bool_signal_name(b),
        _ => None,
    }
}

/// Match `s * (s - 1)` or `(s - 1) * s` (with optional parens around
/// either operand) and return `Some(s)` for the inner identifier.
fn bool_signal_from_mul_minus_one(e: &Expr) -> Option<String> {
    let strip = |x: &Expr| -> Expr {
        match x {
            Expr::Paren(b) => (**b).clone(),
            other => other.clone(),
        }
    };
    if let Expr::Binary(BinOp::Mul, l, r) = e {
        let l = strip(l);
        let r = strip(r);
        // s * (s - 1) ?
        if let (Expr::Ident(s_l), Expr::Binary(BinOp::Sub, sub_l, sub_r)) = (&l, &r) {
            if let (Expr::Ident(s_sub), Expr::Int(1)) = (sub_l.as_ref(), sub_r.as_ref()) {
                if s_l == s_sub {
                    return Some(s_l.clone());
                }
            }
        }
        // (s - 1) * s ?
        if let (Expr::Binary(BinOp::Sub, sub_l, sub_r), Expr::Ident(s_r)) = (&l, &r) {
            if let (Expr::Ident(s_sub), Expr::Int(1)) = (sub_l.as_ref(), sub_r.as_ref()) {
                if s_r == s_sub {
                    return Some(s_r.clone());
                }
            }
        }
    }
    None
}

/// Evaluate a template body from start to finish, producing events
/// and a map of output-signal values.
///
/// Sub-component evaluations are folded into the env up-front via a
/// pre-pass that walks the body collecting `<==`/`<--` wires to each
/// declared component, then recursively evaluates the sub-template
/// with those inputs.  The recursive evaluation's outputs are stored
/// in the parent's `Value::Component { signals }` slot so subsequent
/// reads like `sub.out` resolve to concrete integers — which is what
/// the Circom witness calculator does at runtime.  Without this fold,
/// `sub.out` reads back as `None` (the wires only populate inputs,
/// not outputs), which is the bug that made every recorded
/// intermediate output value surface as 0.
pub fn evaluate_template(template: &Template, ctx: &EvalContext) -> EvalResult {
    // Install the function table for the duration of this evaluation
    // so `Expr::Call(name, args)` inside `<==` RHS / `var` inits
    // resolves against the program's `function` definitions.  The
    // guard pops the binding when the function returns.
    let _fns_guard = FnsGuard::install(ctx.functions);

    // Discover Boolean-constrained signals across **every** template
    // in the program so a Variable event whose LHS reads back a
    // Bool-typed value (e.g. `nz_zero <== nz_a.out;` where IsNonZero
    // declares `out * (out - 1) === 0`) emits a `Bool` ValueRecord
    // rather than a generic `Int`.  This is the canonical Circom
    // pattern used by IsZero / IsEqual / LessThan comparators in
    // circomlib.  We compute the set across all templates (not just
    // the current one) because the parent frame's `<==` line surfaces
    // the value with a name that's distinct from any signal in the
    // current template body — the bool flavour is carried by the
    // sub-component's output declaration, not the parent's wire site.
    let mut bool_signals = collect_boolean_signals(&template.body);
    for t in ctx.templates.values() {
        for n in collect_boolean_signals(&t.body) {
            bool_signals.insert(n);
        }
    }

    let mut env: HashMap<String, Value> = HashMap::new();

    // Bind generic numeric parameters.
    for (i, name) in template.generic_params.iter().enumerate() {
        let v = ctx.generic_args.get(i).copied().unwrap_or(0);
        env.insert(name.clone(), Value::Int(v));
    }

    // Pre-seed input signal values.
    for (name, value) in &ctx.input_signals {
        env.insert(name.clone(), Value::Int(*value));
    }

    // Pre-seed bus-typed inputs as `Value::Component`-shaped slots so
    // member reads (`p.x`, `p.y`) resolve through the existing
    // `Expr::Member` -> `Value::Component` lookup path.  Each declared
    // field defaults to 0 (matching the witness calculator's default
    // for unset inputs — the recorder doesn't have a JSON-input wiring
    // mechanism today, so every bus field starts at 0 just like every
    // scalar `signal input` does).  Bus fields whose type isn't in
    // `ctx.buses` (e.g. forward-declared, in an included file the
    // recorder didn't scan, or the program forgot the `bus` keyword)
    // are seeded as empty Components so reads still return None
    // gracefully rather than panicking.
    for stmt in &template.body {
        if let Stmt::InputBusDecl { name, bus_type, .. } = stmt {
            let mut signals: HashMap<String, i64> = HashMap::new();
            if let Some(bus) = ctx.buses.get(bus_type) {
                for field in &bus.fields {
                    signals.insert(field.clone(), 0);
                }
            }
            env.insert(
                name.clone(),
                Value::Component {
                    template: bus_type.clone(),
                    signals,
                },
            );
        }
    }

    // ------------------------------------------------------------------
    // Pre-pass: walk the body in source order.  When a sub-component
    // declaration appears, record it.  When a wire to a sub-component
    // appears, evaluate the RHS *now* against the current env (which
    // already contains every previously-declared / -evaluated
    // sub-component's outputs).  Once we reach the end of the body —
    // or the start of the next sibling block that "uses" a
    // sub-component's output — eagerly evaluate any pending
    // sub-components so subsequent reads of `comp.signal` resolve to
    // concrete integers.
    //
    // Circom's "wires before use" rule guarantees that by the time
    // the parent body references `compX.signal`, every wire targeting
    // `compX.in` has already been visited.  We trigger evaluation
    // lazily on first read of any output of a component (see
    // `eval_expr` for `Expr::Member`).
    // ------------------------------------------------------------------
    let mut prepass_env = env.clone();
    let mut comp_decls: Vec<(String, String, Vec<i64>)> = Vec::new();
    let mut comp_wires_exprs: HashMap<String, Vec<(String, Expr)>> = HashMap::new();
    collect_components_with_wires(
        &template.body,
        &mut prepass_env,
        &mut comp_decls,
        &mut comp_wires_exprs,
    );

    // Evaluate every sub-component in source-declaration order, with
    // wires re-evaluated against an env that already has every
    // previously-evaluated sibling's outputs available.  Circom's
    // ordering rule ("a signal must be assigned before it is used")
    // guarantees source order is a valid evaluation order for this
    // dependency graph.
    for (comp_name, template_name, args) in &comp_decls {
        let Some(child_template) = ctx.templates.get(template_name) else {
            env.insert(
                comp_name.clone(),
                Value::Component {
                    template: template_name.clone(),
                    signals: HashMap::new(),
                },
            );
            continue;
        };
        let mut inputs: HashMap<String, i64> = HashMap::new();
        if let Some(wires) = comp_wires_exprs.get(comp_name) {
            for (signal, expr) in wires {
                let v = eval_expr(expr, &env).and_then(|v| v.as_int()).unwrap_or(0);
                inputs.insert(signal.clone(), v);
            }
        }
        let child_ctx = EvalContext {
            templates: ctx.templates,
            input_signals: inputs.clone(),
            generic_args: args.clone(),
            functions: ctx.functions,
            buses: ctx.buses,
        };
        let child_result = evaluate_template(child_template, &child_ctx);
        let mut signals = inputs;
        for (k, v) in child_result.outputs {
            signals.insert(k, v);
        }
        env.insert(
            comp_name.clone(),
            Value::Component {
                template: template_name.clone(),
                signals,
            },
        );
    }

    // ------------------------------------------------------------------
    // Second pass: produce the user-visible event stream.  Sub-component
    // outputs are already cached in the env, so wire RHS expressions
    // like `mul2.in <== add5.y` resolve correctly.
    // ------------------------------------------------------------------
    let mut events = Vec::new();
    eval_block(&template.body, &mut env, &mut events, ctx, &bool_signals);

    // Collect output-signal values from the env so the caller can
    // expose them via `comp.signal`.
    let mut outputs = HashMap::new();
    for stmt in &template.body {
        if let Stmt::SignalDecl {
            name,
            kind: SignalKind::Output,
            ..
        } = stmt
        {
            if let Some(v) = env.get(name).and_then(Value::as_int) {
                outputs.insert(name.clone(), v);
            } else {
                outputs.insert(name.clone(), 0);
            }
        }
    }

    EvalResult { events, outputs }
}

/// Pre-pass walker: collects sub-component declarations and their
/// wire expressions in source order.  Wires are stored as
/// unevaluated `Expr`s so the caller can evaluate each one *after*
/// all previously-declared siblings have already been recursively
/// evaluated — that's how a wire of the shape
/// `mul2.in <== add5.y` gets a non-zero value (the read of
/// `add5.y` needs add5's body to have been folded into the env
/// first).
fn collect_components_with_wires(
    stmts: &[Stmt],
    env: &mut HashMap<String, Value>,
    comp_decls: &mut Vec<(String, String, Vec<i64>)>,
    comp_wires: &mut HashMap<String, Vec<(String, Expr)>>,
) {
    for s in stmts {
        match s {
            Stmt::ComponentDecl {
                name,
                template,
                args,
                ..
            } => {
                let arg_vals: Vec<i64> = args
                    .iter()
                    .map(|e| eval_expr(e, env).and_then(|v| v.as_int()).unwrap_or(0))
                    .collect();
                comp_decls.push((name.clone(), template.clone(), arg_vals));
                env.insert(
                    name.clone(),
                    Value::Component {
                        template: template.clone(),
                        signals: HashMap::new(),
                    },
                );
            }
            Stmt::ComponentArrayDecl { name, dims, .. } => {
                // Pre-allocate the array slot with empty Component
                // values; each ComponentArrayAssign below will
                // populate one slot.  Only the first dimension is
                // used today.
                let n = dims
                    .first()
                    .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                    .unwrap_or(0) as usize;
                env.insert(
                    name.clone(),
                    Value::Array(
                        (0..n)
                            .map(|_| Value::Component {
                                template: String::new(),
                                signals: HashMap::new(),
                            })
                            .collect(),
                    ),
                );
            }
            Stmt::ComponentArrayAssign {
                name,
                index,
                template,
                args,
                ..
            } => {
                let idx = eval_expr(index, env).and_then(|v| v.as_int()).unwrap_or(0);
                let synthetic = format!("{name}[{idx}]");
                let arg_vals: Vec<i64> = args
                    .iter()
                    .map(|e| eval_expr(e, env).and_then(|v| v.as_int()).unwrap_or(0))
                    .collect();
                comp_decls.push((synthetic.clone(), template.clone(), arg_vals));
                env.insert(
                    synthetic,
                    Value::Component {
                        template: template.clone(),
                        signals: HashMap::new(),
                    },
                );
            }
            Stmt::Assign { lhs, rhs, op, .. } => {
                if matches!(op, AssignOp::SignalAssign | AssignOp::SignalAssignConstrain) {
                    if let Expr::Member(box_lhs, signal) = lhs {
                        // Wire to a scalar component: `comp.signal <== expr;`
                        if let Expr::Ident(comp_name) = box_lhs.as_ref() {
                            comp_wires
                                .entry(comp_name.clone())
                                .or_default()
                                .push((signal.clone(), rhs.clone()));
                            continue;
                        }
                        // Wire to a component-array element:
                        // `arr[i].signal <== expr;` — resolve the
                        // index against the current env so we route
                        // the wire to the right synthetic
                        // "arr[<idx>]" component slot.
                        if let Expr::Index(arr_box, idx_expr) = box_lhs.as_ref() {
                            if let Expr::Ident(arr_name) = arr_box.as_ref() {
                                let idx = eval_expr(idx_expr, env)
                                    .and_then(|v| v.as_int())
                                    .unwrap_or(0);
                                let synthetic = format!("{arr_name}[{idx}]");
                                comp_wires
                                    .entry(synthetic)
                                    .or_default()
                                    .push((signal.clone(), rhs.clone()));
                                continue;
                            }
                        }
                    }
                }
                let value = eval_expr(rhs, env).and_then(|v| v.as_int()).unwrap_or(0);
                apply_lvalue(lhs, value, env);
            }
            Stmt::VarDecl { name, init, .. } => {
                let val = init
                    .as_ref()
                    .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                    .unwrap_or(0);
                env.insert(name.clone(), Value::Int(val));
            }
            Stmt::SignalDecl { name, dims, .. } => {
                if dims.is_empty() {
                    if !env.contains_key(name) {
                        env.insert(name.clone(), Value::UnsetSignal);
                    }
                } else {
                    let n = dims
                        .first()
                        .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                        .unwrap_or(0) as usize;
                    env.insert(name.clone(), Value::Array(vec![Value::Int(0); n]));
                }
            }
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                let c = eval_expr(cond, env).and_then(|v| v.as_int()).unwrap_or(0);
                if c != 0 {
                    collect_components_with_wires(then_block, env, comp_decls, comp_wires);
                } else {
                    collect_components_with_wires(else_block, env, comp_decls, comp_wires);
                }
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
                ..
            } => {
                let mut init_evt = Vec::new();
                let empty_fns = HashMap::new();
                let empty_buses = HashMap::new();
                let empty_bool: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let empty_ctx = EvalContext {
                    templates: &HashMap::new(),
                    input_signals: HashMap::new(),
                    generic_args: Vec::new(),
                    functions: &empty_fns,
                    buses: &empty_buses,
                };
                eval_stmt(init, env, &mut init_evt, &empty_ctx, &empty_bool);
                let mut iterations = 0usize;
                while iterations < 10_000 {
                    let c = eval_expr(cond, env).and_then(|v| v.as_int()).unwrap_or(0);
                    if c == 0 {
                        break;
                    }
                    collect_components_with_wires(body, env, comp_decls, comp_wires);
                    let mut update_evt = Vec::new();
                    eval_stmt(update, env, &mut update_evt, &empty_ctx, &empty_bool);
                    iterations += 1;
                }
            }
            _ => {}
        }
    }
}

/// Pre-pass walker (legacy entry point): mirrors the second-pass
/// control flow but only surfaces sub-component declarations and the
/// wires that target them as already-evaluated integers.  Kept for
/// callers / tests that need a simple "collect everything I see"
/// view; the structured evaluator now drives sub-component
/// instantiation through `collect_components_with_wires`.
#[allow(dead_code, clippy::only_used_in_recursion)]
fn collect_components(
    stmts: &[Stmt],
    env: &mut HashMap<String, Value>,
    events: &mut Vec<EvalEvent>,
    comp_decls: &mut Vec<(String, String, Vec<i64>)>,
    comp_wires: &mut HashMap<String, HashMap<String, i64>>,
) {
    for s in stmts {
        match s {
            Stmt::ComponentDecl {
                name,
                template,
                args,
                ..
            } => {
                let arg_vals: Vec<i64> = args
                    .iter()
                    .map(|e| eval_expr(e, env).and_then(|v| v.as_int()).unwrap_or(0))
                    .collect();
                comp_decls.push((name.clone(), template.clone(), arg_vals));
                env.insert(
                    name.clone(),
                    Value::Component {
                        template: template.clone(),
                        signals: HashMap::new(),
                    },
                );
            }
            Stmt::Assign { lhs, rhs, op, .. } => {
                if matches!(op, AssignOp::SignalAssign | AssignOp::SignalAssignConstrain) {
                    if let Expr::Member(box_lhs, signal) = lhs {
                        if let Expr::Ident(comp_name) = box_lhs.as_ref() {
                            let value = eval_expr(rhs, env).and_then(|v| v.as_int()).unwrap_or(0);
                            comp_wires
                                .entry(comp_name.clone())
                                .or_default()
                                .insert(signal.clone(), value);
                            continue;
                        }
                    }
                }
                // Non-wire assignment — apply to env so subsequent
                // reads see the updated value.
                let value = eval_expr(rhs, env).and_then(|v| v.as_int()).unwrap_or(0);
                apply_lvalue(lhs, value, env);
            }
            Stmt::VarDecl { name, init, .. } => {
                let val = init
                    .as_ref()
                    .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                    .unwrap_or(0);
                env.insert(name.clone(), Value::Int(val));
            }
            Stmt::SignalDecl { name, dims, .. } => {
                if dims.is_empty() {
                    if !env.contains_key(name) {
                        env.insert(name.clone(), Value::UnsetSignal);
                    }
                } else {
                    let n = dims
                        .first()
                        .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                        .unwrap_or(0) as usize;
                    env.insert(name.clone(), Value::Array(vec![Value::Int(0); n]));
                }
            }
            Stmt::If {
                cond,
                then_block,
                else_block,
                ..
            } => {
                let c = eval_expr(cond, env).and_then(|v| v.as_int()).unwrap_or(0);
                if c != 0 {
                    collect_components(then_block, env, events, comp_decls, comp_wires);
                } else {
                    collect_components(else_block, env, events, comp_decls, comp_wires);
                }
            }
            Stmt::For {
                init,
                cond,
                update,
                body,
                ..
            } => {
                let mut init_evt = Vec::new();
                let empty_fns = HashMap::new();
                let empty_buses = HashMap::new();
                let empty_bool: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                eval_stmt(
                    init,
                    env,
                    &mut init_evt,
                    &EvalContext {
                        templates: &HashMap::new(),
                        input_signals: HashMap::new(),
                        generic_args: Vec::new(),
                        functions: &empty_fns,
                        buses: &empty_buses,
                    },
                    &empty_bool,
                );
                let mut iterations = 0usize;
                while iterations < 10_000 {
                    let c = eval_expr(cond, env).and_then(|v| v.as_int()).unwrap_or(0);
                    if c == 0 {
                        break;
                    }
                    collect_components(body, env, events, comp_decls, comp_wires);
                    let mut update_evt = Vec::new();
                    eval_stmt(
                        update,
                        env,
                        &mut update_evt,
                        &EvalContext {
                            templates: &HashMap::new(),
                            input_signals: HashMap::new(),
                            generic_args: Vec::new(),
                            functions: &empty_fns,
                            buses: &empty_buses,
                        },
                        &empty_bool,
                    );
                    iterations += 1;
                }
            }
            _ => {}
        }
    }
}

fn eval_block(
    stmts: &[Stmt],
    env: &mut HashMap<String, Value>,
    events: &mut Vec<EvalEvent>,
    ctx: &EvalContext,
    bool_signals: &std::collections::HashSet<String>,
) {
    for s in stmts {
        eval_stmt(s, env, events, ctx, bool_signals);
    }
}

fn eval_stmt(
    stmt: &Stmt,
    env: &mut HashMap<String, Value>,
    events: &mut Vec<EvalEvent>,
    ctx: &EvalContext,
    bool_signals: &std::collections::HashSet<String>,
) {
    match stmt {
        Stmt::VarDecl { line, name, init } => {
            let val = init
                .as_ref()
                .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                .unwrap_or(0);
            env.insert(name.clone(), Value::Int(val));
            // `var` declarations are compile-time scratch variables in
            // Circom — surfacing them as user-visible step variables
            // would pollute the trace (every for-loop induction
            // variable would show up as a recorded "value", contrary
            // to the Circom mental model where only `signal`s carry
            // values into the witness).  Emit a step-only event.
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
        }
        Stmt::InputBusDecl {
            line,
            name,
            bus_type,
        } => {
            // Bus-typed input declaration (Circom 2.2+):
            //   `input BusName() var;`
            // The value was pre-seeded into `env` by `evaluate_template`
            // before the body walk started (so wire RHS evaluations in
            // the prepass could read fields like `p.x`).  Re-seed
            // defensively here in case the eval_stmt path was reached
            // through a code path that bypassed the pre-seed (e.g. an
            // included template body) — the recorder treats the
            // duplicate insert as idempotent.
            if !env.contains_key(name) {
                let mut signals: HashMap<String, i64> = HashMap::new();
                if let Some(bus) = ctx.buses.get(bus_type) {
                    for field in &bus.fields {
                        signals.insert(field.clone(), 0);
                    }
                }
                env.insert(
                    name.clone(),
                    Value::Component {
                        template: bus_type.clone(),
                        signals,
                    },
                );
            }
            // Step-only event at the input-decl line: the user-visible
            // bus value surfaces as the call_entry arg (a
            // `ValueRecord::Struct`), not as a step Variable record —
            // mirroring how scalar input signal decls surface their
            // value at the declaration line via a separate path.
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
        }
        Stmt::SignalDecl {
            line,
            name,
            kind,
            dims,
        } => {
            // Step at the declaration line.  Initialise to UnsetSignal
            // so reads before assignment yield 0.  Inputs already in
            // the env (from ctx.input_signals) are kept.
            if dims.is_empty() {
                if !env.contains_key(name) {
                    env.insert(name.clone(), Value::UnsetSignal);
                }
                let val = env.get(name).and_then(Value::as_int).unwrap_or(0);
                // Inputs surface their value at the decl line; outputs/
                // intermediates surface 0 here and update later when
                // assigned.
                let display_val = if matches!(kind, SignalKind::Input) {
                    val
                } else {
                    // Emit only a Step (no var) for non-input decls so
                    // the variable event lands on the assignment line.
                    events.push(EvalEvent {
                        line: *line,
                        kind: EvalEventKind::Step,
                    });
                    return;
                };
                events.push(EvalEvent {
                    line: *line,
                    kind: EvalEventKind::Variable {
                        name: name.clone(),
                        value: display_val,
                        is_bool: bool_signals.contains(name),
                    },
                });
            } else {
                // Array signal: pre-allocate the slot.  Walk only the
                // first dimension; multi-dim is not exercised by the
                // shipped fixtures.
                let n = dims
                    .first()
                    .and_then(|e| eval_expr(e, env).and_then(|v| v.as_int()))
                    .unwrap_or(0) as usize;
                env.insert(name.clone(), Value::Array(vec![Value::Int(0); n]));
                events.push(EvalEvent {
                    line: *line,
                    kind: EvalEventKind::Step,
                });
            }
        }
        Stmt::Assign { line, op, lhs, rhs } => {
            let value = eval_expr(rhs, env).and_then(|v| v.as_int()).unwrap_or(0);
            // Resolve indices against the current env *before* applying
            // the assignment so `out[i] <-- ...` renders as `out[3]`
            // when `i = 3` rather than the placeholder `out[?]`.  This
            // is the only path that surfaces array element names to the
            // recorder's variable-event sink.
            let lhs_name = expr_to_name_with_env(lhs, Some(env));
            // Apply the assignment to the env regardless of the operator.
            apply_lvalue(lhs, value, env);

            match op {
                AssignOp::VarAssign => {
                    // `var` updates are bookkeeping — emit a step but
                    // no Variable event (mirrors the rationale in
                    // VarDecl: `var`s aren't user-visible signals).
                    events.push(EvalEvent {
                        line: *line,
                        kind: EvalEventKind::Step,
                    });
                }
                AssignOp::SignalAssign | AssignOp::SignalAssignConstrain => {
                    // Wire? — `comp.signal <== expr` is also a wire
                    // into the sub-component's input env so we record
                    // a Wire event alongside the user-visible
                    // Variable event.  Two shapes are recognised:
                    //   * `comp.signal <== expr` — scalar component.
                    //   * `arr[i].signal <== expr` — element of a
                    //     component array; route to the synthetic
                    //     `arr[<idx>]` slot populated by the wire
                    //     pre-pass.
                    if let Expr::Member(comp_box, signal) = lhs {
                        if let Expr::Ident(comp_name) = comp_box.as_ref() {
                            events.push(EvalEvent {
                                line: *line,
                                kind: EvalEventKind::Wire {
                                    comp_name: comp_name.clone(),
                                    signal_name: signal.clone(),
                                    value,
                                },
                            });
                        } else if let Expr::Index(arr_box, idx_expr) = comp_box.as_ref() {
                            if let Expr::Ident(arr_name) = arr_box.as_ref() {
                                let idx = eval_expr(idx_expr, env)
                                    .and_then(|v| v.as_int())
                                    .unwrap_or(0);
                                let synthetic = format!("{arr_name}[{idx}]");
                                events.push(EvalEvent {
                                    line: *line,
                                    kind: EvalEventKind::Wire {
                                        comp_name: synthetic,
                                        signal_name: signal.clone(),
                                        value,
                                    },
                                });
                            }
                        }
                    }
                    // Detect Boolean-constrained signals.  Three
                    // shapes are recognised:
                    //   * `out` declared in a template whose body
                    //     contains `out * (out - 1) === 0` — picked
                    //     up by `bool_signals.contains(&lhs_name)`.
                    //   * `comp.out` parent-frame views — last
                    //     segment matches a bool-constrained signal.
                    //   * `parent_out <== sub.boolsig;` — the LHS is
                    //     a fresh signal in the parent template, but
                    //     the RHS reads back a boolean from a
                    //     sub-component, so the surfaced value is
                    //     {0,1}.
                    let mut is_bool = bool_signals.contains(&lhs_name)
                        || lhs_name
                            .rsplit('.')
                            .next()
                            .map(|tail| bool_signals.contains(tail))
                            .unwrap_or(false);
                    if !is_bool {
                        if let Some(name) = rhs_bool_signal_name(rhs) {
                            if bool_signals.contains(&name) {
                                is_bool = true;
                            }
                        }
                    }
                    events.push(EvalEvent {
                        line: *line,
                        kind: EvalEventKind::Variable {
                            name: lhs_name,
                            value,
                            is_bool,
                        },
                    });
                }
            }
        }
        Stmt::Constraint { line, lhs, rhs } => {
            // `===` is only a constraint — record a step at the line.
            // Additionally, if both sides evaluate to concrete i64s
            // and they don't match, surface a tagged constraint-
            // violation event so debugger consumers can flag the
            // offending line.  Constants-on-both-sides is the common
            // shape for the structured evaluator (defaults are 0,
            // and many fixtures hardcode RHS values), and it covers
            // the range-proof fixture's load-bearing case.
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
            if let (Some(lv), Some(rv)) = (
                eval_expr(lhs, env).and_then(|v| v.as_int()),
                eval_expr(rhs, env).and_then(|v| v.as_int()),
            ) {
                if lv != rv {
                    let text = format!(
                        "constraint violation at line {line}: \
                         lhs={lv} != rhs={rv}"
                    );
                    events.push(EvalEvent {
                        line: *line,
                        kind: EvalEventKind::ConstraintViolation {
                            lhs_value: lv,
                            rhs_value: rv,
                            text,
                        },
                    });
                }
            }
        }
        Stmt::If {
            line,
            cond,
            then_block,
            else_block,
        } => {
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
            let c = eval_expr(cond, env).and_then(|v| v.as_int()).unwrap_or(0);
            if c != 0 {
                eval_block(then_block, env, events, ctx, bool_signals);
            } else {
                eval_block(else_block, env, events, ctx, bool_signals);
            }
        }
        Stmt::For {
            line,
            init,
            cond,
            update,
            body,
        } => {
            // Step at the for-loop header line, once.  Init/update
            // statements (typically `var i = 0` and `i++`) execute
            // for every iteration but are bookkeeping for the loop;
            // surfacing them as repeated step events would yield a
            // confusing per-iteration step train at the for-line.
            // Apply the init/update side-effects to the env without
            // emitting events.
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
            let mut sink = Vec::new();
            eval_stmt(init, env, &mut sink, ctx, bool_signals);
            let mut iterations = 0usize;
            const MAX_ITERATIONS: usize = 10_000;
            while iterations < MAX_ITERATIONS {
                let c = eval_expr(cond, env).and_then(|v| v.as_int()).unwrap_or(0);
                if c == 0 {
                    break;
                }
                eval_block(body, env, events, ctx, bool_signals);
                let mut update_sink = Vec::new();
                eval_stmt(update, env, &mut update_sink, ctx, bool_signals);
                iterations += 1;
            }
        }
        Stmt::ComponentDecl {
            line,
            name,
            template,
            args,
        } => {
            let arg_vals: Vec<i64> = args
                .iter()
                .map(|e| eval_expr(e, env).and_then(|v| v.as_int()).unwrap_or(0))
                .collect();
            // The pre-pass has already populated this component's
            // signals map (inputs from wires + outputs from
            // recursively evaluating the sub-template).  Don't clobber
            // it — only insert if missing (defensive against malformed
            // input).
            if !env.contains_key(name) {
                env.insert(
                    name.clone(),
                    Value::Component {
                        template: template.clone(),
                        signals: HashMap::new(),
                    },
                );
            }
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::ComponentEnter {
                    comp_name: name.clone(),
                    template: template.clone(),
                    args: arg_vals,
                },
            });
        }
        Stmt::ComponentArrayDecl { line, .. } => {
            // Array slot is pre-allocated by the wire-collection pre-pass
            // (the per-element synthetic Component entries are also
            // populated there).  Surface a step at the decl line.
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
        }
        Stmt::ComponentArrayAssign {
            line,
            name,
            index,
            template,
            args,
        } => {
            let idx = eval_expr(index, env).and_then(|v| v.as_int()).unwrap_or(0);
            let synthetic = format!("{name}[{idx}]");
            let arg_vals: Vec<i64> = args
                .iter()
                .map(|e| eval_expr(e, env).and_then(|v| v.as_int()).unwrap_or(0))
                .collect();
            // The wire-collection pre-pass already populated the
            // synthetic Component entry; don't clobber it.
            if !env.contains_key(&synthetic) {
                env.insert(
                    synthetic.clone(),
                    Value::Component {
                        template: template.clone(),
                        signals: HashMap::new(),
                    },
                );
            }
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::ComponentEnter {
                    comp_name: synthetic,
                    template: template.clone(),
                    args: arg_vals,
                },
            });
        }
        Stmt::ExprStmt { line, .. } => {
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
        }
        Stmt::Return { line, .. } => {
            events.push(EvalEvent {
                line: *line,
                kind: EvalEventKind::Step,
            });
        }
    }
}

fn apply_lvalue(lhs: &Expr, value: i64, env: &mut HashMap<String, Value>) {
    match lhs {
        Expr::Ident(name) => {
            env.insert(name.clone(), Value::Int(value));
        }
        Expr::Member(box_lhs, signal) => {
            if let Expr::Ident(comp_name) = box_lhs.as_ref() {
                let entry = env.entry(comp_name.clone()).or_insert(Value::Component {
                    template: String::new(),
                    signals: HashMap::new(),
                });
                if let Value::Component { signals, .. } = entry {
                    signals.insert(signal.clone(), value);
                }
            } else if let Expr::Index(arr_box, idx_expr) = box_lhs.as_ref() {
                // `arr[i].signal = value;` — route to the synthetic
                // `arr[<idx>]` Component slot populated by the
                // wire-collection pre-pass.
                if let Expr::Ident(arr_name) = arr_box.as_ref() {
                    let idx = eval_expr(idx_expr, env)
                        .and_then(|v| v.as_int())
                        .unwrap_or(0);
                    let synthetic = format!("{arr_name}[{idx}]");
                    let entry = env.entry(synthetic).or_insert(Value::Component {
                        template: String::new(),
                        signals: HashMap::new(),
                    });
                    if let Value::Component { signals, .. } = entry {
                        signals.insert(signal.clone(), value);
                    }
                }
            }
        }
        Expr::Index(box_lhs, idx_expr) => {
            let idx = eval_expr(idx_expr, env)
                .and_then(|v| v.as_int())
                .unwrap_or(0) as usize;
            if let Expr::Ident(name) = box_lhs.as_ref() {
                let entry = env.entry(name.clone()).or_insert(Value::Array(Vec::new()));
                if let Value::Array(arr) = entry {
                    if idx >= arr.len() {
                        arr.resize(idx + 1, Value::Int(0));
                    }
                    arr[idx] = Value::Int(value);
                }
            }
        }
        _ => {}
    }
}

/// Render an l-value expression as a printable name.  When `env` is
/// `Some(...)`, indexing expressions like `out[i]` resolve `i` against
/// the env (so the printed name surfaces as `out[3]` rather than
/// `out[?]`).  Without an env we still try to render literal indices.
fn expr_to_name_with_env(e: &Expr, env: Option<&HashMap<String, Value>>) -> String {
    match e {
        Expr::Ident(s) => s.clone(),
        Expr::Member(b, s) => format!("{}.{}", expr_to_name_with_env(b, env), s),
        Expr::Index(b, i) => {
            let idx = match i.as_ref() {
                Expr::Int(n) => n.to_string(),
                other => env
                    .and_then(|e| eval_expr(other, e).and_then(|v| v.as_int()))
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".to_string()),
            };
            format!("{}[{}]", expr_to_name_with_env(b, env), idx)
        }
        _ => "?".to_string(),
    }
}

fn eval_expr(e: &Expr, env: &HashMap<String, Value>) -> Option<Value> {
    with_active_fns(|fns| eval_expr_with_fns(e, env, fns))
}

/// Like `eval_expr`, but with access to a function-table so
/// `Expr::Call(name, args)` references can resolve to compile-time
/// `function` definitions.  The caller passes `Some(...)` when
/// evaluating from inside a template / function body where calls need
/// to be looked up; `None` is the legacy path used by the pre-pass and
/// by every evaluation that pre-dates function support.
fn eval_expr_with_fns(
    e: &Expr,
    env: &HashMap<String, Value>,
    fns: Option<&HashMap<String, Function>>,
) -> Option<Value> {
    match e {
        Expr::Int(n) => Some(Value::Int(*n)),
        Expr::Ident(name) => env.get(name).cloned(),
        Expr::Member(b, name) => {
            // First, special-case `arr[i].signal` reads: the wire
            // pre-pass populates synthetic env entries of the form
            // `arr[<idx>]` with the per-element Component value, but
            // the underlying `arr` Array slot stays empty.  Resolve
            // the synthetic key directly so the read picks up the
            // sub-component's outputs.
            if let Expr::Index(arr_box, idx_expr) = b.as_ref() {
                if let Expr::Ident(arr_name) = arr_box.as_ref() {
                    if let Some(idx) =
                        eval_expr_with_fns(idx_expr, env, fns).and_then(|v| v.as_int())
                    {
                        let synthetic = format!("{arr_name}[{idx}]");
                        if let Some(Value::Component { signals, .. }) = env.get(&synthetic) {
                            return signals.get(name).copied().map(Value::Int);
                        }
                    }
                }
            }
            let base = eval_expr_with_fns(b, env, fns)?;
            match base {
                Value::Component { signals, .. } => signals.get(name).copied().map(Value::Int),
                _ => None,
            }
        }
        Expr::Index(b, idx) => {
            let base = eval_expr_with_fns(b, env, fns)?;
            let i = eval_expr_with_fns(idx, env, fns).and_then(|v| v.as_int())? as usize;
            if let Value::Array(arr) = base {
                arr.get(i).cloned()
            } else {
                None
            }
        }
        Expr::Paren(b) => eval_expr_with_fns(b, env, fns),
        Expr::Ternary(cond, then_b, else_b) => {
            let c = eval_expr_with_fns(cond, env, fns).and_then(|v| v.as_int())?;
            if c != 0 {
                eval_expr_with_fns(then_b, env, fns)
            } else {
                eval_expr_with_fns(else_b, env, fns)
            }
        }
        Expr::Unary(op, b) => {
            let v = eval_expr_with_fns(b, env, fns).and_then(|v| v.as_int())?;
            match op {
                UnaryOp::Neg => Some(Value::Int(-v)),
                UnaryOp::Not => Some(Value::Int(if v == 0 { 1 } else { 0 })),
            }
        }
        Expr::Binary(op, l, r) => {
            let lv = eval_expr_with_fns(l, env, fns).and_then(|v| v.as_int())?;
            let rv = eval_expr_with_fns(r, env, fns).and_then(|v| v.as_int())?;
            let result = match op {
                BinOp::Add => lv + rv,
                BinOp::Sub => lv - rv,
                BinOp::Mul => lv * rv,
                BinOp::Div => {
                    if rv == 0 {
                        0
                    } else {
                        lv / rv
                    }
                }
                BinOp::Mod => {
                    if rv == 0 {
                        0
                    } else {
                        lv % rv
                    }
                }
                BinOp::Lt => (lv < rv) as i64,
                BinOp::Le => (lv <= rv) as i64,
                BinOp::Gt => (lv > rv) as i64,
                BinOp::Ge => (lv >= rv) as i64,
                BinOp::Eq => (lv == rv) as i64,
                BinOp::Ne => (lv != rv) as i64,
                BinOp::And => ((lv != 0) && (rv != 0)) as i64,
                BinOp::Or => ((lv != 0) || (rv != 0)) as i64,
                BinOp::BitAnd => lv & rv,
                BinOp::BitOr => lv | rv,
                BinOp::BitXor => lv ^ rv,
                BinOp::Shl => lv.wrapping_shl(rv as u32),
                BinOp::Shr => lv.wrapping_shr(rv as u32),
            };
            Some(Value::Int(result))
        }
        Expr::Call(name, args) => {
            // Look up the function in the function table; if missing,
            // fall back to None (the legacy behaviour) so degenerate
            // inputs still produce *some* trace.
            let fns = fns?;
            let func = fns.get(name)?;
            // Evaluate each argument in the caller's env, then bind the
            // results to the function's formal parameters in a fresh
            // env.  Functions don't see signals — only their numeric
            // parameters and any `var`s declared in their body.
            let mut fn_env: HashMap<String, Value> = HashMap::new();
            for (param, arg_expr) in func.params.iter().zip(args.iter()) {
                let v = eval_expr_with_fns(arg_expr, env, Some(fns))
                    .and_then(|v| v.as_int())
                    .unwrap_or(0);
                fn_env.insert(param.clone(), Value::Int(v));
            }
            // Walk the body looking for the `return` statement; the
            // body is also allowed to mutate `var`s in its own env via
            // assignments / for loops, so we need to interpret each
            // statement.
            execute_function_body(&func.body, &mut fn_env, fns)
        }
    }
}

/// Execute a function body and return the value of the first `return`
/// statement encountered (or 0 if none).  Functions are pure
/// compile-time numeric code: they have no signals, no constraints,
/// and never touch the witness, so we don't emit any recorder events
/// here — the recorder integration emits per-line steps separately
/// when it walks the function body for the function-table call frame.
fn execute_function_body(
    body: &[Stmt],
    env: &mut HashMap<String, Value>,
    fns: &HashMap<String, Function>,
) -> Option<Value> {
    for stmt in body {
        if let Some(v) = execute_function_stmt(stmt, env, fns) {
            return Some(v);
        }
    }
    Some(Value::Int(0))
}

fn execute_function_stmt(
    stmt: &Stmt,
    env: &mut HashMap<String, Value>,
    fns: &HashMap<String, Function>,
) -> Option<Value> {
    match stmt {
        Stmt::VarDecl { name, init, .. } => {
            let val = init
                .as_ref()
                .and_then(|e| eval_expr_with_fns(e, env, Some(fns)).and_then(|v| v.as_int()))
                .unwrap_or(0);
            env.insert(name.clone(), Value::Int(val));
            None
        }
        Stmt::Assign { lhs, rhs, .. } => {
            let value = eval_expr_with_fns(rhs, env, Some(fns))
                .and_then(|v| v.as_int())
                .unwrap_or(0);
            apply_lvalue(lhs, value, env);
            None
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
            ..
        } => {
            let c = eval_expr_with_fns(cond, env, Some(fns))
                .and_then(|v| v.as_int())
                .unwrap_or(0);
            if c != 0 {
                execute_function_body(then_block, env, fns)
                    .filter(|v| !matches!(v, Value::Int(0)))
                    .or(None)
            } else {
                execute_function_body(else_block, env, fns)
                    .filter(|v| !matches!(v, Value::Int(0)))
                    .or(None)
            }
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
            ..
        } => {
            execute_function_stmt(init, env, fns);
            let mut iterations = 0usize;
            const MAX_ITERATIONS: usize = 10_000;
            while iterations < MAX_ITERATIONS {
                let c = eval_expr_with_fns(cond, env, Some(fns))
                    .and_then(|v| v.as_int())
                    .unwrap_or(0);
                if c == 0 {
                    break;
                }
                for s in body {
                    if let Some(ret) = execute_function_stmt(s, env, fns) {
                        return Some(ret);
                    }
                }
                execute_function_stmt(update, env, fns);
                iterations += 1;
            }
            None
        }
        Stmt::Return { value, .. } => {
            let v = value
                .as_ref()
                .and_then(|e| eval_expr_with_fns(e, env, Some(fns)).and_then(|v| v.as_int()))
                .unwrap_or(0);
            Some(Value::Int(v))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_template() {
        let src = "template Foo() {\n  signal output x;\n  x <== 42;\n}\n";
        let templates = parse_templates(src);
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].name, "Foo");
        assert_eq!(templates[0].body.len(), 2);
    }

    #[test]
    fn evaluate_constants() {
        let src = "template Foo() {\n  signal output x;\n  x <== 6 + 7;\n}\n";
        let templates = parse_templates(src);
        let mut tmap = HashMap::new();
        for t in &templates {
            tmap.insert(t.name.clone(), t.clone());
        }
        let empty_fns = HashMap::new();
        let empty_buses = HashMap::new();
        let ctx = EvalContext {
            templates: &tmap,
            input_signals: HashMap::new(),
            generic_args: Vec::new(),
            functions: &empty_fns,
            buses: &empty_buses,
        };
        let result = evaluate_template(&templates[0], &ctx);
        assert_eq!(result.outputs.get("x"), Some(&13));
    }

    #[test]
    fn evaluate_for_loop() {
        let src = "template Foo() {\n  signal output total;\n  var acc = 0;\n  for (var i = 0; i < 5; i++) {\n    acc = acc + i * 2;\n  }\n  total <== acc;\n}\n";
        let templates = parse_templates(src);
        let mut tmap = HashMap::new();
        for t in &templates {
            tmap.insert(t.name.clone(), t.clone());
        }
        let empty_fns = HashMap::new();
        let empty_buses = HashMap::new();
        let ctx = EvalContext {
            templates: &tmap,
            input_signals: HashMap::new(),
            generic_args: Vec::new(),
            functions: &empty_fns,
            buses: &empty_buses,
        };
        let result = evaluate_template(&templates[0], &ctx);
        assert_eq!(result.outputs.get("total"), Some(&20));
    }

    #[test]
    fn evaluate_if() {
        let src = "template Foo() {\n  signal output b;\n  var s = 7;\n  var x;\n  if (s > 5) {\n    x = 100;\n  } else {\n    x = 1;\n  }\n  b <== x;\n}\n";
        let templates = parse_templates(src);
        let mut tmap = HashMap::new();
        for t in &templates {
            tmap.insert(t.name.clone(), t.clone());
        }
        let empty_fns = HashMap::new();
        let empty_buses = HashMap::new();
        let ctx = EvalContext {
            templates: &tmap,
            input_signals: HashMap::new(),
            generic_args: Vec::new(),
            functions: &empty_fns,
            buses: &empty_buses,
        };
        let result = evaluate_template(&templates[0], &ctx);
        assert_eq!(result.outputs.get("b"), Some(&100));
    }
}
