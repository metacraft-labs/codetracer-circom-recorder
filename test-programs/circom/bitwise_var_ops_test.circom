pragma circom 2.0.0;

// Bitwise-on-`var` exercise: walks `&`, `|`, `^`, `<<`, `>>` over a
// pair of compile-time `var` operands and surfaces each per-op result
// through a dedicated `signal output` so the recorder can pin each
// `ValueRecord::Int` value at the corresponding `<==` line.  Closes
// the M12 deferred coverage gap for bitwise operators on `var`s — the
// recorder's evaluator has carried these in the AST since
// commit 730faa4 but no end-to-end fixture pinned the surfaced values.
//
// Computation (both `var`s and the final wire-up to outputs):
//   a = 0xF0 = 240
//   b = 0x0F = 15
//   and_v = a & b   = 0x00  = 0
//   or_v  = a | b   = 0xFF  = 255
//   xor_v = a ^ b   = 0xFF  = 255
//   shl_v = a << 2  = 0x3C0 = 960
//   shr_v = a >> 4  = 0x0F  = 15
template BitwiseVarOps() {
    signal output and_out;
    signal output or_out;
    signal output xor_out;
    signal output shl_out;
    signal output shr_out;

    var a = 240;
    var b = 15;

    var and_v = a & b;
    var or_v  = a | b;
    var xor_v = a ^ b;
    var shl_v = a << 2;
    var shr_v = a >> 4;

    and_out <== and_v;
    or_out  <== or_v;
    xor_out <== xor_v;
    shl_out <== shl_v;
    shr_out <== shr_v;
}

component main = BitwiseVarOps();
