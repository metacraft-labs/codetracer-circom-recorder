pragma circom 2.0.0;

// Boolean comparator-template exercise: minimal `IsNonZero` /
// `IsEqual` templates whose outputs are constrained to {0, 1} via the
// canonical `out * (out - 1) === 0` Boolean constraint.  This is the
// shape used by circomlib's bitify / comparators libraries — closes
// the M12 deferred coverage for boolean-output templates.  The
// recorder detects the `signal * (signal - 1) === 0` pattern and
// surfaces such signals with `ValueRecord::Bool` rather than the
// generic `ValueRecord::Int`, so the calltrace pane / locals pane
// show "true" / "false" rather than "0" / "1".
//
// The implementations sidestep field-arithmetic inversion (which
// can't be modelled in i64) by computing `out` directly from a
// ternary `<--` driven by `==` / `!=`; the Boolean constraint then
// pins the output to {0, 1} so the witness calculator and the
// recorder agree on the final value.
//
// Computation:
//   IsNonZero(0)   -> 0 (false)
//   IsNonZero(7)   -> 1 (true)
//   IsEqual(5, 5)  -> 1 (true)
//   IsEqual(5, 9)  -> 0 (false)
template IsNonZero() {
    signal input in;
    signal output out;

    out <-- in == 0 ? 0 : 1;
    out * (out - 1) === 0;
}

template IsEqual() {
    signal input a;
    signal input b;
    signal output out;

    out <-- a == b ? 1 : 0;
    out * (out - 1) === 0;
}

template TopLevel() {
    signal output nz_zero;
    signal output nz_seven;
    signal output eq_same;
    signal output eq_diff;

    component nz_a = IsNonZero();
    component nz_b = IsNonZero();
    component eq_a = IsEqual();
    component eq_b = IsEqual();

    nz_a.in <== 0;
    nz_b.in <== 7;
    eq_a.a <== 5;
    eq_a.b <== 5;
    eq_b.a <== 5;
    eq_b.b <== 9;

    nz_zero <== nz_a.out;
    nz_seven <== nz_b.out;
    eq_same <== eq_a.out;
    eq_diff <== eq_b.out;
}

component main = TopLevel();
