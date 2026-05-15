pragma circom 2.0.0;

// Compile-time `if`/`else` exercise: `template Branch(MODE)` selects
// between two output formulas based on a generic numeric parameter
// `MODE`.  Closes the M12 deferred coverage gap for compile-time
// branch elimination — when the recorder's structured evaluator
// instantiates `Branch(0)` only the `then`-block body line surfaces
// as a step (the `else` body line is *not* visited because the var
// `MODE == 0` condition folds at compile time).  When the parent
// instantiates `Branch(1)` the situation is reversed: only the
// `else`-block body line surfaces.  Two sibling sub-component
// instantiations in the same `Pair` parent prove the per-instance
// difference end-to-end inside one trace.
//
// Computation:
//   Branch(0): cond `(MODE == 0) == 1` -> y <== x * 2 = 0 * 2 = 0
//   Branch(1): cond `(MODE == 0) == 0` -> y <== x + 100 = 0 + 100 = 100
//   Pair: out_zero = 0, out_one = 100
template Branch(MODE) {
    signal input x;
    signal output y;

    if (MODE == 0) {
        y <== x * 2;
    } else {
        y <== x + 100;
    }
}

template Pair() {
    signal output out_zero;
    signal output out_one;

    component b0 = Branch(0);
    component b1 = Branch(1);

    b0.x <== 0;
    b1.x <== 0;

    out_zero <== b0.y;
    out_one <== b1.y;
}

component main = Pair();
