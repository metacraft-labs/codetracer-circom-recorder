pragma circom 2.0.0;

// var-vs-signal exercise: mixes a compile-time `var k = 7` constant,
// a `var sum = 0` accumulator mutated in a for-unroll, and a single
// `signal output out` that captures the final sum.  Closes the M12
// deferred coverage gap for the `var` / `signal` distinction at the
// trace surface — the recorder's structured evaluator currently treats
// `var` declarations / mutations as bookkeeping (compile-time scratch)
// and emits Step events at their lines without any accompanying
// Variable event, while `signal` assignments emit both a Step and a
// Variable event carrying the field-element value.  This test pins
// that asymmetry strictly so a later refactor can't silently surface
// `var` bindings into the values pane (which would pollute the trace
// with every for-loop induction variable).
//
// Computation:
//   k   = 7                                              (compile-time)
//   sum = 0 + (0+k) + (1+k) + (2+k) + (3+k) + (4+k)       = 0+7+8+9+10+11 = 45
//   out <== sum                                          = 45
template VarVsSignal() {
    signal output out;

    var k = 7;
    var sum = 0;
    for (var i = 0; i < 5; i++) {
        sum = sum + i + k;
    }

    out <== sum;
}

component main = VarVsSignal();
