pragma circom 2.0.0;

// Multi-line `<==` constraint exercise: a single signal-assignment
// constraint whose RHS expression is split across four physical source
// lines.  Closes the M12 deferred coverage gap for source-formatting
// resilience — the structured evaluator must surface a *single* step
// event for the constraint (carrying the constructed expression value)
// rather than four separate steps for each physical line of the RHS.
// This pins the recorder's "one statement, one step" contract against
// developer-friendly multi-line formatting that real-world circomlib
// circuits routinely use to keep long algebraic constraints readable.
//
// Computation:
//   a = 2, b = 3, c = 4, d = 5, e = 1
//   out <== 2*a + 3*b + 4*c + 5*d - e = 4 + 9 + 16 + 25 - 1 = 53
//
// The RHS is linear in the signals (only constant-times-signal terms
// are summed) so the witness compiler accepts it as a quadratic
// constraint, which lets us focus the test purely on the source-line
// formatting concern.
template MultiLineConstraint() {
    signal output out;

    signal a;
    signal b;
    signal c;
    signal d;
    signal e;

    a <== 2;
    b <== 3;
    c <== 4;
    d <== 5;
    e <== 1;

    out <==
        2 * a +
        3 * b +
        4 * c +
        5 * d -
        e;
}

component main = MultiLineConstraint();
