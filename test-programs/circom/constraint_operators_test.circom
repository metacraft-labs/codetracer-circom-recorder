pragma circom 2.0.0;

// Constraint-operator coverage extension: multiple `===` forms beyond
// the simple `lhs === rhs` shape exercised by `constraint_assert_test`.
// All constraints hold so the witness calculator succeeds; the recorder
// is expected to surface every `===` line as a dedicated step event.
//
// Closes the M11 deferred `emits_assertion_steps` follow-up by adding
// coverage for:
//   * `===` between two arithmetic sub-expressions
//     (`a + b === c * d` with both sides folding to a constant).
//   * `===` involving a difference (`s - a === b`).
//   * Multiple `===` constraints in sequence.
//
// Computation:
//   a = 3, b = 4, c = 7, d = 1
//   s = a + b = 7
//   constraints:
//     s === a + b       (7 === 3 + 4)   holds
//     a + b === c * d   (3 + 4 === 7 * 1) holds
//     s - a === b       (7 - 3 === 4)   holds
//     c === s           (7 === 7)       holds
template ConstraintOperators() {
    signal output s;

    signal a;
    signal b;
    signal c;
    signal d;

    a <== 3;
    b <== 4;
    c <== 7;
    d <== 1;

    s <== a + b;

    s === a + b;
    a + b === c * d;
    s - a === b;
    c === s;
}

component main = ConstraintOperators();
