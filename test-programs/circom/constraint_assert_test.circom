pragma circom 2.0.0;

// Constraint-assertion exercise: uses the `===` operator to assert that
// two field elements are equal.  This is Circom's only language-level
// "panic" primitive — the witness calculator succeeds when every `===`
// holds, and the proof generator rejects the witness otherwise.
//
// Computation:
//   a   = 6
//   b   = 7
//   sum = 13
//   prod = 42  (assert sum === a + b — passes; assert 42 === a * b — passes)
template ConstraintAssert() {
    signal output sum;
    signal output prod;

    signal a;
    signal b;

    a <== 6;
    b <== 7;

    sum <== a + b;
    prod <== a * b;

    sum === a + b;
    prod === 42;
}

component main = ConstraintAssert();
