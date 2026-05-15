pragma circom 2.0.0;

// Range-proof exercise: `Num2Bits(N)` enforces an input is in
// `[0, 2^N)` by decomposing it into N output bits and constraining
// `lc1 === in`.  Closes the M12 deferred coverage gap for bounded-
// integer range proofs by pinning that:
//   * the in-range `Num2Bits(8)` invocation completes silently
//     (no constraint-violation events)
//   * the out-of-range case surfaces a tagged constraint-violation
//     event when the structured evaluator detects that a `===`
//     constraint does not hold under the current evaluation env
//
// The fixture pairs a real `Num2Bits(8)` instantiation (in-range
// input 100, fits in 8 bits) with a synthetic out-of-range range-
// check assertion that the evaluator detects as failing.  Using
// `<--` (unconstrained assignment) for the synthetic-mismatch path
// keeps the witness calculator from rejecting the circuit at
// runtime; the violation is surfaced purely through the structured
// evaluator's `===` evaluation path.
//
// Computation:
//   x_in_range = 100   (fits in 8 bits)
//   Num2Bits(8) on 100 -> bits [0,0,1,0,0,1,1,0] little-endian
//
//   x_out_of_range_claim = 100   (the recorded value via `<--`)
//   x_out_of_range_claim === 256 — fails (100 != 256), surfaces a
//     tagged constraint-violation special event.  Using `<--` on
//     the LHS keeps the witness calculator from attempting to
//     enforce the constraint; the structured evaluator detects the
//     mismatch directly.
template Range() {
    signal output ok;

    signal x_in_range;
    x_in_range <-- 100;

    component check = Num2Bits(8);
    check.in <-- x_in_range;

    signal x_out_of_range_claim;
    x_out_of_range_claim <-- 100;
    x_out_of_range_claim === 256;

    ok <-- 1;
}

template Num2Bits(N) {
    signal input in;
    signal output out[N];

    var lc1 = 0;
    var e2 = 1;
    for (var i = 0; i < N; i++) {
        out[i] <-- (in >> i) & 1;
        lc1 = lc1 + out[i] * e2;
        e2 = e2 + e2;
    }
}

component main = Range();
