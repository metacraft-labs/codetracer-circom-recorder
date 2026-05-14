pragma circom 2.0.0;

// Real-world circomlib idiom: `Num2Bits(N)` decomposes an N-bit field
// element into N output bits.  This is the canonical bit-decomposition
// pattern shipped with circomlib (`circomlib/circuits/bitify.circom`).
// Closes the M11 deferred `intermediate_outputs_decode` follow-up by
// exercising a real-world template with a numeric template parameter
// (`N`), an `output[N]` signal array, a for loop over `N`, and a `===`
// constraint that pins the decomposition.
//
// The recorder defaults `signal input` values to 0, so the input is 0
// and every output bit is 0.  The structured evaluator must:
//   * Bind `N` to the template-arg value (4) when entering the call.
//   * Allocate the `signal output out[N]` array.
//   * Walk the for-loop and emit per-iteration steps.
//   * Surface the `===` constraint line as a step.
template Num2Bits(N) {
    signal input in;
    signal output out[N];

    var lc1 = 0;
    var e2 = 1;
    for (var i = 0; i < N; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] - 1) === 0;
        lc1 = lc1 + out[i] * e2;
        e2 = e2 + e2;
    }
    lc1 === in;
}

component main = Num2Bits(4);
