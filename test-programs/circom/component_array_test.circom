pragma circom 2.0.0;

// Component-array exercise: `component subs[M]` declares an array of
// sub-component instances, each of which is independently instantiated
// inside a for loop and wired up element-wise.  Closes the M12
// deferred coverage gap for component arrays — every `subs[i]` slot
// must surface as its own call_entry / call_exit pair.
//
// Computation:
//   M = 3
//   in[i] = 0 for i in 0..3 (recorder defaults inputs to 0)
//   subs[i].x = in[i]
//   out[i] = subs[i].y = subs[i].x = in[i] = 0
template Sum() {
    signal input x;
    signal output y;

    y <== x;
}

template UseSubs(M) {
    signal input in[M];
    signal output out[M];

    component subs[M];
    for (var i = 0; i < M; i++) {
        subs[i] = Sum();
        subs[i].x <== in[i];
        out[i] <== subs[i].y;
    }
}

component main = UseSubs(3);
