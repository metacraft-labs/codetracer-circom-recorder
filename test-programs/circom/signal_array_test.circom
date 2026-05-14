pragma circom 2.0.0;

// Signal-array element-access exercise: `template VectorAdd(N)` declares
// two `signal input` arrays of length N and one `signal output` array
// of the same length, then walks the indices in lockstep adding
// element-wise.  Closes the M12 deferred coverage gap for indexed
// signal reads/writes — the recorder must surface every `a[i]` /
// `b[i]` / `c[i]` reference with the resolved index, not the
// placeholder `?`.
//
// Computation:
//   N = 4
//   a[i] = 0, b[i] = 0  for i in 0..4 (recorder defaults inputs to 0)
//   c[i] = a[i] + b[i] = 0
//
// The fact that all inputs default to 0 doesn't reduce the test's
// value: the structured evaluator must still bind N=4, allocate both
// input and output arrays, walk the body 4 times, and surface every
// iteration's `c[i] <== a[i] + b[i]` as a step + Variable event with
// the indexed name resolved against the loop induction variable `i`.
template VectorAdd(N) {
    signal input a[N];
    signal input b[N];
    signal output c[N];

    for (var i = 0; i < N; i++) {
        c[i] <== a[i] + b[i];
    }
}

component main = VectorAdd(4);
