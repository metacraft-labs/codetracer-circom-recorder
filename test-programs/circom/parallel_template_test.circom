pragma circom 2.0.0;

// Parallel-template exercise: the `template parallel NAME(...)` modifier
// (Circom 2.0+) opts a template into the parallel witness-calculator
// codegen path so the witness for each instantiation can be computed
// independently of its siblings.  Closes the M12 deferred coverage gap
// for the parallel-template annotation by pinning that the recorder
// surfaces the parallel flag in function-table metadata at the file
// scope, distinguishing parallel from regular templates.
//
// `BatchHash(N)` is a per-element squaring batch — `out[i] <== in[i] *
// in[i]` for i in 0..N.  Instantiated at N=4 the for-loop unrolls
// into four iterations, each surfacing its own input/output wire
// values so per-instance variable tracking remains intact under the
// parallel annotation.
//
// Computation (every input defaults to 0 because no signal-input JSON
// is provided to the witness calculator):
//   in[0] = 0, in[1] = 0, in[2] = 0, in[3] = 0
//   out[i] = in[i] * in[i] = 0 for i in 0..4
template parallel BatchHash(N) {
    signal input in[N];
    signal output out[N];

    for (var i = 0; i < N; i++) {
        out[i] <== in[i] * in[i];
    }
}

component main = BatchHash(4);
