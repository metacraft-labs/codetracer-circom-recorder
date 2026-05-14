pragma circom 2.0.0;

// Generic-template + signal-array exercise: `template Sum(N)` declares
// a `signal input in[N]` parameterised by N and an `signal output sum`.
// The body unrolls a for loop driven by the template arg `N`.  Closes
// the M11 follow-up "bread-and-butter form unexercised today":
// `template Foo(N)` with signal arrays parameterised by N.
//
// Computation:
//   N = 3
//   in[0] = 0, in[1] = 0, in[2] = 0  (recorder defaults to 0 for inputs)
//   acc = 0 + 0 + 0 + 0 = 0
//   sum = acc = 0
//
// The fact that all inputs default to 0 doesn't reduce the test's
// value: the structured evaluator must still bind N=3, walk the
// for-loop body 3 times, and surface every iteration as a step event.
// The `template_args` plumbing exercised here (the `Sum(3)` literal
// flowing through the recorder's component-arg parser into the
// evaluator's generic_args) is the new mechanism shipped 2026-05-13.
template Sum(N) {
    signal input in[N];
    signal output sum;

    var acc = 0;
    for (var i = 0; i < N; i++) {
        acc = acc + in[i];
    }
    sum <== acc;
}

component main = Sum(3);
