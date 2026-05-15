pragma circom 2.0.0;

// Public-signal annotation exercise: the `component main {public [...]}`
// header tags a subset of the main template's input signals as
// `public` (proof-visible).  Closes the M12 deferred coverage gap for
// the public-signal annotation by pinning that the recorder surfaces
// the public-signal set in per-trace metadata at the
// `component main` boundary.
//
// Computation:
//   a = 0, b = 0, c = 0  (all defaulted by the recorder — no input JSON)
//   sum = a + b + c = 0
template Foo() {
    signal input a;
    signal input b;
    signal input c;
    signal output sum;

    sum <== a + b + c;
}

component main {public [a, b]} = Foo();
