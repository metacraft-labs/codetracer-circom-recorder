pragma circom 2.0.0;

// Pure compile-time `function` exercise: `function fib(n)` runs an
// iterative Fibonacci over a `var` accumulator and returns the result
// as a numeric `var`.  Functions are *compile-time only* in Circom —
// they have no signals, no constraints, and never touch the witness
// — and the recorder must surface them in the function table so a
// debugger can step through their bodies independently from
// `template` calls.
//
// Computation:
//   fib(8): 0, 1, 1, 2, 3, 5, 8, 13, 21
//   fib(8) returns 21
//   out <== fib(8) = 21
template UseFib() {
    signal output out;

    out <== fib(8);
}

function fib(n) {
    var a = 0;
    var b = 1;
    for (var i = 0; i < n; i++) {
        var t = a + b;
        a = b;
        b = t;
    }
    return a;
}

component main = UseFib();
