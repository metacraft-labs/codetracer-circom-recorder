pragma circom 2.0.0;

// Nested-for-loop unroll exercise: two for loops, one nested inside the
// other.  Both bounds are compile-time `var` literals so the compiler
// fully unrolls every iteration, which is what makes the per-line step
// stream emerge in the recorder trace.  Closes the M11 deferred
// `for_and_if_steps_emitted` follow-up by extending coverage past the
// single-loop case in `control_flow_test.circom`.
//
// Computation:
//   for i in 0..3:
//     for j in 0..2:
//       acc = acc + (i * 10 + j)
//   total = acc
//
// Expansion:
//   i=0 j=0 -> +0; j=1 -> +1
//   i=1 j=0 -> +10; j=1 -> +11
//   i=2 j=0 -> +20; j=1 -> +21
//   total = 0+1+10+11+20+21 = 63
template ForLoopUnroll() {
    signal output total;

    var acc = 0;
    for (var i = 0; i < 3; i++) {
        for (var j = 0; j < 2; j++) {
            acc = acc + (i * 10 + j);
        }
    }

    total <== acc;
}

component main = ForLoopUnroll();
