pragma circom 2.0.0;

// Signal-hierarchy exercise: a top-level template instantiates two
// sub-templates and forwards the first sub-template's output as the
// second sub-template's input.  Drives the recorder's per-component
// argument-staging path (`writer.arg("a", value)` followed by
// `register_call`) and exposes its sub-component output as a top-level
// signal.
//
// Computation:
//   add5.x   = 4
//   add5.y   = add5.x + 5 = 9
//   mul2.in  = add5.y     = 9
//   mul2.out = 9 * 2      = 18
//   total    = mul2.out + 1 = 19
template Add5() {
    signal input x;
    signal output y;

    y <== x + 5;
}

template Mul2() {
    signal input in;
    signal output out;

    out <== in * 2;
}

template SignalHierarchy() {
    signal output total;

    component add5 = Add5();
    component mul2 = Mul2();

    add5.x <== 4;
    mul2.in <== add5.y;
    total <== mul2.out + 1;
}

component main = SignalHierarchy();
