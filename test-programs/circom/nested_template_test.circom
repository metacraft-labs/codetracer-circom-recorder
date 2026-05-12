pragma circom 2.0.0;

// Nested-template chain: Outer instantiates Middle, Middle instantiates
// Inner.  Each level wires its single output through the next, so the
// trace must surface a 3-deep template-call hierarchy:
//
//   main (NestedTemplate)
//     ├─ middle (Middle)
//     │     └─ inner (Inner)   inner.out = 1 + 2 = 3
//     │     middle.out = inner.out + 10 = 13
//     outer_result is bound to middle.out + 100 = 113
//
// Every signal is driven from literal constants so no input is required
// (the recorder defaults all main inputs to 0; this circuit takes none).
template Inner() {
    signal output out;

    out <== 1 + 2;
}

template Middle() {
    signal output out;

    component inner = Inner();
    out <== inner.out + 10;
}

template NestedTemplate() {
    signal output outer_result;

    component middle = Middle();
    outer_result <== middle.out + 100;
}

component main = NestedTemplate();
