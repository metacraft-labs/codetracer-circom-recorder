pragma circom 2.1.0;

// Signal-tag exercise: Circom 2.1+ allows attaching named tags to
// signal declarations via the `signal {tag}` syntax.  Tags are
// compile-time annotations that propagate through `<==` and feed
// back-end constraint hints.  Closes the M12 deferred coverage gap
// for signal tags by pinning that the recorder parses the `{tag}`
// annotations on declarations and surfaces the tag set via a
// dedicated `signal_tags` special event at the file scope.
//
// `Inner` declares its inputs with tags; `Driver` declares fresh
// tagged signals and wires the (untagged) main inputs into them
// through the explicit-attach `<--` operator (the constrained `<==`
// requires the RHS to already carry the tag, which the untagged
// main inputs do not).  The main component is the untagged Driver —
// Circom rejects `component main` whose template declares tagged
// inputs.
//
// Computation: every signal defaults to 0.
template Inner() {
    signal input {bit} a;
    signal input {maxbit} b;
    signal output sum;

    sum <== a + b;
}

template Driver() {
    signal input a;
    signal input b;
    signal output sum;

    signal {bit} bit_a;
    signal {maxbit} maxbit_b;
    bit_a <-- a;
    maxbit_b <-- b;
    bit_a * (bit_a - 1) === 0;

    component inner = Inner();
    inner.a <== bit_a;
    inner.b <== maxbit_b;
    sum <== inner.sum;
}

component main = Driver();
