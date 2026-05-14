pragma circom 2.0.0;

// Long wire-chain exercise: three sibling sub-components instantiated
// inside one parent template, with each sub-component's output wired
// into the next sub-component's input via the parent's body.  Closes
// the M11 deferred `chain_values_decode` follow-up by extending wire
// chains past the 2-component case in `signal_hierarchy_test.circom`.
//
// Computation:
//   step1.x   = 5
//   step1.out = 5 + 1   = 6
//   step2.in  = step1.out = 6
//   step2.out = 6 * 2   = 12
//   step3.in  = step2.out = 12
//   step3.out = 12 - 3  = 9
//   final     = step3.out + 100 = 109
template AddOne() {
    signal input x;
    signal output out;

    out <== x + 1;
}

template MulTwo() {
    signal input in;
    signal output out;

    out <== in * 2;
}

template SubThree() {
    signal input in;
    signal output out;

    out <== in - 3;
}

template WireToComponent() {
    signal output final;

    component step1 = AddOne();
    component step2 = MulTwo();
    component step3 = SubThree();

    step1.x <== 5;
    step2.in <== step1.out;
    step3.in <== step2.out;
    final <== step3.out + 100;
}

component main = WireToComponent();
