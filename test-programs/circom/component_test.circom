pragma circom 2.0.0;

template Adder() {
    signal input a;
    signal input b;
    signal output out;

    out <== a + b;
}

template ComponentTest() {
    signal input x;
    signal input y;
    signal output result;

    component adder = Adder();
    adder.a <== x;
    adder.b <== y;
    result <== adder.out;
}

component main = ComponentTest();
