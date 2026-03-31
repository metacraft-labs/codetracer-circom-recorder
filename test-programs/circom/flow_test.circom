pragma circom 2.0.0;

template FlowTest() {
    signal input in;
    signal a;
    signal b;
    signal sum_val;
    signal doubled;
    signal output out;

    a <== 10;
    b <== 32;
    sum_val <== a + b;
    doubled <== sum_val * 2;
    out <== doubled + a;
}

component main = FlowTest();
