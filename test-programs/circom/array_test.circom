pragma circom 2.0.0;

template ArrayTest() {
    signal input in;
    signal values[3];
    signal output out;

    values[0] <== in;
    values[1] <== values[0] * 2;
    values[2] <== values[1] * 3;
    out <== values[2];
}

component main = ArrayTest();
