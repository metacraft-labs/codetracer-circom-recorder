pragma circom 2.0.6;
pragma custom_templates;

// Custom-template exercise: `pragma custom_templates;` enables the
// `template custom NAME(...)` declaration form that opts a template
// into the PLONK-custom-gate codegen path.  Closes the M12 deferred
// coverage gap for the custom-template annotation by pinning that the
// recorder surfaces the custom-template flag in function-table
// metadata at the file scope.
//
// XorGate: c = a + b - 2*a*b enforces XOR for boolean a/b.  The
// `c * (1 - c) === 0` etc. constraints pin a/b/c to {0, 1}.
//
// Computation:
//   a = 0, b = 0  (both default to 0)
//   c = a + b - 2*a*b = 0
template custom XorGate() {
    signal input a;
    signal input b;
    signal output c;
    c <-- a + b - 2*a*b;
    c * (1 - c) === 0;
    a * (1 - a) === 0;
    b * (1 - b) === 0;
}

template Driver() {
    signal input a;
    signal input b;
    signal output c;

    component gate = XorGate();
    gate.a <== a;
    gate.b <== b;
    c <== gate.c;
}

component main = Driver();
