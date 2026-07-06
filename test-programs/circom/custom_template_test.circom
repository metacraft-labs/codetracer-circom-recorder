pragma circom 2.0.6;
pragma custom_templates;

// Custom-template exercise: `pragma custom_templates;` enables the
// `template custom NAME(...)` declaration form that opts a template
// into the PLONK-custom-gate codegen path.  Closes the M12 deferred
// coverage gap for the custom-template annotation by pinning that the
// recorder surfaces the custom-template flag in function-table
// metadata at the file scope.
//
// XorGate: c = a + b - 2*a*b computes XOR for boolean a/b.  Custom
// templates opt into the PLONK-custom-gate codegen path, where the
// gate's algebraic relation is supplied by the custom gate itself —
// so circom FORBIDS ordinary R1CS constraints (`===` / `<==`) in the
// body (error CG02).  The witness is therefore assigned with the
// non-constraining `<--` operator only; the constraint enforcement is
// the custom gate's responsibility, not the template body's.
//
// Computation:
//   a = 0, b = 0  (both default to 0)
//   c = a + b - 2*a*b = 0
template custom XorGate() {
    signal input a;
    signal input b;
    signal output c;
    c <-- a + b - 2*a*b;
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
