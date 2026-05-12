pragma circom 2.0.0;

// Control-flow exercise: var mutability, if/else, and for loops over a
// compile-time var bound.  Circom evaluates var expressions / control-
// flow at compile time; the resulting field-constant is then bound into
// signal assignments by the constraint operator.  The values surfaced
// in the trace come from the witness, so every literal in this circuit
// must round-trip through the witness calculator and back into the .sym
// table.
//
// Computation:
//   start  = 7
//   total  = sum of (i * 2) for i in 0..5      = 0+2+4+6+8 = 20
//   bonus  = (start > 5) ? 100 : 1             = 100
//   result = total + bonus                     = 120
template ControlFlow() {
    signal output total;
    signal output bonus;
    signal output result;

    var start = 7;

    var acc = 0;
    for (var i = 0; i < 5; i++) {
        acc = acc + i * 2;
    }

    var b;
    if (start > 5) {
        b = 100;
    } else {
        b = 1;
    }

    total <== acc;
    bonus <== b;
    result <== acc + b;
}

component main = ControlFlow();
