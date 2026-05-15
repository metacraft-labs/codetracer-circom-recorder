pragma circom 2.1.0;

// Anonymous-component exercise: Circom 2.1+ allows inline-defined
// sub-components via the `expr <== Template(args)(in1, in2)` syntax
// (or `<--` for the unconstrained variant) — the template is
// instantiated and wired in a single expression-statement, without
// a named `component foo = Template();` declaration.  Closes the
// M12 deferred coverage gap for the anonymous-component syntax: the
// recorder source-scans for these inline-defined invocations and
// surfaces the per-instance synthetic name + underlying template
// name via a dedicated `anonymous_components` special event so
// debugger consumers can render every anonymous instantiation in
// the function-table view alongside its arguments.
//
// Computation:
//   in defaults to 0.
//   doubled = Doubler()(in)            -> 2 * 0 = 0   (anon @ line 32)
//   tripled = Tripler()(doubled)       -> 3 * 0 = 0   (anon @ line 33)
//   out     = doubled + tripled        -> 0 + 0 = 0
template Doubler() {
    signal input x;
    signal output y;

    y <== 2 * x;
}

template Tripler() {
    signal input x;
    signal output y;

    y <== 3 * x;
}

template Driver() {
    signal input in;
    signal output out;

    signal doubled;
    signal tripled;
    doubled <-- Doubler()(in);
    tripled <-- Tripler()(doubled);
    out <-- doubled + tripled;
}

component main = Driver();
