pragma circom 2.1.5;

include "pragma_version_helper.circom";

// Pragma-version exercise: the entrypoint declares
// `pragma circom 2.1.5;` and `include`s a helper file whose own
// `pragma circom 2.1.0;` header pins a different language version
// (the bus_type fixture ships once a circom 2.2+ binary is wired in
// — see task #56).
// Closes the M12 deferred coverage gap for `pragma circom <version>;`
// headers: the recorder scans the entrypoint and every directly
// included file, then surfaces the per-file pragma-version set via a
// dedicated `pragma_versions` special event so debugger consumers
// can show which Circom language version was assumed when each
// source file was parsed.
//
// Computation:
//   x = 0  (input defaults to 0)
//   inner.x = x = 0
//   inner.y = 2 * inner.x = 0
//   y = inner.y = 0
template Driver() {
    signal input x;
    signal output y;

    component inner = Doubler();
    inner.x <== x;
    y <== inner.y;
}

component main = Driver();
