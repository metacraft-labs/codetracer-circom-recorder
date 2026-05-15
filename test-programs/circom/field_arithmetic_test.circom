pragma circom 2.0.0;

// Field-arithmetic wraparound exercise: walks `(a + b) % p` over a
// pair of `var` values pre-positioned near a chosen modulus boundary
// so the sum overflows past `p` and the `%` reduction lands on a
// canonical small-magnitude representative.  The recorder evaluates
// `var` arithmetic in i64 — the bn128 field prime
// `21888242871839275222246405745257275088548364400416034343698204186575808495617`
// doesn't fit in i64, so the fixture uses a synthetic in-i64 modulus
// (the prime 1_000_003) which still exercises the same `(a + b) % p`
// reduction path that the witness calculator applies under the real
// field modulus.  Closes the M12 deferred coverage gap for compile-
// time field-arithmetic-style reductions on `var`s.
//
// Computation:
//   p          = 1_000_003           (chosen prime, fits in i64)
//   a          = p - 100             = 999_903
//   b          = 250
//   sum_raw    = a + b                = 1_000_153
//   sum_mod    = (a + b) % p          = 150
//   diff_raw   = b - a                = 250 - 999_903 = -999_653
//   diff_mod   = ((b - a) % p + p) % p = (-999_653 % 1_000_003 + 1_000_003) % 1_000_003
//              = (-999_653 + 1_000_003) % 1_000_003 = 350
template FieldArithmetic() {
    signal output sum_out;
    signal output diff_out;

    var p = 1000003;
    var a = p - 100;
    var b = 250;

    var sum_mod = (a + b) % p;
    var diff_mod = ((b - a) % p + p) % p;

    sum_out  <== sum_mod;
    diff_out <== diff_mod;
}

component main = FieldArithmetic();
