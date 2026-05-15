pragma circom 2.2.0;

// Bus-type exercise (Circom 2.2+ composite types).  A `bus` declares
// a named record of field-element signals that can be passed to a
// template as a single typed parameter via `input BusName() var;`.
//
// REQUIRES circom >= 2.2.  The dev shell pins circom 2.1.5; the test
// harness sets `CIRCOM_BIN` to a 2.2.3 binary built locally from the
// metacraft-circom-fork tree.  Without that, compilation fails with
// `Pragma version 2.2.0 is not supported`.
//
// The recorder surfaces the bus-typed input arg as the trace's first
// `ValueRecord::Struct` for Circom: a registered `TypeKind::Struct`
// `Point` carries the field-element type-id list, and the call_entry
// arg's `field_values` mirrors the bus's declared field order.  Bus
// field reads (`p.x`, `p.y`) inside the template body resolve through
// the existing `Expr::Member` -> `Value::Component` lookup path the
// evaluator already uses for `comp.signal` reads from sub-component
// instances.
//
// Computation (with all inputs defaulted to 0):
//   p.x = 0, p.y = 0  (no JSON-input wiring today)
//   x2  = p.x * p.x   = 0
//   y2  = p.y * p.y   = 0
//   d   = x2 + y2     = 0
//
// `<==` requires quadratic constraints — splitting the squared terms
// into intermediate signals (`x2`, `y2`) keeps each constraint
// quadratic.  Trying to write `d <== p.x*p.x + p.y*p.y` directly is
// rejected by the circom compiler with
// "Non quadratic constraints are not allowed!".
bus Point() {
    signal x;
    signal y;
}

template Distance() {
    input Point() p;
    signal output d;
    signal x2;
    signal y2;
    x2 <== p.x * p.x;
    y2 <== p.y * p.y;
    d  <== x2 + y2;
}

component main = Distance();
