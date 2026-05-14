pragma circom 2.0.0;

// Signal-kind coverage exercise: declares each of Circom's three signal
// kinds (input / intermediate / output) inside one template body.  The
// recorder must surface every signal with the right kind so a debugger
// can distinguish witness inputs (set externally before evaluation),
// intermediate computations (visible only inside the witness), and
// output signals (fed back into the parent's env).
//
// Computation:
//   x            = 0  (input defaults to 0; recorder-supplied default)
//   internal_sum = x + x   = 0
//   y            = internal_sum * 2 = 0
//
// The fact that x defaults to 0 doesn't reduce the test's value: the
// structured evaluator must still walk every declaration and surface
// every assignment with its decoded i64 value.  The intermediate signal
// `internal_sum` is the canonical "should not be optimised away" case
// — it's allocated, written, and read back as a non-input/non-output
// witness slot.
template Mixed() {
    signal input x;
    signal internal_sum;
    signal output y;

    internal_sum <== x + x;
    y <== internal_sum * 2;
}

component main = Mixed();
