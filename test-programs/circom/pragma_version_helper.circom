pragma circom 2.1.0;

// Include-target helper for `pragma_version_test.circom` — declares
// its own `pragma circom 2.1.0;` header (different from the
// entrypoint's `pragma circom 2.2.2;`) so the recorder's per-file
// pragma scan surfaces both versions on the per-trace
// `pragma_versions` special event.
template Doubler() {
    signal input x;
    signal output y;

    y <== 2 * x;
}
