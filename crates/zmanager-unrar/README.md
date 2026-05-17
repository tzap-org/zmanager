# zmanager-unrar Build Notes

This crate embeds the extraction-only UnRAR source from `vendor/unrar` and
exposes a small C ABI to Rust.

## Upstream Source

- Upstream mirror used for comparison: <https://github.com/pmachapman/unrar>
- Vendored version in this repository: UnRAR `7.21.1`, dated 2026-03-22 in
  `vendor/unrar/version.hpp`.
- License: `vendor/unrar/license.txt`.

Keep `vendor/unrar` as close to upstream as possible. Z-Manager integration
belongs in this crate's Rust/C++ bridge and build script.

## Local Build Patch

`build.rs` copies UnRAR `.cpp` files into Cargo's `OUT_DIR` before compiling.
For `x86_64-apple-darwin` only, it patches the copied `system.cpp` and
`rijndael.cpp` files to avoid Apple clang's `__builtin_cpu_supports` path.

Reason: the upstream Unix source uses `__builtin_cpu_supports` under
`__GNUC__`. In the Rust `cc` static-library build on macOS Intel, Apple clang
can emit references to GCC's `___cpu_model` runtime symbol, which is not
available from the Apple toolchain during the final Rust test binary link.

The patch disables optional UnRAR SSE/AES-NI autodetection for that embedded
macOS Intel build and keeps the portable code path. It does not change archive
parsing, password handling, or extraction semantics.

If upstream adds an Apple-clang-specific fix, remove the build-time patch and
return to compiling the copied files without modification.
