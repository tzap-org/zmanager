# Z-Manager libarchive2-sys Patches

This directory vendors `libarchive2-sys` 0.2.0 from crates.io.

The local build-script patch is intentionally narrow:

- native Windows MSVC bindgen uses the actual Cargo target instead of the
  upstream hard-coded `x86_64-pc-windows-gnu` target;
- bindgen receives Visual Studio and Windows SDK include directories from the
  `INCLUDE` environment initialized by `vcvarsall.bat`;
- vcpkg library search uses `VCPKG_TARGET_TRIPLET` or `VCPKG_DEFAULT_TRIPLET`
  instead of assuming `x64-windows`;
- MSVC zlib linking uses vcpkg's `z.lib` name.

The vendored libarchive CMake templates are part of the source payload. Some
of them match upstream libarchive ignore patterns, so verify they are tracked
when refreshing this directory.

Do not edit bundled libarchive C sources here unless the change is required for
Z-Manager and has been documented in this file. Prefer upstreaming build-script
fixes and removing this vendor patch when a compatible `libarchive2-sys`
release is available.
