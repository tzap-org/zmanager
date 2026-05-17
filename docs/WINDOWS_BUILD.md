# Windows Build Notes

Windows builds use the MSVC Rust targets and the project-owned libarchive
wrapper. They do not use MinGW, bindgen, LLVM, or the former patched Rust
binding path.

## Supported Targets

| Platform | Rust target | vcpkg triplet | Runner |
| --- | --- | --- | --- |
| Windows x64 | `x86_64-pc-windows-msvc` | `x64-windows` | `windows-2025` |
| Windows ARM64 | `aarch64-pc-windows-msvc` | `arm64-windows` | `windows-11-arm` |

## Required Tools

- Rust stable with the target being tested.
- Visual Studio C++ build tools for the target architecture.
- Windows SDK.
- CMake.
- vcpkg at `C:\vcpkg`.

The libarchive wrapper builds the vendored libarchive 3.8.7 source from
`vendor/libarchive/libarchive-3.8.7`. vcpkg supplies the compression and crypto
dependencies used by that build:

```powershell
C:\vcpkg\vcpkg.exe install `
  zlib:x64-windows `
  bzip2:x64-windows `
  liblzma:x64-windows `
  zstd:x64-windows `
  lz4:x64-windows `
  openssl:x64-windows
```

Use `arm64-windows` instead of `x64-windows` for native ARM64.

## Local Validation

Run the same script used by CI from the repository root.

Windows x64:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\ci-windows.ps1 `
  -Target "x86_64-pc-windows-msvc" `
  -Triplet "x64-windows" `
  -VcArch "x64" `
  -VsComponent "Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
```

Windows ARM64:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\ci-windows.ps1 `
  -Target "aarch64-pc-windows-msvc" `
  -Triplet "arm64-windows" `
  -VcArch "arm64" `
  -VsComponent "Microsoft.VisualStudio.Component.VC.Tools.ARM64"
```

To create the release zip locally, add `-Package -OutDir dist`.

## Build Behavior

`crates/zmanager-libarchive-sys` builds libarchive 3.8.7 through CMake with a
narrow set of owned FFI declarations. The safe Rust wrapper in
`crates/zmanager-libarchive` exposes only the read/list/extract operations that
`zmanager-core` uses.

Windows builds intentionally use XmlLite and Windows CNG where possible. That
keeps the libarchive dependency boundary smaller than the former MinGW path and
avoids libxml2/iconv runtime requirements on Windows.

The release package copies vcpkg runtime DLLs from
`C:\vcpkg\installed\<triplet>\bin` beside `zm.exe`. Do not require users to
install vcpkg or Visual Studio to run a GitHub release binary.

## CI

The CI workflow covers six target goals:

- macOS Apple Silicon
- macOS Intel
- Linux x86_64
- Linux ARM64
- Windows x64 MSVC
- Windows ARM64 MSVC

Windows jobs call `scripts/ci-windows.ps1`, which:

- initializes the Visual Studio environment with `vcvarsall.bat`;
- installs the vcpkg dependencies for the requested triplet;
- sets `CMAKE_TOOLCHAIN_FILE`, `VCPKG_*`, `LIB`, `INCLUDE`, and vcpkg runtime
  paths;
- runs `cargo test --workspace --target <target>`;
- builds `zm.exe` in release mode for the same target.
