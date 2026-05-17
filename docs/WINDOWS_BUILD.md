# Windows Build Notes

These notes capture the current local Windows setup for `zm` and the settings
we should reuse when adding Windows jobs to GitHub Actions.

Windows support is not a release claim until this setup passes in CI. The first
target is build and test parity for the Rust CLI, then release packaging.

## Current Local Target

Frank's Windows VM is Windows on ARM using the native MSVC Rust host:

```text
host: aarch64-pc-windows-msvc
```

That proves the ARM64 path first. For x64 Windows validation, repeat the same
dependency layout with the x64 Rust toolchain and `x64-windows` vcpkg triplet.

Observed local baseline:

```text
rustc 1.95.0
cargo 1.95.0
Rust host: aarch64-pc-windows-msvc
CMake 4.3.2 from Kitware
Visual Studio Community 2026
MSBuild 18.6.3
MSVC 19.51.36243.0
MSVC tool path: VC\Tools\MSVC\14.51.36231\bin\Hostx64\arm64\cl.exe
Windows SDK selected by CMake: 10.0.26100.0
```

## Required Tools

- Rust stable with the MSVC target being tested.
- Visual Studio C++ toolchain with the MSVC compiler and Windows 11 SDK.
- Visual Studio 2026 Community is acceptable when the C++ toolchain and SDK are
  installed; a separate Visual Studio 2022 Build Tools install is not required.
- Kitware CMake is acceptable; the Microsoft bundled CMake component is not
  required when `cmake --version` already works.
- LLVM for `libclang.dll`; this is required by `bindgen`.
- vcpkg for native compression libraries used by the libarchive build.

In Visual Studio Installer, install these components for the ARM64 VM:

- MSVC C++ compiler and build tools for ARM64.
- Windows 11 SDK.
- The latest MSVC toolset available in the installed Visual Studio channel.

For an x64 validation machine, install the x64/x86 MSVC tools instead of, or in
addition to, ARM64.

Install LLVM:

```bat
winget install LLVM.LLVM
```

Install vcpkg:

```bat
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
```

Install ARM64 dependencies:

```bat
C:\vcpkg\vcpkg.exe install zlib:arm64-windows bzip2:arm64-windows liblzma:arm64-windows zstd:arm64-windows lz4:arm64-windows openssl:arm64-windows
```

Install x64 dependencies for an x64 build:

```bat
C:\vcpkg\vcpkg.exe install zlib:x64-windows bzip2:x64-windows liblzma:x64-windows zstd:x64-windows lz4:x64-windows openssl:x64-windows
```

## ARM64 Environment

Use these variables for the native ARM64 Windows build:

```bat
set LIBCLANG_PATH=C:\Program Files\LLVM\bin
set PATH=C:\Program Files\LLVM\bin;%PATH%

set CMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
set VCPKG_DEFAULT_TRIPLET=arm64-windows
set VCPKG_TARGET_TRIPLET=arm64-windows
set LIB=C:\vcpkg\installed\arm64-windows\lib;%LIB%
set INCLUDE=C:\vcpkg\installed\arm64-windows\include;%INCLUDE%
```

Use the vendored `libarchive2-sys` patch command below when
`VCPKG_INSTALLATION_ROOT` is set. The upstream `libarchive2-sys` `0.2.0` build
script checks that variable but then adds an `x64-windows` library search path,
which is unsafe for native ARM64 builds.

## x64 Environment

Use this variant for Windows x64:

```bat
set LIBCLANG_PATH=C:\Program Files\LLVM\bin
set PATH=C:\Program Files\LLVM\bin;%PATH%

set CMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
set VCPKG_DEFAULT_TRIPLET=x64-windows
set VCPKG_TARGET_TRIPLET=x64-windows
set LIB=C:\vcpkg\installed\x64-windows\lib;%LIB%
set INCLUDE=C:\vcpkg\installed\x64-windows\include;%INCLUDE%
```

## Build Commands

After changing LLVM, vcpkg, or triplet settings, clear the native libarchive
build output first:

```bat
cd C:\Users\frankzhu\Projects\zmanager
cargo clean -p libarchive2-sys
cargo test --config "patch.crates-io.libarchive2-sys.path='vendor/rust/libarchive2-sys'" --workspace
```

The important first failure to eliminate is:

```text
Unable to find libclang: couldn't find clang.dll / libclang.dll
```

That means `LIBCLANG_PATH` does not point to the LLVM `bin` directory, or LLVM
is not installed.

If the build then fails while linking `zmanager-unrar` with unresolved symbols
such as `WinNT`, `IsWindows11OrGreater`, `MarkOfTheWeb`, registry APIs,
`SHGetPathFromIDListW`, token APIs, or `CryptAcquireContextW`, clean and rebuild
after pulling the fix that added the Windows-only UnRAR source files and system
libraries:

```bat
cargo clean -p zmanager-unrar
cargo test --config "patch.crates-io.libarchive2-sys.path='vendor/rust/libarchive2-sys'" --workspace
```

If CMake fails while configuring vendored libarchive with:

```text
libarchive/build/cmake/config.h.in does not exist
```

the checkout is missing a required libarchive CMake template. Pull the commit
that force-tracks the ignored upstream template, then verify it exists:

```bat
dir vendor\rust\libarchive2-sys\libarchive\build\cmake\config.h.in
```

If `libarchive2-sys` builds `archive.lib` successfully and then bindgen fails
with:

```text
libarchive/libarchive\archive.h:39:10: fatal error: 'sys/stat.h' file not found
```

the MSVC environment is present for CMake, but libclang is not seeing the same
MSVC/UCRT include directories while generating Rust bindings. Windows builds use
Z-Manager's vendored `libarchive2-sys` patch through Cargo's `--config` option
because upstream `0.2.0` treats every Windows build as
`x86_64-pc-windows-gnu` during bindgen. The local patch uses the actual MSVC
target, reads the Visual Studio include paths from `INCLUDE`, and keeps the
vcpkg library path target-aware. The patch is not enabled from `Cargo.toml` so
macOS and Linux continue to use the registry dependency graph that Homebrew and
Linux package manager testing already validate.

## Expected libarchive Build Behavior

The `libarchive2-sys` build currently:

- builds bundled libarchive through CMake;
- runs `bindgen`, which requires `libclang.dll`;
- uses the actual Windows MSVC target for bindgen instead of a hard-coded GNU
  target;
- imports MSVC and Windows SDK include directories from `INCLUDE`;
- links compression libraries by name: `z`, `bz2`, `lzma`, `zstd`, `lz4`,
  and `libcrypto`;
- links Windows system libraries: `bcrypt`, `advapi32`, `xmllite`, and `ole32`.

If the next Windows failure mentions missing `zlib`, `bz2`, `lzma`, `zstd`,
`lz4`, or `libcrypto`, verify the vcpkg triplet matches the Rust target and
that the `LIB` and `INCLUDE` variables point at the same triplet.

If the next failure says an x64 object conflicts with ARM64, patch our build
dependency path before claiming Windows ARM64 support. That would indicate the
upstream `libarchive2-sys` Windows vcpkg path needs target-aware handling.

## Expected UnRAR Build Behavior

The `zmanager-unrar` build keeps `vendor/unrar` close to upstream and compiles
copied sources from Cargo's build output directory. On Windows it must include
the extra upstream Windows sources used by the Visual Studio project:

- `isnt.cpp` for Windows version helpers such as `WinNT`.
- `motw.cpp` for Mark-of-the-Web support.

The build script also links Windows system libraries required by the upstream
Windows code path:

- `advapi32` for registry, token, security, LSA, and CryptoAPI calls.
- `shell32` for shell folder and shell execution APIs.
- `shlwapi`, `powrprof`, and `psapi` to match the libraries requested by
  upstream Windows headers.

## GitHub Actions Plan

Use the official hosted Windows runner labels when adding CI:

- `windows-2025` or `windows-latest` for Windows x64.
- `windows-2025-vs2026` when intentionally testing the Visual Studio 2026
  image.
- `windows-11-arm` for Windows ARM64.

Windows CI is wired through `scripts/ci-windows.ps1`. The script:

- initializes the Visual Studio developer environment with `vcvarsall.bat`;
- installs or locates LLVM for `libclang.dll`;
- installs vcpkg compression dependencies for the requested triplet;
- sets `LIBCLANG_PATH`, `CMAKE_TOOLCHAIN_FILE`, `VCPKG_*`, `LIB`, and
  `INCLUDE`;
- runs `cargo test --config patch.crates-io.libarchive2-sys.path=... --workspace --target <target>`
  so the Windows-only `libarchive2-sys` bindgen fix does not affect macOS or
  Linux jobs.

The CI matrix is:

```yaml
windows-test:
  name: ${{ matrix.name }}
  runs-on: ${{ matrix.runner }}
  strategy:
    fail-fast: false
    matrix:
      include:
        - name: Windows x64
          runner: windows-2025
          target: x86_64-pc-windows-msvc
          triplet: x64-windows
        - name: Windows ARM64
          runner: windows-11-arm
          target: aarch64-pc-windows-msvc
          triplet: arm64-windows
```

Keep this out of release packaging until both Windows jobs are green and we
have verified the generated `zm.exe` on a real Windows shell.

## References

- GitHub-hosted runner labels: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- Runner image contents and migrations: https://github.com/actions/runner-images
