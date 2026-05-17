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

Do not set `VCPKG_INSTALLATION_ROOT` for this build yet. The current upstream
`libarchive2-sys` build script checks that variable but then adds an
`x64-windows` library search path. That is unsafe for native ARM64 builds.

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
cargo test --workspace
```

The important first failure to eliminate is:

```text
Unable to find libclang: couldn't find clang.dll / libclang.dll
```

That means `LIBCLANG_PATH` does not point to the LLVM `bin` directory, or LLVM
is not installed.

## Expected libarchive Build Behavior

The `libarchive2-sys` build currently:

- builds bundled libarchive through CMake;
- runs `bindgen`, which requires `libclang.dll`;
- links compression libraries by name: `zlib`, `bz2`, `lzma`, `zstd`, `lz4`,
  and `libcrypto`;
- links Windows system libraries: `bcrypt`, `advapi32`, `xmllite`, and `ole32`.

If the next Windows failure mentions missing `zlib`, `bz2`, `lzma`, `zstd`,
`lz4`, or `libcrypto`, verify the vcpkg triplet matches the Rust target and
that the `LIB` and `INCLUDE` variables point at the same triplet.

If the next failure says an x64 object conflicts with ARM64, patch our build
dependency path before claiming Windows ARM64 support. That would indicate the
upstream `libarchive2-sys` Windows vcpkg path needs target-aware handling.

## Future GitHub Actions Plan

Use the official hosted Windows runner labels when adding CI:

- `windows-2025` or `windows-latest` for Windows x64.
- `windows-2025-vs2026` when intentionally testing the Visual Studio 2026
  image.
- `windows-11-arm` for Windows ARM64.

Start with a non-release CI job:

```yaml
windows:
  name: Windows ${{ matrix.target }}
  runs-on: ${{ matrix.runner }}
  strategy:
    fail-fast: false
    matrix:
      include:
        - runner: windows-2025
          target: x86_64-pc-windows-msvc
          triplet: x64-windows
        - runner: windows-11-arm
          target: aarch64-pc-windows-msvc
          triplet: arm64-windows
  steps:
    - uses: actions/checkout@v6
    - name: Install Rust toolchain
      shell: pwsh
      run: |
        rustup toolchain install stable --profile minimal --component clippy,rustfmt --target ${{ matrix.target }}
        rustup default stable
    - name: Install native dependencies
      shell: pwsh
      run: |
        choco install llvm -y
        git clone https://github.com/microsoft/vcpkg C:\vcpkg
        C:\vcpkg\bootstrap-vcpkg.bat
        C:\vcpkg\vcpkg.exe install zlib:${{ matrix.triplet }} bzip2:${{ matrix.triplet }} liblzma:${{ matrix.triplet }} zstd:${{ matrix.triplet }} lz4:${{ matrix.triplet }} openssl:${{ matrix.triplet }}
    - name: Test
      shell: pwsh
      env:
        LIBCLANG_PATH: C:\Program Files\LLVM\bin
        CMAKE_TOOLCHAIN_FILE: C:\vcpkg\scripts\buildsystems\vcpkg.cmake
        VCPKG_DEFAULT_TRIPLET: ${{ matrix.triplet }}
        VCPKG_TARGET_TRIPLET: ${{ matrix.triplet }}
      run: |
        $env:Path = "C:\Program Files\LLVM\bin;$env:Path"
        $env:LIB = "C:\vcpkg\installed\${{ matrix.triplet }}\lib;$env:LIB"
        $env:INCLUDE = "C:\vcpkg\installed\${{ matrix.triplet }}\include;$env:INCLUDE"
        cargo test --workspace --target ${{ matrix.target }}
```

Keep this out of release packaging until both Windows jobs are green and we
have verified the generated `zm.exe` on a real Windows shell.

## References

- GitHub-hosted runner labels: https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- Runner image contents and migrations: https://github.com/actions/runner-images
