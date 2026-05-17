param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$Triplet,

    [Parameter(Mandatory = $true)]
    [string]$VcArch,

    [Parameter(Mandatory = $true)]
    [string]$VsComponent
)

$ErrorActionPreference = "Stop"

function Import-VisualStudioEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Architecture,

        [Parameter(Mandatory = $true)]
        [string]$RequiredComponent
    )

    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        throw "vswhere.exe was not found"
    }

    $installationPath = & $vswhere `
        -latest `
        -products * `
        -requires $RequiredComponent `
        -property installationPath

    if (-not $installationPath) {
        throw "Visual Studio installation with component $RequiredComponent was not found"
    }

    $vcvarsall = Join-Path $installationPath "VC\Auxiliary\Build\vcvarsall.bat"
    if (-not (Test-Path $vcvarsall)) {
        throw "vcvarsall.bat was not found at $vcvarsall"
    }

    Write-Host "Using Visual Studio at $installationPath"
    Write-Host "Initializing MSVC environment for $Architecture"

    $environment = cmd.exe /c "`"$vcvarsall`" $Architecture && set"
    foreach ($line in $environment) {
        if ($line -match "^([^=]+)=(.*)$") {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process")
        }
    }
}

function Ensure-Llvm {
    $llvmBin = "C:\Program Files\LLVM\bin"
    $libclang = Join-Path $llvmBin "libclang.dll"

    if (-not (Test-Path $libclang)) {
        Write-Host "Installing LLVM"
        winget install `
            --id LLVM.LLVM `
            --source winget `
            --accept-package-agreements `
            --accept-source-agreements `
            --silent
    }

    if (-not (Test-Path $libclang)) {
        throw "libclang.dll was not found at $libclang"
    }

    $env:LIBCLANG_PATH = $llvmBin
    $env:Path = "$llvmBin;$env:Path"
}

function Ensure-Vcpkg {
    $vcpkgRoot = "C:\vcpkg"
    $vcpkg = Join-Path $vcpkgRoot "vcpkg.exe"

    if (-not (Test-Path $vcpkg)) {
        git clone https://github.com/microsoft/vcpkg $vcpkgRoot
        & (Join-Path $vcpkgRoot "bootstrap-vcpkg.bat")
    }

    & $vcpkg install `
        "zlib:$Triplet" `
        "bzip2:$Triplet" `
        "liblzma:$Triplet" `
        "zstd:$Triplet" `
        "lz4:$Triplet" `
        "openssl:$Triplet"

    $env:CMAKE_TOOLCHAIN_FILE = Join-Path $vcpkgRoot "scripts\buildsystems\vcpkg.cmake"
    $env:VCPKG_INSTALLATION_ROOT = $vcpkgRoot
    $env:VCPKG_DEFAULT_TRIPLET = $Triplet
    $env:VCPKG_TARGET_TRIPLET = $Triplet
    $env:LIB = "$vcpkgRoot\installed\$Triplet\lib;$env:LIB"
    $env:INCLUDE = "$vcpkgRoot\installed\$Triplet\include;$env:INCLUDE"
}

Import-VisualStudioEnvironment -Architecture $VcArch -RequiredComponent $VsComponent
Ensure-Llvm
Ensure-Vcpkg

Write-Host "rustc:"
rustc -Vv
Write-Host "cargo:"
cargo -V
Write-Host "cmake:"
cmake --version
Write-Host "clang:"
clang --version
Write-Host "INCLUDE=$env:INCLUDE"

rustup toolchain install stable --profile minimal --target $Target
rustup default stable

cargo test --workspace --target $Target
