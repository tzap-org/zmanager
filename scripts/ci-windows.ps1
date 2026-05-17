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
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $true
}

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
        Write-Host "Visual Studio component $RequiredComponent was not found through vswhere; trying latest installation"
        $installationPath = & $vswhere `
            -latest `
            -products * `
            -property installationPath
    }

    if (-not $installationPath) {
        throw "Visual Studio installation was not found"
    }

    $installationPath = ($installationPath | Select-Object -First 1).Trim()

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

function Find-LibclangBin {
    $candidates = @()

    if ($env:LIBCLANG_PATH) {
        $candidates += $env:LIBCLANG_PATH
    }

    $candidates += "C:\Program Files\LLVM\bin"

    if ($env:VCToolsInstallDir) {
        $candidates += Join-Path $env:VCToolsInstallDir "Llvm\$VcArch\bin"
        $candidates += Join-Path $env:VCToolsInstallDir "Llvm\$($VcArch.ToUpperInvariant())\bin"
        $candidates += Join-Path $env:VCToolsInstallDir "Llvm\x64\bin"
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path (Join-Path $candidate "libclang.dll"))) {
            return $candidate
        }
    }

    return $null
}

function Write-GitHubFailure {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    $tail = Get-Content -Path $LogPath -Tail 80
    if ($env:GITHUB_STEP_SUMMARY) {
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "### $Title"
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value ""
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "```text"
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $tail
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value "```"
    }

    $message = $tail -join "`n"
    $message = $message.Replace("%", "%25")
    $message = $message.Replace("`r", "%0D")
    $message = $message.Replace("`n", "%0A")
    Write-Host ("::error title={0}::{1}" -f $Title, $message)
}

function Invoke-NativeLogged {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$LogName,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [string[]]$Arguments = @()
    )

    $logPath = Join-Path (Get-Location) $LogName
    $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
    & $FilePath @Arguments 2>&1 | Tee-Object -FilePath $logPath
    $status = $LASTEXITCODE
    $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference

    if ($status -ne 0) {
        Write-GitHubFailure -Title $Title -LogPath $logPath
        exit $status
    }
}

function Ensure-Llvm {
    $llvmBin = Find-LibclangBin

    if (-not $llvmBin) {
        Write-Host "Installing LLVM"
        Invoke-NativeLogged `
            -Title "LLVM install failed" `
            -LogName "winget-llvm.log" `
            -FilePath "winget" `
            -Arguments @(
                "install",
                "--id",
                "LLVM.LLVM",
                "--source",
                "winget",
                "--accept-package-agreements",
                "--accept-source-agreements",
                "--silent"
            )
    }

    $llvmBin = Find-LibclangBin
    if (-not $llvmBin) {
        throw "libclang.dll was not found"
    }

    $env:LIBCLANG_PATH = $llvmBin
    $env:Path = "$llvmBin;$env:Path"
    Write-Host "Using LLVM at $llvmBin"
}

function Ensure-Vcpkg {
    $vcpkgRoot = "C:\vcpkg"
    $vcpkg = Join-Path $vcpkgRoot "vcpkg.exe"

    if (-not (Test-Path $vcpkg)) {
        Invoke-NativeLogged `
            -Title "vcpkg clone failed" `
            -LogName "vcpkg-clone.log" `
            -FilePath "git" `
            -Arguments @("clone", "https://github.com/microsoft/vcpkg", $vcpkgRoot)
        Invoke-NativeLogged `
            -Title "vcpkg bootstrap failed" `
            -LogName "vcpkg-bootstrap.log" `
            -FilePath (Join-Path $vcpkgRoot "bootstrap-vcpkg.bat")
    }

    Invoke-NativeLogged `
        -Title "vcpkg install failed for $Triplet" `
        -LogName "vcpkg-install-$Triplet.log" `
        -FilePath $vcpkg `
        -Arguments @(
            "install",
            "zlib:$Triplet",
            "bzip2:$Triplet",
            "liblzma:$Triplet",
            "zstd:$Triplet",
            "lz4:$Triplet",
            "openssl:$Triplet"
        )

    $env:CMAKE_TOOLCHAIN_FILE = Join-Path $vcpkgRoot "scripts\buildsystems\vcpkg.cmake"
    $env:VCPKG_INSTALLATION_ROOT = $vcpkgRoot
    $env:VCPKG_DEFAULT_TRIPLET = $Triplet
    $env:VCPKG_TARGET_TRIPLET = $Triplet
    $env:LIB = "$vcpkgRoot\installed\$Triplet\lib;$env:LIB"
    $env:INCLUDE = "$vcpkgRoot\installed\$Triplet\include;$env:INCLUDE"
}

function Invoke-CargoTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetTriple
    )

    $libarchivePatch = 'patch.crates-io.libarchive2-sys.path="vendor/rust/libarchive2-sys"'
    Invoke-NativeLogged `
        -Title "cargo test failed on $TargetTriple" `
        -LogName "cargo-test-windows-$TargetTriple.log" `
        -FilePath "cargo" `
        -Arguments @("test", "--config", $libarchivePatch, "--workspace", "--target", $TargetTriple)
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

Invoke-NativeLogged `
    -Title "rustup toolchain install failed for $Target" `
    -LogName "rustup-install-$Target.log" `
    -FilePath "rustup" `
    -Arguments @("toolchain", "install", "stable", "--profile", "minimal", "--target", $Target)
Invoke-NativeLogged `
    -Title "rustup default stable failed" `
    -LogName "rustup-default.log" `
    -FilePath "rustup" `
    -Arguments @("default", "stable")

Invoke-CargoTest -TargetTriple $Target
