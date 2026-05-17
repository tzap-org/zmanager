param(
    [Parameter(Mandatory = $true)]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$Triplet,

    [Parameter(Mandatory = $true)]
    [string]$VcArch,

    [Parameter(Mandatory = $true)]
    [string]$VsComponent,

    [switch]$Package,

    [string]$OutDir = "dist"
)

$ErrorActionPreference = "Stop"
$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $PSNativeCommandUseErrorActionPreference = $false
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
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '```text'
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value $tail
        Add-Content -Path $env:GITHUB_STEP_SUMMARY -Value '```'
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
    Write-Host ("Running: " + $FilePath + " " + ($Arguments -join " "))
    if (Test-Path $logPath) {
        Remove-Item $logPath
    }

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $FilePath @Arguments 2>&1 | ForEach-Object {
            $line = $_.ToString()
            Write-Host $line
            Add-Content -Path $logPath -Value $line
        }
        $status = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }

    if ($status -ne 0) {
        Add-Content -Path $logPath -Value ("Exited with code " + $status)
        Write-GitHubFailure -Title $Title -LogPath $logPath
        exit $status
    }
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

    [Environment]::SetEnvironmentVariable(
        "CMAKE_TOOLCHAIN_FILE",
        (Join-Path $vcpkgRoot "scripts\buildsystems\vcpkg.cmake"),
        "Process"
    )
    [Environment]::SetEnvironmentVariable("VCPKG_INSTALLATION_ROOT", $vcpkgRoot, "Process")
    [Environment]::SetEnvironmentVariable("VCPKG_DEFAULT_TRIPLET", $Triplet, "Process")
    [Environment]::SetEnvironmentVariable("VCPKG_TARGET_TRIPLET", $Triplet, "Process")

    $libraryPath = Join-Path $vcpkgRoot "installed\$Triplet\lib"
    $debugLibraryPath = Join-Path $vcpkgRoot "installed\$Triplet\debug\lib"
    $runtimePath = Join-Path $vcpkgRoot "installed\$Triplet\bin"
    $debugRuntimePath = Join-Path $vcpkgRoot "installed\$Triplet\debug\bin"
    $includePath = Join-Path $vcpkgRoot "installed\$Triplet\include"
    $currentLibraryPath = [Environment]::GetEnvironmentVariable("LIB", "Process")
    $currentIncludePath = [Environment]::GetEnvironmentVariable("INCLUDE", "Process")
    [Environment]::SetEnvironmentVariable("LIB", ($debugLibraryPath + ";" + $libraryPath + ";" + $currentLibraryPath), "Process")
    [Environment]::SetEnvironmentVariable("INCLUDE", ($includePath + ";" + $currentIncludePath), "Process")

    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Process")
    [Environment]::SetEnvironmentVariable("Path", ($debugRuntimePath + ";" + $runtimePath + ";" + $currentPath), "Process")
}

function Invoke-CargoTest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetTriple
    )

    Invoke-NativeLogged `
        -Title "cargo test failed on $TargetTriple" `
        -LogName "cargo-test-windows-$TargetTriple.log" `
        -FilePath "cargo" `
        -Arguments @("test", "--workspace", "--target", $TargetTriple)
}

function Invoke-CargoBuildRelease {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetTriple
    )

    Invoke-NativeLogged `
        -Title "cargo release build failed on $TargetTriple" `
        -LogName "cargo-build-windows-$TargetTriple.log" `
        -FilePath "cargo" `
        -Arguments @("build", "--locked", "--release", "--target", $TargetTriple, "-p", "zmanager-cli", "--bin", "zm")
}

function Copy-ReleaseFiles {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetTriple,

        [Parameter(Mandatory = $true)]
        [string]$Stage
    )

    Copy-Item (Join-Path $RepositoryRoot "target\$TargetTriple\release\zm.exe") (Join-Path $Stage "zm.exe")
    Copy-Item (Join-Path $RepositoryRoot "README.md") $Stage
    Copy-Item (Join-Path $RepositoryRoot "LICENSE") $Stage
    Copy-Item (Join-Path $RepositoryRoot "THIRD_PARTY_NOTICES.md") $Stage
}

function Copy-VcpkgRuntimeDlls {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage
    )

    $runtimePath = Join-Path "C:\vcpkg" "installed\$Triplet\bin"
    if (-not (Test-Path $runtimePath)) {
        return
    }

    Get-ChildItem -Path $runtimePath -Filter "*.dll" | ForEach-Object {
        Copy-Item $_.FullName $Stage
    }
}

function New-ReleasePackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetTriple
    )

    $outRoot = Join-Path $RepositoryRoot $OutDir
    New-Item -ItemType Directory -Force -Path $outRoot | Out-Null

    $stage = Join-Path ([System.IO.Path]::GetTempPath()) ("zmanager-release-" + [System.Guid]::NewGuid())
    New-Item -ItemType Directory -Path $stage | Out-Null
    try {
        Copy-ReleaseFiles -TargetTriple $TargetTriple -Stage $stage
        Copy-VcpkgRuntimeDlls -Stage $stage

        $archive = Join-Path $outRoot ("zm-$TargetTriple.zip")
        if (Test-Path $archive) {
            Remove-Item $archive
        }
        Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $archive
        $hash = Get-FileHash -Algorithm SHA256 -Path $archive
        Set-Content -Path ($archive + ".sha256") -Value ($hash.Hash.ToLowerInvariant() + "  " + (Split-Path -Leaf $archive))
        Write-Host $archive
    } finally {
        Remove-Item -Recurse -Force $stage
    }
}

Import-VisualStudioEnvironment -Architecture $VcArch -RequiredComponent $VsComponent
Ensure-Vcpkg

Write-Host "rustc:"
rustc -Vv
Write-Host "cargo:"
cargo -V
Write-Host "cmake:"
cmake --version
Write-Host ("INCLUDE=" + [Environment]::GetEnvironmentVariable("INCLUDE", "Process"))

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

if ($Package) {
    Invoke-CargoBuildRelease -TargetTriple $Target
    New-ReleasePackage -TargetTriple $Target
} else {
    Invoke-CargoTest -TargetTriple $Target
    Invoke-CargoBuildRelease -TargetTriple $Target
}
