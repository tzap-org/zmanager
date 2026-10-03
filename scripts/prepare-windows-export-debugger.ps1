param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
    throw "Debugger provisioning is restricted to disposable GitHub-hosted runners"
}

# Windows SDK 10.0.26100.9457, linked by Microsoft's SDK downloads page.
# Download a debugger-only layout and administratively extract its MSI. This
# does not install an SDK, register a debugger or alter the machine's PATH.
$installerUrl = "https://go.microsoft.com/fwlink/?linkid=2382321"
$fixture = Join-Path $env:RUNNER_TEMP "zm-export-debugger-sdk"
if (Test-Path $fixture) { throw "Debugger fixture already exists: $fixture" }
New-Item -ItemType Directory $fixture | Out-Null
$installer = Join-Path $fixture "winsdksetup.exe"
Invoke-WebRequest -Uri $installerUrl -OutFile $installer

function Assert-MicrosoftSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature $Path
    if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notlike "*Microsoft Corporation*") {
        throw "Invalid Microsoft signature: $Path"
    }
}

Assert-MicrosoftSignature $installer
$layout = Join-Path $fixture "layout"
$process = Start-Process $installer -ArgumentList @(
    "/layout", "`"$layout`"", "/features", "OptionId.WindowsDesktopDebuggers", "/quiet", "/norestart"
) -Wait -PassThru
if ($process.ExitCode -ne 0) { throw "Debugger layout failed: $($process.ExitCode)" }

# This MSI includes native ARM64, x64 and x86 command-line debuggers.
$msi = Join-Path $layout "Installers\SDK Debuggers-x86_en-us.msi"
Assert-MicrosoftSignature $msi
$extracted = Join-Path $fixture "extracted"
$log = Join-Path $fixture "extract.log"
$process = Start-Process msiexec.exe -ArgumentList @(
    "/a", "`"$msi`"", "/qn", "TARGETDIR=`"$extracted`"", "/l*v", "`"$log`""
) -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Get-Content $log -Tail 30
    throw "Debugger extraction failed: $($process.ExitCode)"
}

$architecture = if ($Target -eq "aarch64-pc-windows-msvc") { "arm64" } else { "x64" }
$cdb = Join-Path $extracted "Windows Kits\10\Debuggers\$architecture\cdb.exe"
Assert-MicrosoftSignature $cdb
"ZMANAGER_TEST_CDB=$cdb" | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
"ZMANAGER_TEST_EXPORT_INTERRUPTION=1" | Out-File $env:GITHUB_ENV -Encoding utf8 -Append
Write-Host "Prepared native $architecture CDB for signed-export interruption checks"
