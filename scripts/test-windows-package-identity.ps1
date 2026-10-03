param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc")]
    [string]$Target
)

$ErrorActionPreference = "Stop"
if (-not $env:ZMANAGER_AUDIT_BINARY) { throw "An unpacked, checksum-verified package is required" }
if (-not $env:ZMANAGER_TEST_CDB -or $env:ZMANAGER_TEST_EXPORT_INTERRUPTION -ne "1") {
    throw "Native signed-export interruption coverage is required"
}
$env:ZMANAGER_TEST_EXPORT_DISK_FULL = "1"
& (Join-Path $PSScriptRoot "test-windows-network-denial.ps1") `
    -Binaries @($env:ZMANAGER_AUDIT_BINARY) `
    -TestCommand @(
        "cargo", "test", "--offline", "--locked", "--release", "--target", $Target,
        "-p", "zmanager-cli", "--no-default-features", "--test", "offline_tzap_cli", "--", "--nocapture"
    )
