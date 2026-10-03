param(
    [Parameter(Mandatory = $true)]
    [string[]]$Binaries,
    [Parameter(Mandatory = $true)]
    [string[]]$TestCommand
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The network-denial test requires an administrator session."
}
if ($PSVersionTable.PSEdition -ne "Desktop") {
    throw "Run this harness with Windows PowerShell for the .NET Framework probe compiler."
}

$profiles = @(Get-NetFirewallProfile)
$disabledProfiles = @($profiles | Where-Object { $_.Enabled -ne "True" })
if ($disabledProfiles.Count -gt 0 -and
    -not ($env:GITHUB_ACTIONS -eq "true" -and $env:RUNNER_ENVIRONMENT -eq "github-hosted")) {
    throw "Refusing to enable disabled firewall profiles outside a disposable GitHub-hosted runner."
}
$binaryPaths = @($Binaries | ForEach-Object { (Resolve-Path $_).Path } | Select-Object -Unique)
$fixture = Join-Path ([IO.Path]::GetTempPath()) ("zm-network-denial-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $fixture | Out-Null
$backups = @{}
$rules = @()
$cleanupErrors = @()
try {
    $probe = Join-Path $fixture "probe.exe"
    Add-Type -Path (Join-Path $PSScriptRoot "windows-network-probe.cs") -OutputAssembly $probe -OutputType ConsoleApplication
    # Only a TCP handshake to staging: no hosted-service request or credentials.
    $address = [Net.Dns]::GetHostAddresses("staging.tzap.org") |
        Where-Object { $_.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork } |
        Select-Object -First 1
    if (-not $address) { throw "Staging has no IPv4 address for the positive-control probe." }
    foreach ($profile in $disabledProfiles) {
        Set-NetFirewallProfile -Name $profile.Name -Enabled True
    }
    foreach ($binary in $binaryPaths) {
        $backup = Join-Path $fixture ([Guid]::NewGuid().ToString() + ".exe")
        Copy-Item $binary $backup
        $backups[$binary] = $backup
        $originalHash = (Get-FileHash $binary -Algorithm SHA256).Hash
        # Probe each exact executable path; the rule stays at that path after
        # restoring the actual CLI, including its compatibility entry point.
        Copy-Item $probe $binary -Force
        & $binary $address.IPAddressToString
        if ($LASTEXITCODE -ne 0) { throw "Positive-control TCP connection failed for $binary." }
        $ruleName = "ZManagerOfflineFixture-" + [Guid]::NewGuid()
        $rule = New-NetFirewallRule -Name $ruleName -DisplayName $ruleName -Direction Outbound -Action Block `
            -Profile Any -Program $binary -Enabled True
        $rules += $rule
        & $binary $address.IPAddressToString
        if ($LASTEXITCODE -ne 42) { throw "The firewall did not reject TCP with WSAEACCES for $binary." }
        Copy-Item $backup $binary -Force
        if ((Get-FileHash $binary -Algorithm SHA256).Hash -ne $originalHash) {
            throw "The original executable was not restored exactly: $binary."
        }
        Write-Host "PASS: positive control and enforced outbound denial for $binary"
    }
    $executable = $TestCommand[0]
    $arguments = @($TestCommand | Select-Object -Skip 1)
    & $executable @arguments
    if ($LASTEXITCODE -ne 0) { throw "Offline CLI tests failed with network denied." }
} finally {
    # Attempt every cleanup even if one operation fails; never delete backups
    # when a restored executable could not be verified.
    foreach ($binary in $backups.Keys) {
        try {
            Copy-Item $backups[$binary] $binary -Force
            if ((Get-FileHash $binary).Hash -ne (Get-FileHash $backups[$binary]).Hash) {
                throw "Restored executable checksum mismatch: $binary"
            }
        } catch { $cleanupErrors += $_.Exception.Message }
    }
    foreach ($rule in $rules) {
        try {
            $instanceId = [string]$rule.InstanceID
            $remainingRules = @(
                Get-NetFirewallRule |
                    Where-Object { [string]$_.InstanceID -eq $instanceId }
            )
            if ($remainingRules.Count -gt 0) {
                Remove-NetFirewallRule -InputObject $remainingRules -ErrorAction Stop
            }
            $remainingRules = @(
                Get-NetFirewallRule |
                    Where-Object { [string]$_.InstanceID -eq $instanceId }
            )
            if ($remainingRules.Count -gt 0) {
                throw "Fixture firewall rule was not removed: $($rule.Name)"
            }
        } catch { $cleanupErrors += $_.Exception.Message }
    }
    foreach ($profile in $disabledProfiles) {
        try {
            Set-NetFirewallProfile -Name $profile.Name -Enabled $profile.Enabled
            if ((Get-NetFirewallProfile -Name $profile.Name).Enabled -ne $profile.Enabled) {
                throw "Firewall profile was not restored: $($profile.Name)"
            }
        } catch { $cleanupErrors += $_.Exception.Message }
    }
    if ($cleanupErrors.Count -gt 0) {
        throw ("Network fixture cleanup failed; backups retained at ${fixture}: " + ($cleanupErrors -join "; "))
    }
    Remove-Item $fixture -Recurse -Force
}
