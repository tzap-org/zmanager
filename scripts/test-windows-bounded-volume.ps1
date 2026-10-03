param(
    [Parameter(Mandatory = $true)] [string]$ImagePath,
    [Parameter(Mandatory = $true)] [string]$MountPath,
    [switch]$Detach
)

$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -or $env:RUNNER_ENVIRONMENT -ne "github-hosted") {
    throw "Virtual-disk fixtures are restricted to disposable GitHub-hosted runners."
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The bounded virtual-disk fixture requires an administrator session."
}
$ImagePath = [IO.Path]::GetFullPath($ImagePath)
$MountPath = [IO.Path]::GetFullPath($MountPath)
$fixture = Split-Path $ImagePath -Parent
$name = Split-Path $fixture -Leaf
if (($name -notlike "zm-write-failures-*" -and $name -notlike "zm-export-disk-full-*") -or
    $ImagePath -ne (Join-Path $fixture "bounded.vhd") -or
    $MountPath -ne (Join-Path $fixture "bounded volume") -or
    $ImagePath.IndexOfAny([char[]]"`r`n`"") -ge 0) {
    throw "Refusing a virtual-disk path outside the dedicated fixture."
}

if ($Detach) {
    if (Test-Path -LiteralPath $ImagePath) {
        $image = Get-DiskImage -ImagePath $ImagePath
        if ($image.Attached) {
            try {
                foreach ($partition in @($image | Get-Disk | Get-Partition)) {
                    if ($partition.AccessPaths -contains ($MountPath.TrimEnd('\') + '\')) {
                        Remove-PartitionAccessPath -DiskNumber $partition.DiskNumber -PartitionNumber $partition.PartitionNumber `
                            -AccessPath ($MountPath.TrimEnd('\') + '\')
                    }
                }
            } finally {
                Dismount-DiskImage -ImagePath $ImagePath
            }
        }
        if ((Get-DiskImage -ImagePath $ImagePath).Attached) {
            throw "Fixture VHD remained attached: $ImagePath"
        }
    }
    exit 0
}

if ((Test-Path -LiteralPath $ImagePath) -or
    -not (Test-Path -LiteralPath $MountPath -PathType Container) -or
    @(Get-ChildItem -LiteralPath $MountPath -Force).Count -ne 0) {
    throw "Fixture image must be new and its mount directory must be empty."
}
# DiskPart selects only this newly created file. No physical disk number is
# accepted from a caller, and no `noerr` permits continuing after a failure.
@(
    "create vdisk file=`"$ImagePath`" maximum=32 type=expandable",
    "select vdisk file=`"$ImagePath`"",
    "attach vdisk",
    "exit"
) | & (Join-Path $env:SystemRoot "System32\diskpart.exe")
if ($LASTEXITCODE -ne 0) { throw "Could not create and attach the fixture VHD." }
$image = Get-DiskImage -ImagePath $ImagePath
if (-not $image.Attached) { throw "Fixture VHD was not attached." }
$disks = @($image | Get-Disk)
if ($disks.Count -ne 1 -or $disks[0].Number -eq 0 -or $disks[0].Size -gt 64MB -or
    $disks[0].PartitionStyle -ne "RAW") {
    throw "Refusing to initialize anything other than the bounded new fixture VHD."
}
$disk = $disks[0]
if ($disk.IsOffline) { Set-Disk -Number $disk.Number -IsOffline $false }
Initialize-Disk -Number $disk.Number -PartitionStyle MBR
$partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize
$partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "ZManagerWriteFixture" -Confirm:$false -Force | Out-Null
Add-PartitionAccessPath -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber -AccessPath ($MountPath.TrimEnd('\') + '\')
$volume = $partition | Get-Volume
if ($volume.Size -gt 64MB -or $volume.FileSystemLabel -ne "ZManagerWriteFixture") {
    throw "Bounded fixture volume verification failed."
}
Write-Output "PASS: mounted a bounded disposable NTFS virtual disk"
