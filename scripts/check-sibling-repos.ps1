[CmdletBinding(PositionalBinding = $false)]
param([switch]$Fetch, [switch]$Strict, [string]$ParentDir = "")
$ErrorActionPreference = "Stop"
if ($ParentDir) { $env:ZMANAGER_SIBLING_PARENT_DIR = [System.IO.Path]::GetFullPath($ParentDir) }
$bashCommand = Get-Command bash.exe -ErrorAction SilentlyContinue
if (-not $bashCommand) { $bashCommand = Get-Command bash -ErrorAction SilentlyContinue }
if (-not $bashCommand) { foreach ($candidate in @("C:\Program Files\Git\bin\bash.exe", "C:\Program Files\Git\usr\bin\bash.exe")) { if (Test-Path $candidate) { $bashCommand = [pscustomobject]@{ Source = $candidate }; break } } }
if (-not $bashCommand) { throw "Git Bash is required to inspect sibling repositories." }
$script = Join-Path $PSScriptRoot "check-sibling-repos.sh"
$arguments = @($script)
if ($Fetch) { $arguments += "--fetch" }; if ($Strict) { $arguments += "--strict" }
& $bashCommand.Source @arguments
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
