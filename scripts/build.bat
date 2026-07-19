@echo off
setlocal

rem Detect host architecture
if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set TARGET=aarch64-pc-windows-msvc
    set TRIPLET=arm64-windows-static
    set VCARCH=arm64
    set VSCOMPONENT=Microsoft.VisualStudio.Component.VC.Tools.ARM64
) else (
    set TARGET=x86_64-pc-windows-msvc
    set TRIPLET=x64-windows-static
    set VCARCH=x64
    set VSCOMPONENT=Microsoft.VisualStudio.Component.VC.Tools.x86.x64
)

powershell -ExecutionPolicy Bypass -File "%~dp0ci-windows.ps1" -Target "%TARGET%" -Triplet "%TRIPLET%" -VcArch "%VCARCH%" -VsComponent "%VSCOMPONENT%" %*
