param([switch]$Release, [switch]$Python, [switch]$Odin, [switch]$All)

$ErrorActionPreference = "Stop"

if (-not (Test-path build)) {
    mkdir build > $null
}

if (-not (Test-Path build\fnmatch.lib) -or $Odin.IsPresent -or $All.IsPresent) {
    odin build fnmatch -no-bounds-check -no-entry-point -build-mode:lib -o:speed -out:build\fnmatch.lib
    if (-not $?) { return }
}

if ($Python.IsPresent -or $All.IsPresent) {
    # python .\setup.py build         # or
    # python -m build                 # or
    pip install .                     # or
    # pip install --editable .
    if (-not $?) { return }
}

$debug_args = @(
    "-DLOG_LEVEL=LOG_ERROR",
    # "-DTEST_REPOS",
    # "-fsanitize=address",
    # "-analyze",
    "-Zi"
)

$rel_args = @(
    # "-favor:INTEL64",
    # What's the flag to undef asserts?
    "-O2"
)

$gen_args = @(
    "-Femain",
    "fnmatch.lib",
    "..\main.c",
    "-link",
    "-nodefaultlib:msvcrt"
)

if ($Release.IsPresent) {
    $cl_args = $rel_args + $gen_args
} else {
    $cl_args = $debug_args + $gen_args
}

Set-Location build

cl $cl_args
if (-not $?) { 
    Set-Location ..
    return
}

Test-Path main.exe > $null
Set-Location ..

if (-not (Test-Path .\main.exe)) {
    New-Item -ItemType SymbolicLink -Target .\build\main.exe -Path .\main.exe
}
