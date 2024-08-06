$cwd = Get-Location | Select-Object -ExpandProperty Path
$env:INCLUDE += ";$cwd"
$env:LIB += ";$cwd\build"

# These three are the default paths, change if necessary
$env:INCLUDE += ";C:\Python312\include\"
$env:INCLUDE += ";C:\Program Files\OpenSSL-Win64\include\"
$env:LIB += ";C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT\"

# Got to get your hands dirty to set this
$env:LIB += ";$(p -o cbase)\zlib\"
