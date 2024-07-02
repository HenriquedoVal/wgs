$env:INCLUDE += ";C:\Python312\include\"
$env:INCLUDE += ";C:\Program Files\OpenSSL-Win64\include\"

$env:LIB += ";$(p -o cbase)\zlib\"
$env:LIB += ";C:\Program Files\OpenSSL-Win64\lib\VC\x64\MT\"
