Check the git status of a repo. Intended to be integrated with
[ShellServer](https://github.com/HenriquedoVal/Shellserver/) as a Python
binding. Inspired by [Gitstatus](https://github.com/romkatv/gitstatus), but
in C and following Git for Windows directives.

## Building

### Requirements
- [Odin](http://odin-lang.org/)
- [Zlib](zlib.net)
- [OpenSSL](https://openssl.org)

### Quick start

PowerShell with MSVC loaded:
~~~
> git clone https://github.com/HenriquedoVal/wgs/
> cd wgs
> .\set_env  # modify this file to set your env
> .\build

# To run:
> .\main <path/to/git/repo>
~~~

Or change `cl` to `clang-cl` on `build.ps1` to use Clang.
