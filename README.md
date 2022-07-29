# libexecinfo-unw
Standalone implementation of glibc's execinfo using libunwind. Based on https://github.com/resslinux/libexecinfo

Updates over resslinux/libexecinfo
* Uses meson so that a .pc file gets generated automatically.
* Doesn't require generating C source with a Python script (https://github.com/resslinux/libexecinfo/blob/master/gen.py).
* Doesn't segfault (yay).
* Includes various fixes for backtrace_symbols https://git.alpinelinux.org/aports/tree/main/libexecinfo/10-execinfo.patch.
