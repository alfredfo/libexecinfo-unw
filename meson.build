project('execinfo', 'c', version : '1.0.1')

pkg = import('pkgconfig')
prog_python = import('python').find_installation('python3')

dep_unwind = dependency('libunwind', required: true)

execinfo = library('execinfo', 'execinfo.c',
                   dependencies : [ dep_unwind ],
                   version: meson.project_version(),
                   install : true)

install_headers('execinfo.h')

pkg.generate(execinfo, description : 'Standalone implementation of glibc\'s execinfo using libunwind')
