project('execinfo', 'c', version : '1.0.0')

# pkg = import('pkgconfig')
prog_python = import('python').find_installation('python3')

dep_unwind = dependency('libunwind-generic', required: true)#, required : true)
# deps = [ dep_unwind ]

execinfo = library('execinfo', 'execinfo.c',
                   dependencies : [dep_unwind],
                   install : true)

install_headers('execinfo.h')

#pkg.generate(execinfo,
#             description : 'Clone of the backtrace facility found in glibc implemented with libunwind')
