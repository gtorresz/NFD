# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

from waflib import TaskGen

def options(opt):
    opt.add_option('--fuzzing', action='store_true', default=False,
                               help='Add compiler flags to enable fuzz instrumentation')
def configure(conf):
    if conf.options.fuzzing:
        conf.check_cxx(cxxflags=['-DFUZZTESTING','-fprofile-instr-generate', '-fcoverage-mapping'],
                linkflags=['-fprofile-instr-generate'], mandatory=True)
        conf.env.append_unique('CXXFLAGS', ['-DFUZZTESTING','-fprofile-instr-generate', '-fcoverage-mapping'])
        conf.env.append_unique('LINKFLAGS', ['-fprofile-instr-generate'])

