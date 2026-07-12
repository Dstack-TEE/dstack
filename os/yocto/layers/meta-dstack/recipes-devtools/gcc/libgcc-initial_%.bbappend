python dstack_stub_stdio() {
    import os
    staging_incdir = d.getVar('STAGING_INCDIR')
    stdio = os.path.join(staging_incdir, 'stdio.h')
    if not os.path.exists(stdio):
        bb.note("Adding minimal stdio.h stub to satisfy libgcc-initial configure")
        with open(stdio, 'w') as fh:
            fh.write('#ifndef __YOCTO_DUMMY_STDIO__\n')
            fh.write('#define __YOCTO_DUMMY_STDIO__\n')
            fh.write('typedef int FILE;\n')
            fh.write('extern FILE *stdin;\n')
            fh.write('extern FILE *stdout;\n')
            fh.write('extern FILE *stderr;\n')
            fh.write('static inline int printf(const char *fmt, ...) { (void)fmt; return 0; }\n')
            fh.write('#endif\n')
}

do_configure[prefuncs] += "dstack_stub_stdio"
DEBUG_FLAGS = ""
