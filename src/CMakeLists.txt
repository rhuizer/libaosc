set(SOURCES dynstring.c i386_nops.c mt19937.c rand.c wrapper.c x86_ascii.c)
add_library(aosc SHARED ${SOURCES})
add_library(aosc_static STATIC ${SOURCES})
