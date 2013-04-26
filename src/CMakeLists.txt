include(CheckFunctionExists)
CHECK_FUNCTION_EXISTS(sleep HAVE_SLEEP)
CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

set(SOURCES dynstring.c i386_nops.c mt19937.c rand.c wrapper.c x86_ascii.c)
add_library(aosc SHARED ${SOURCES})
add_library(aosc_static STATIC ${SOURCES})
