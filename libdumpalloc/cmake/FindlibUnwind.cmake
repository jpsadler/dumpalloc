# Try to find libUnwind
# Once done, this will define
# libUnwind_FOUND - system has libUnwind
# libUnwind_INCLUDE_DIRS - the libunwind include directories
# libUnwind_LIBRARIES - link to these to use libunwind

include (LibFindMacros)

libfind_pkg_check_modules(libUnwind_PKGCONF libunwind)

# include dir
find_path(libUnwind_INCLUDE_DIR
	NAMES libunwind.h
	PATHS ${libUnwind_PKGCONF_INCLUDE_DIRS}
)

find_library(libUnwind_LIBRARY
	names unwind
	PATHS ${libUnwind_PKGCONF_LIBRARY_DIRS}
)

set(libUnwind_PROCESS_INCLUDES libUnwind_INCLUDE_DIR libUnwind_INCLUDE_DIRS)
set(libUnwind_PROCESS_LIBS libUnwind_LIBRARY libUnwind_LIBRARIES)
libfind_process(libUnwind)