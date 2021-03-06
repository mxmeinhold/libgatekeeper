find_package(PkgConfig)
pkg_check_modules(PC_LIBFREEFARE QUIET libfreefare)
set(LIBFREEFARE_DEFINITIONS ${PC_LIBFREEFARE_CFLAGS_OTHER})

find_path(LIBFREEFARE_INCLUDE_DIR freefare.h
        HINTS ${PC_LIBFREEFARE_INCLUDEDIR} ${PC_LIBFREEFARE_INCLUDE_DIR}
        PATH_SUFFIXES freefare)

find_library(LIBFREEFARE_LIBRARY NAMES freefare libfreefare
        HINTS ${PC_LIBFREEFARE_LIBDIR} ${PC_LIBFREEFARE_LIBRARY_DIRS})

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBFREEFARE_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(LibFreefare DEFAULT_MSG
        LIBFREEFARE_LIBRARY LIBFREEFARE_INCLUDE_DIR)

mark_as_advanced(LIBFREEFARE_INCLUDE_DIR LIBFREEFARE_LIBRARY)

set(LIBFREEFARE_LIBRARIES ${LIBFREEFARE_LIBRARY})
set(LIBFREEFARE_INCLUDE_DIRS ${LIBFREEFARE_INCLUDE_DIR})