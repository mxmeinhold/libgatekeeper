cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(libgatekeeper C)

# Version Information
set(VERSION_MAJOR "0")
set(VERSION_MINOR "1")
set(VERSION_PATCH "0")

set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

set(PACKAGE_NAME "libgatekeeper")
set(PACKAGE_VERSION ${VERSION})
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")

set(CMAKE_C_STANDARD 99)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

# Library install locations for all platforms
include(GNUInstallDirs)

# Required modules
find_package(LibNfc REQUIRED)
find_package(LibFreefare REQUIRED)
find_package(UUID REQUIRED)
find_package(OpenSSL REQUIRED)

set(GATEKEEPER_LIBRARIES
        ${LIBNFC_LIBRARIES}
        ${LIBFREEFARE_LIBRARIES}
        ${UUID_LIBRARIES}
        ${OPENSSL_LIBRARIES})

set(GATEKEEPER_INCLUDE_DIRS
        ${LIBNFC_INCLUDE_DIR}
        ${LIBFREEFARE_INCLUDE_DIR}
        ${UUID_INCLUDE_DIR}
        ${OPENSSL_INCLUDE_DIR})

# Library
add_subdirectory(libgatekeeper)

# Examples
add_subdirectory(examples)