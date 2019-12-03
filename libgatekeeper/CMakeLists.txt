set(LIBRARY_SOURCES
        src/gatekeeper.c
        src/crypto.c
        src/encoding.c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${GATEKEEPER_INCLUDE_DIRS})

add_library(gatekeeper SHARED ${LIBRARY_SOURCES})

# Define headers
target_include_directories(gatekeeper PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE src)

# Depend on a module defined in the top-level file
target_link_libraries(gatekeeper ${GATEKEEPER_LIBRARIES})

# Install to the correct locations (provided by GNUInstallDirs)
install(TARGETS gatekeeper EXPORT GatekeeperConfig
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})  # This is for Windows
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

# Make the project importable from the install directory
install(EXPORT GatekeeperConfig DESTINATION share/gatekeeper/cmake)

# Make the project importable from the build directory
export(TARGETS gatekeeper FILE GatekeeperConfig.cmake)