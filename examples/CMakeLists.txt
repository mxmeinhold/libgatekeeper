SET(EXAMPLES_SOURCES
        issue-tag
        format-tag)

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${GATEKEEPER_INCLUDE_DIRS})

# Examples
foreach (source ${EXAMPLES_SOURCES})
    add_executable(${source} ${source}.c)
    target_link_libraries(${source} gatekeeper)
    install(TARGETS ${source} RUNTIME DESTINATION bin COMPONENT examples)
endforeach (source)