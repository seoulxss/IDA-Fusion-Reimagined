cmake_minimum_required(VERSION 3.25)

# Needs the IDA SDK (9.x) -- point IDASDK at the checkout that contains "src/":
#   https://github.com/HexRaysSA/ida-sdk
include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")  # must come before project()

project(fusion CXX)
find_package(idasdk REQUIRED)

ida_add_plugin(fusion
    SOURCES
        main.cpp
        fusion.cpp
        pattern.cpp
)

# Headless check against a real database (needs idalib):
#   cmake -B build -G Ninja -DFUSION_BUILD_TESTS=ON
option(FUSION_BUILD_TESTS "Build the idalib based headless test" OFF)
if(FUSION_BUILD_TESTS AND EXISTS "${IDALIB_PATH}")
    ida_add_idalib(fusion_headless
        TYPE EXECUTABLE
        SOURCES
            tests/headless.cpp
            fusion.cpp
            pattern.cpp
    )
    if(WIN32)
        target_compile_definitions(fusion_headless PRIVATE NOMINMAX _CRT_SECURE_NO_WARNINGS)
        target_link_options(fusion_headless PRIVATE /STACK:0x400000)
    endif()
endif()
