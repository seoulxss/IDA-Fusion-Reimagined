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
