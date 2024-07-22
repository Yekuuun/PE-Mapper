cmake_minimum_required(VERSION 3.10)
project(pe-mapper)

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
set(SOURCES
        src/main.cpp
        src/mapper.cpp
)

include_directories(${INCLUDE_DIR})

file(GLOB SOURCES "${SRC_DIR}/*.cpp")

add_executable(pe-mapper ${SOURCES})

set_target_properties(pe-mapper PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/../build)