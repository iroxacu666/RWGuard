cmake_minimum_required(VERSION 3.20)
project(RWGuard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(RWGuard WIN32
    src/main.cpp
    src/scanner.cpp
    src/scanner.h
    res/resource.h
)

target_compile_options(RWGuard PRIVATE /utf-8)
target_link_libraries(RWGuard PRIVATE comctl32 shlwapi uxtheme)
