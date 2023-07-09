cmake_minimum_required(VERSION 3.0.0)
project(sec_rav VERSION 0.1.0 LANGUAGES C CXX)

add_definitions(-DCMAKE_EXPORT_COMPILE_COMMANDS=ON)
set( CMAKE_EXPORT_COMPILE_COMMANDS ON )

add_subdirectory(streamer)

