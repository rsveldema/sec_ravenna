cmake_minimum_required(VERSION 3.0.0)

include(CTest)
enable_testing()

set (CMAKE_CXX_STANDARD 20)


add_subdirectory(src)

add_executable(audiostreamer main.cpp)
target_link_libraries(audiostreamer PUBLIC streamer)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
