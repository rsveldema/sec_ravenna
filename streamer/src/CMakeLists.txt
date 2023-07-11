cmake_minimum_required(VERSION 3.0.0)

include(CTest)
enable_testing()

add_library(streamer SHARED streamer.cpp discovery.cpp)
target_link_libraries(streamer INTERFACE uring)
target_include_directories(streamer PUBLIC include)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
