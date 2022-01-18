cmake_minimum_required(VERSION 3.19)
project(hsmenc_audit)

set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-DWC_NO_HARDEN")

add_executable(hsmenc_audit main.cpp)
target_link_libraries(hsmenc_audit wolfssl)
