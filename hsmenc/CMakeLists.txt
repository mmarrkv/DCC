cmake_minimum_required(VERSION 3.19)
project(hsmenc)

set(CMAKE_CXX_STANDARD 14)

link_directories(. )

add_executable(hsmenc hsmenc.cpp)
target_link_libraries(hsmenc frclone)
