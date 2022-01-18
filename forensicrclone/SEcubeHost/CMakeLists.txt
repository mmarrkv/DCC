cmake_minimum_required(VERSION 3.19)
project(SEcubeHost)

set(CMAKE_CXX_STANDARD 14)

file(GLOB_RECURSE SOURCES "sources/*.*")

add_executable(SEcubeHostTestChaCha secube_testchacha.cpp ${SOURCES})

add_library(frclone SHARED frclone.cpp ${SOURCES})

add_executable(frclone_test frclone_testdriver.cpp)
target_link_libraries(frclone_test frclone)
