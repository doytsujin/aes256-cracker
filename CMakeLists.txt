# Arbitrary
cmake_minimum_required(VERSION 2.8.9)
project (aescrack)

add_subdirectory(tiny-AES-c)
include_directories(tiny-AES-c)

find_package(OpenMP)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")

add_executable(aescrack main.c)
target_include_directories(aescrack PRIVATE ./tiny-AES-c)
target_link_libraries(aescrack tiny-aes)
