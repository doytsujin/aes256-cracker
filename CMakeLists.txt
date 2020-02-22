# Arbitrary
cmake_minimum_required(VERSION 3.16.4)
project (aescrack LANGUAGES C CUDA)

add_subdirectory(tiny-AES-c)
include_directories(tiny-AES-c)

find_package(OpenMP REQUIRED)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")

add_executable(aescrack_mp main.c)
target_include_directories(aescrack_mp PRIVATE ./tiny-AES-c)
target_compile_definitions(aescrack_mp PUBLIC VOMP)
target_link_libraries(aescrack_mp tiny-aes)

add_executable(aescrack_cuda main.cu)
target_compile_definitions(aescrack_cuda PUBLIC VCUDA)

add_executable(aescrack_seq main.c)
target_include_directories(aescrack_seq PRIVATE ./tiny-AES-c)
target_link_libraries(aescrack_seq tiny-aes)
