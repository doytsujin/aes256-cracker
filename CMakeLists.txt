# Arbitrary
cmake_minimum_required(VERSION 2.8.9)
project (aescrack)

add_subdirectory(tiny-AES-c)
include_directories(tiny-AES-c)

add_executable(aescrack main.c)
target_include_directories(aescrack PRIVATE ./tiny-AES-c)
target_link_libraries(aescrack tiny-aes)
