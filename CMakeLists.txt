cmake_minimum_required(VERSION 3.0)
project(Pitt_ECE_2162_Spectre C)

set(CMAKE_C_STANDARD 99)

add_executable(test src/test.c src/memory_function.h src/helper_functions.h)
add_executable(spectre_main src/main.c src/memory_function.h src/helper_functions.h)
add_executable(spectre_github src/spectre_github.c src/memory_function.h src/helper_functions.h)
