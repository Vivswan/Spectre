cmake_minimum_required(VERSION 3.0)
project(Pitt_ECE_2162_Spectre C)

set(CMAKE_C_STANDARD 99)

add_executable(test test.c)
add_executable(spectre_main main.c)
add_executable(spectre_github spectre_github.c)
