cmake_minimum_required(VERSION 3.10.0)
project(moe-tcp VERSION 0.1.0 LANGUAGES C)

add_executable(
  moe-tcp 
  main.c
)

target_compile_options(
  moe-tcp
  PRIVATE
  -Wall
  -Wextra
  -Werror
)

