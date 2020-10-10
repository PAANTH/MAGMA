project(trial_proj)
cmake_minimum_required(VERSION 2.8)
enable_language(C ASM)

option(VER1_BOARD  "Compile firmware for board of version 1"  ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall -Werror -fdiagnostics-color=always -Wno-pointer-to-int-cast -Wno-unused-variable -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -fdiagnostics-color=always")

set(SRC_DIR           "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(INCLUDE_DIR       "${CMAKE_CURRENT_SOURCE_DIR}/inc")



file (GLOB SOURCE_LIST ${SRC_DIR}/*.c)



add_executable(${PROJECT_NAME}.elf ${SOURCE_LIST})
target_include_directories(${PROJECT_NAME}.elf PRIVATE ${INCLUDE_DIR})
if (VER1_BOARD)
  target_compile_definitions(${PROJECT_NAME}.elf PRIVATE VER1)
endif(VER1_BOARD)

