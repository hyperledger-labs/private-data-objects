# Copyright (C) 2019 Intel Corporation.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CMAKE_MINIMUM_REQUIRED(VERSION 3.10 FATAL_ERROR)

################################################################################
# Configure Environment
################################################################################

# Error checking on environment variables
IF (NOT DEFINED ENV{WASM_SRC})
  MESSAGE(FATAL_ERROR "WASM_SRC environment variable not defined!")
ENDIF()
SET(WASM_SRC "$ENV{WASM_SRC}")

# Make sure wasm-micro-runtime submodule has been cloned
FILE(GLOB WAMR_SUBMOD ${WASM_SRC})
LIST(LENGTH WAMR_SUBMOD SUBMOD_CONTENTS)
IF (SUBMOD_CONTENTS EQUAL 0)
  MESSAGE(FATAL_ERROR "WAMR git submodule has not been cloned. Please run `git submodule update --init` first.")
ENDIF()

# Reset default linker flags
SET (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
SET (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET
IF (NOT DEFINED WAMR_BUILD_TARGET)
  IF (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    SET (WAMR_BUILD_TARGET "X86_64")
  ELSE ()
    # Build as X86_32 by default in 32-bit platform
    SET (WAMR_BUILD_TARGET "X86_32")
  ENDIF ()
ENDIF ()

IF (NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()

# Disable AoT by default
SET (WAMR_BUILD_AOT 0)
SET (WAMR_BUILD_INTERP 1)
IF (PDO_INTERPRETER STREQUAL "wawaka-opt")
  SET (WAMR_BUILD_FAST_INTERP 1)
  ADD_DEFINITIONS (-DUSE_WAWAKA_OPT=1)
  MESSAGE(STATUS "Building wawaka in optimized INTERP mode")
ELSE()
  # Disable optimized interpreter by default
  SET (WAMR_BUILD_FAST_INTERP 0)
  MESSAGE(STATUS "Building wawaka in INTERP mode")
ENDIF()

# Disable JIT by default for all runtime modes.
SET (WAMR_BUILD_JIT 0)

IF (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  SET (WAMR_BUILD_LIBC_BUILTIN 1)
ENDIF ()

IF (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Disable libc wasi support by default
  SET (WAMR_BUILD_LIBC_WASI 0)
ENDIF ()

################################################################################

SET(IWASM_STATIC_NAME iwasm)
SET(WAWAKA_STATIC_NAME wwasm)
PROJECT(wawaka_wasm C CXX)

SET (WAMR_BUILD_PLATFORM "linux-sgx")

SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -ffunction-sections -fdata-sections \
                                     -Wall -Wno-unused-parameter -Wno-pedantic \
                                     -nostdinc -fvisibility=hidden -fpie" )

SET (WAMR_ROOT_DIR ${WASM_SRC})
SET (SHARED_DIR ${WAMR_ROOT_DIR}/core/shared)
SET (IWASM_DIR ${WAMR_ROOT_DIR}/core/iwasm)
SET (APP_FRAMEWORK_DIR ${WAMR_ROOT_DIR}/core/app-framework)

ENABLE_LANGUAGE (ASM)

#################################################################
# WAMR Library
#################################################################
# include the build config template file
INCLUDE (${WAMR_ROOT_DIR}/build-scripts/config_common.cmake)

INCLUDE (${SHARED_DIR}/platform/${WAMR_BUILD_PLATFORM}/shared_platform.cmake)
INCLUDE (${SHARED_DIR}/mem-alloc/mem_alloc.cmake)
INCLUDE (${SHARED_DIR}/utils/shared_utils.cmake)

# this picks up the libc_erro.h, this appears to be an error in WAMR in that the
# test for WASI is AFTER the attempt to include a file that is only available when
# WASI is turned on.
INCLUDE (${SHARED_DIR}/platform/common/libc-util/platform_common_libc_util.cmake)

IF (WAMR_BUILD_LIBC_BUILTIN EQUAL 1)
  INCLUDE (${IWASM_DIR}/libraries/libc-builtin/libc_builtin.cmake)
ENDIF ()
IF (WAMR_BUILD_LIBC_WASI EQUAL 1)
  INCLUDE (${IWASM_DIR}/libraries/libc-wasi/libc_wasi.cmake)
ENDIF ()

INCLUDE (${IWASM_DIR}/common/iwasm_common.cmake)

IF (WAMR_BUILD_INTERP EQUAL 1 OR WAMR_BUILD_JIT EQUAL 1)
  INCLUDE (${IWASM_DIR}/interpreter/iwasm_interp.cmake)
ENDIF ()

ADD_LIBRARY (${IWASM_STATIC_NAME}
             ${PLATFORM_SHARED_SOURCE}
             ${PLATFORM_COMMON_LIBC_UTIL_SOURCE}
             ${MEM_ALLOC_SHARED_SOURCE}
             ${UTILS_SHARED_SOURCE}
             ${LIBC_BUILTIN_SOURCE}
             ${LIBC_WASI_SOURCE}
             ${WAMR_POSIX_SOURCES}
             ${IWASM_COMMON_SOURCE}
             ${IWASM_INTERP_SOURCE}
             ${IWASM_COMPL_SOURCE}
             # this is necessary because WAMR currently does not have a definition
             # for os_is_handle_valid in the sgx_platform.c file
             ${CMAKE_CURRENT_SOURCE_DIR}/wamr_fixes.c
           )

TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${SHARED_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${IWASM_DIR}/include)

#################################################################
# Wawaka Interpreter
#################################################################
FILE(GLOB WWASM_PROJECT_HEADERS *.h)
FILE(GLOB WWASM_PROJECT_SOURCES *.cpp)

ADD_LIBRARY(${WAWAKA_STATIC_NAME}
             ${WWASM_PROJECT_HEADERS}
             ${WWASM_PROJECT_SOURCES})
SGX_PREPARE_TRUSTED(${WAWAKA_STATIC_NAME})

# Set the memory configuration for wawaka
# RUNTIME_MEM_POOL_SIZE: The WASM runtime's global memory pool size
# HEAP_SIZE: Size of the runtime's heap for dynamic allocations by a WASM module.
# STACK_SIZE: Size of the runtime's stack for executing a WASM module
# Layout: RUNTIME_MEM_POOL_SIZE > HEAP_SIZE + STACK_SIZE + padding
# The numbers below were chosen to set RUNTIME_MEM_POOL_SIZE to be about
# 1/8 of the size of the enclave heap size defined in the SGX.cmake file.
IF (NOT DEFINED PDO_MEMORY_CONFIG)
  MESSAGE(FATAL_ERROR "PDO_MEMORY_CONFIG not defined")
ENDIF()

IF (${PDO_MEMORY_CONFIG} STREQUAL "SMALL")
  MATH(EXPR WW_RUNTIME_MEM_POOL_SIZE "4 * 1024 * 1024")
  MATH(EXPR WW_STACK_SIZE "512 * 1024")
  MATH(EXPR WW_HEAP_SIZE "3 * 1024 * 1024")
ELSEIF (${PDO_MEMORY_CONFIG} STREQUAL "MEDIUM")
  MATH(EXPR WW_RUNTIME_MEM_POOL_SIZE "8 * 1024 * 1024")
  MATH(EXPR WW_STACK_SIZE "512 * 1024")
  MATH(EXPR WW_HEAP_SIZE "7 * 1024 * 1024")
ELSEIF (${PDO_MEMORY_CONFIG} STREQUAL "LARGE")
  MATH(EXPR WW_RUNTIME_MEM_POOL_SIZE "16 * 1024 * 1024")
  MATH(EXPR WW_STACK_SIZE "512 * 1024")
  MATH(EXPR WW_HEAP_SIZE "15 * 1024 * 1024")
ELSE()
  MESSAGE(FATAL_ERROR "Invalid memory size; ${PDO_MEMORY_CONFIG}")
ENDIF()

TARGET_COMPILE_DEFINITIONS(${WAWAKA_STATIC_NAME} PRIVATE RUNTIME_MEM_POOL_SIZE=${WW_RUNTIME_MEM_POOL_SIZE})
TARGET_COMPILE_DEFINITIONS(${WAWAKA_STATIC_NAME} PRIVATE HEAP_SIZE=${WW_HEAP_SIZE})
TARGET_COMPILE_DEFINITIONS(${WAWAKA_STATIC_NAME} PRIVATE STACK_SIZE=${WW_STACK_SIZE})

TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PRIVATE ${INTERPRETER_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PRIVATE ${IWASM_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PRIVATE ${SHARED_DIR}/include)

SET_TARGET_PROPERTIES(${WAWAKA_STATIC_NAME} PROPERTIES LINKER_LANGUAGE CXX)
