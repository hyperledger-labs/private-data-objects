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

CMAKE_MINIMUM_REQUIRED(VERSION 3.2 FATAL_ERROR)

################################################################################
# Configure Environment
################################################################################

# Error checking on environment variables
IF (NOT EXISTS "$ENV{WASM_SRC}")
  MESSAGE(FATAL_ERROR "WASM_SRC environment variable not defined!")
ENDIF()

# Make sure wasm-micro-runtime submodule has been cloned
file(GLOB WAMR_SUBMOD "$ENV{WASM_SRC}")
list(LENGTH WAMR_SUBMOD SUBMOD_CONTENTS)
IF (SUBMOD_CONTENTS EQUAL 0)
  # submodule directory is empty
  MESSAGE(FATAL_ERROR "WAMR git submodule has not been cloned. Please run `git submodule update --init` first.")
ENDIF()

IF (NOT DEFINED ENV{WASM_MODE})
  MESSAGE(FATAL_ERROR "WASM_MODE environment variable not defined!")
ENDIF()

SET(WASM_SRC "$ENV{WASM_SRC}")
SET(WASM_MODE "$ENV{WASM_MODE}")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  else ()
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  endif ()
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

IF (WASM_MODE STREQUAL "AOT")
  # Enable AOT.
  set (WAMR_BUILD_AOT 1)
  # Disable Interpreter for AoT mode
  set (WAMR_BUILD_INTERP 0)
  set (WAMR_BUILD_FAST_INTERP 0)
  add_definitions (-DAOT_WASM_RT=1)
  message(STATUS "Building wawaka in AOT mode")
  message(FATAL_ERROR "AoT mode is not currently implemented")
ELSE ()
  # Disable AoT by default
  set (WAMR_BUILD_AOT 0)
  set (WAMR_BUILD_INTERP 1)
  if (WASM_MODE STREQUAL "INTERP_OPT")
    set (WAMR_BUILD_FAST_INTERP 1)
    message(STATUS "Building wawaka in optimized INTERP mode")
  else()
    # Disable optimized interpreter by default
    set (WAMR_BUILD_FAST_INTERP 0)
    message(STATUS "Building wawaka in INTERP mode")
  endif()
ENDIF()

# Disable JIT by default for all runtime modes.
set (WAMR_BUILD_JIT 0)

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Disable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 0)
endif ()

SET(PDO_INCLUDE_DIRS ".")
LIST(APPEND PDO_INCLUDE_DIRS "${PDO_TOP_DIR}/common")
LIST(APPEND PDO_INCLUDE_DIRS "${PDO_TOP_DIR}/common/crypto")
LIST(APPEND PDO_INCLUDE_DIRS "${PDO_TOP_DIR}/common/state")
LIST(APPEND PDO_INCLUDE_DIRS "${PDO_TOP_DIR}/common/interpreter")

SET(SGX_INCLUDE_DIRS "${SGX_SDK}/include")
LIST(APPEND SGX_INCLUDE_DIRS "${SGX_SDK}/include/tlibc")
LIST(APPEND SGX_INCLUDE_DIRS "${SGX_SDK}/include/libcxx")

################################################################################

SET(IWASM_STATIC_NAME iwasm)
SET(WAWAKA_STATIC_NAME wwasm)
PROJECT(wawaka_wasm C CXX)

set (WAMR_BUILD_PLATFORM "linux-sgx")

set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -ffunction-sections -fdata-sections \
                                     -Wall -Wno-unused-parameter -Wno-pedantic \
                                     -nostdinc -fvisibility=hidden -fpie" )

set (WAMR_ROOT_DIR ${WASM_SRC})
set (SHARED_DIR ${WAMR_ROOT_DIR}/core/shared)
set (IWASM_DIR ${WAMR_ROOT_DIR}/core/iwasm)
set (APP_FRAMEWORK_DIR ${WAMR_ROOT_DIR}/core/app-framework)

enable_language (ASM)

#################################################################
# WAMR Library
#################################################################

# include the build config template file
include (${WAMR_ROOT_DIR}/build-scripts/config_common.cmake)

include (${SHARED_DIR}/platform/${WAMR_BUILD_PLATFORM}/shared_platform.cmake)
include (${SHARED_DIR}/mem-alloc/mem_alloc.cmake)
include (${SHARED_DIR}/utils/shared_utils.cmake)
if (WAMR_BUILD_LIBC_BUILTIN EQUAL 1)
  include (${IWASM_DIR}/libraries/libc-builtin/libc_builtin.cmake)
endif ()
if (WAMR_BUILD_LIBC_WASI EQUAL 1)
  include (${IWASM_DIR}/libraries/libc-wasi/libc_wasi.cmake)
endif ()

include (${IWASM_DIR}/common/iwasm_common.cmake)

if (WAMR_BUILD_INTERP EQUAL 1 OR WAMR_BUILD_JIT EQUAL 1)
  include (${IWASM_DIR}/interpreter/iwasm_interp.cmake)
endif ()

if (WAMR_BUILD_AOT EQUAL 1)
  include (${IWASM_DIR}/aot/iwasm_aot.cmake)
  if (WAMR_BUILD_JIT EQUAL 1)
    include (${IWASM_DIR}/compilation/iwasm_compl.cmake)
  endif ()
endif ()

add_library (${IWASM_STATIC_NAME}
             ${PLATFORM_SHARED_SOURCE}
             ${MEM_ALLOC_SHARED_SOURCE}
             ${UTILS_SHARED_SOURCE}
             ${LIBC_BUILTIN_SOURCE}
             ${LIBC_WASI_SOURCE}
             ${IWASM_COMMON_SOURCE}
             ${IWASM_INTERP_SOURCE}
             ${IWASM_AOT_SOURCE}
             ${IWASM_COMPL_SOURCE})

TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PRIVATE ".")

TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${SHARED_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${IWASM_DIR}/include)

TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${SGX_INCLUDE_DIRS})

#################################################################
# Wawaka Interpreter
#################################################################
SET(GENERIC_CXX_FLAGS ${DEBUG_FLAGS} "-Wall" "-fPIC" "-Wno-write-strings" "-std=c++11")

FILE(GLOB WWASM_PROJECT_HEADERS *.h)
FILE(GLOB WWASM_PROJECT_SOURCES *.cpp)

ADD_LIBRARY(${WAWAKA_STATIC_NAME}
             ${WWASM_PROJECT_HEADERS}
             ${WWASM_PROJECT_SOURCES})

TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PRIVATE ".")
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PRIVATE ${PDO_INCLUDE_DIRS})

TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${IWASM_DIR}/include)
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${SHARED_DIR}/include)

TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${SGX_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC "${SGX_SSL}/include")

TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "${GENERIC_CXX_FLAGS}")
#TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-fvisibility=hidden")
#TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-fpie")
TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-nostdinc")
TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-nostdinc++")
TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-fno-builtin-printf")

SET_TARGET_PROPERTIES(${WAWAKA_STATIC_NAME} PROPERTIES LINKER_LANGUAGE CXX)
