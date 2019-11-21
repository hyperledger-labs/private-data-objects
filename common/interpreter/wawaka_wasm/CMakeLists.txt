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

SET(WASM_SRC "$ENV{WASM_SRC}")

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

SET(PLATFORM "linux-sgx")

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
SET(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

ADD_DEFINITIONS(-DUSE_SGX=1)
ADD_DEFINITIONS(-DOPS_INPUT_OUTPUT=1)
ADD_DEFINITIONS(-DOPS_UNSAFE_BUFFERS=1)
ADD_DEFINITIONS(-DWASM_ENABLE_LOG=0)
ADD_DEFINITIONS(-Dbh_printf=bh_printf_sgx)
ADD_DEFINITIONS(-Dvprintf=bh_vprintf_sgx)

IF (NOT ("$ENV{VALGRIND}" STREQUAL "YES"))
  ADD_DEFINITIONS(-DNVALGRIND)
ENDIF ()

# Currently build as 64-bit by default.
IF (CMAKE_SIZEOF_VOID_P EQUAL 8)
  # Build as X86_64 by default in 64-bit platform
  SET (BUILD_TARGET "X86_64")
  ADD_DEFINITIONS(-DBUILD_TARGET_X86_64)
  SET (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")
  SET (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS} -fPIC")
ELSE ()
  # Build as X86_32 by default in 32-bit platform
  SET (BUILD_TARGET "X86_32")
  ADD_DEFINITIONS(-DBUILD_TARGET_X86_32)
  SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32")
  SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
ENDIF ()

IF (NOT DEFINED WASM_ENABLE_WASI)
  # Disable wasi support by default
  SET (WASM_ENABLE_WASI 0)
ENDIF ()

IF (WASM_ENABLE_WASI EQUAL 1)
  ADD_DEFINITIONS(-DWASM_ENABLE_WASI=1)
  ADD_DEFINITIONS(-D_GNU_SOURCE)
  MESSAGE ("-- WASI enabled")
ELSE ()
  MESSAGE ("-- WASI disabled")
ENDIF ()

IF (NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF (NOT CMAKE_BUILD_TYPE)

SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wall -Wno-unused-parameter -Wno-pedantic")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -nostdinc -fvisibility=hidden -fpie")

SET(WASM_IWASM_ROOT ${WASM_SRC}/core/iwasm)
SET(WASM_SHARED_LIB_ROOT ${WASM_SRC}/core/shared-lib)

ENABLE_LANGUAGE(ASM)

#################################################################
# Pull in all the WASM makefiles
#################################################################
INCLUDE(${WASM_IWASM_ROOT}/runtime/platform/${PLATFORM}/platform.cmake)
INCLUDE(${WASM_IWASM_ROOT}/runtime/utils/utils.cmake)
INCLUDE(${WASM_IWASM_ROOT}/runtime/vmcore-wasm/vmcore.cmake)
INCLUDE(${WASM_IWASM_ROOT}/lib/native/libc/wasmtime-wasi-c/wasi.cmake)
INCLUDE(${WASM_IWASM_ROOT}/lib/native/libc/wasm_libc.cmake)
INCLUDE(${WASM_SHARED_LIB_ROOT}/platform/${PLATFORM}/shared_platform.cmake)
INCLUDE(${WASM_SHARED_LIB_ROOT}/mem-alloc/mem_alloc.cmake)
INCLUDE(${WASM_SHARED_LIB_ROOT}/utils/shared_utils.cmake)

#################################################################
# MicroWasm Library
#################################################################
ADD_LIBRARY(${IWASM_STATIC_NAME}
             ${WASM_PLATFORM_LIB_SOURCE}
             ${WASM_UTILS_LIB_SOURCE}
             ${VMCORE_LIB_SOURCE}
             ${WASM_IWASM_ROOT}/lib/native/base/base_lib_export.c
             ${WASM_LIBC_SOURCE}
             ${PLATFORM_SHARED_SOURCE}
             ${MEM_ALLOC_SHARED_SOURCE})

TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PRIVATE ".")

TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${WASM_IWASM_ROOT}/runtime/include)
TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${WASM_IWASM_ROOT}/runtime/platform/include)
TARGET_INCLUDE_DIRECTORIES(${IWASM_STATIC_NAME} PUBLIC ${WASM_SHARED_LIB_ROOT}/include)

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

TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${WASM_IWASM_ROOT}/runtime/include)
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${WASM_IWASM_ROOT}/runtime/platform/include)
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${WASM_SHARED_LIB_ROOT}/include)

TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC ${SGX_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${WAWAKA_STATIC_NAME} PUBLIC "${SGX_SSL}/include")

TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "${GENERIC_CXX_FLAGS}")
#TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-fvisibility=hidden")
#TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-fpie")
TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-nostdinc")
TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-nostdinc++")
TARGET_COMPILE_OPTIONS(${WAWAKA_STATIC_NAME} PRIVATE "-fno-builtin-printf")

SET_TARGET_PROPERTIES(${WAWAKA_STATIC_NAME} PROPERTIES LINKER_LANGUAGE CXX)
