# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CMAKE_MINIMUM_REQUIRED(VERSION 3.10 FATAL_ERROR)
FIND_PACKAGE(PkgConfig REQUIRED)

OPTION(BUILD_TRUSTED "Build modules for running inside an enclave" ON)
OPTION(BUILD_UNTRUSTED "Build modules for running with SGX outside an enclave" ON)
OPTION(BUILD_CLIENT "Build modules for running clients without SGX" OFF)
OPTION(BLOCK_STORE_DEBUG "Debug logging for block store operations" OFF)

INCLUDE(CMakeVariables.txt)

################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################
################################################################################
# Block Store Library
#
# This is built separately from common because it requires the lmdb library
# to be linked to whatever binary is included. It is always built with client_only
# since it has (or should have) no dependencies on SGX. And it is built for
# all of the possible options.
################################################################################
PROJECT(${BLOCK_STORE_LIB_NAME} CXX)

ADD_LIBRARY(${BLOCK_STORE_LIB_NAME} STATIC packages/block_store/lmdb_block_store.cpp)

TARGET_INCLUDE_DIRECTORIES(${BLOCK_STORE_LIB_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})

TARGET_COMPILE_OPTIONS(${BLOCK_STORE_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS} ${OPENSSL_CFLAGS})
TARGET_COMPILE_DEFINITIONS(${BLOCK_STORE_LIB_NAME} PRIVATE "_UNTRUSTED_=1")
TARGET_COMPILE_DEFINITIONS(${BLOCK_STORE_LIB_NAME} PRIVATE "_CLIENT_ONLY_=1")

if (BLOCK_STORE_DEBUG)
    TARGET_COMPILE_DEFINITIONS(${U_COMMON_LIB_NAME} PRIVATE "-DBLOCK_STORE_DEBUG=1")
endif()

################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################
FILE(GLOB PROJECT_HEADERS *.h packages/base64/*.h packages/parson/*.h state/*.h)
FILE(GLOB PROJECT_SOURCES *.cpp packages/base64/*.cpp packages/parson/*.cpp state/*.cpp)

################################################################################
# Client Common Library
################################################################################
IF (BUILD_CLIENT)
  PROJECT(${C_COMMON_LIB_NAME} CXX)

  PKG_CHECK_MODULES (OPENSSL REQUIRED openssl>=1.1.0g)

  ADD_LIBRARY(${C_COMMON_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

  TARGET_INCLUDE_DIRECTORIES(${C_COMMON_LIB_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})

  TARGET_COMPILE_OPTIONS(${C_COMMON_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS} ${OPENSSL_CFLAGS})

  TARGET_COMPILE_DEFINITIONS(${C_COMMON_LIB_NAME} PRIVATE "_UNTRUSTED_=1")
  TARGET_COMPILE_DEFINITIONS(${C_COMMON_LIB_NAME} PRIVATE "_CLIENT_ONLY_=1")
ENDIF()

################################################################################
# Untrusted Common Library
################################################################################
IF (BUILD_UNTRUSTED)
  PROJECT(${U_COMMON_LIB_NAME} CXX)

  PKG_CHECK_MODULES (OPENSSL REQUIRED openssl>=1.1.0g)

  ADD_LIBRARY(${U_COMMON_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

  TARGET_INCLUDE_DIRECTORIES(${U_COMMON_LIB_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${U_COMMON_LIB_NAME} PRIVATE ${SGX_SDK}/include)

  TARGET_COMPILE_OPTIONS(${U_COMMON_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS} ${OPENSSL_CFLAGS})

  TARGET_COMPILE_DEFINITIONS(${U_COMMON_LIB_NAME} PRIVATE "_UNTRUSTED_=1")
ENDIF()

################################################################################
# Trusted Common Library
################################################################################
IF (BUILD_TRUSTED)
  PROJECT(${T_COMMON_LIB_NAME} CXX)

  ADD_LIBRARY(${T_COMMON_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

  TARGET_INCLUDE_DIRECTORIES(${T_COMMON_LIB_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${T_COMMON_LIB_NAME} PRIVATE ${SGX_SDK}/include)
  TARGET_INCLUDE_DIRECTORIES(${T_COMMON_LIB_NAME} PRIVATE ${SGX_SSL}/include)
  TARGET_INCLUDE_DIRECTORIES(${T_COMMON_LIB_NAME} PRIVATE ${SGX_SDK}/include/tlibc)
  TARGET_INCLUDE_DIRECTORIES(${T_COMMON_LIB_NAME} PRIVATE ${SGX_SDK}/include/libcxx)

  TARGET_COMPILE_OPTIONS(${T_COMMON_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS})
  TARGET_COMPILE_OPTIONS(${T_COMMON_LIB_NAME} PRIVATE -nostdinc)
  TARGET_COMPILE_OPTIONS(${T_COMMON_LIB_NAME} PRIVATE -nostdinc++)
  TARGET_COMPILE_OPTIONS(${T_COMMON_LIB_NAME} PRIVATE -fno-builtin-printf)
endif()

################################################################################
# Other libraries in common
################################################################################

SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
LINK_DIRECTORIES(${CMAKE_BINARY_DIR})

IF (BUILD_TRUSTED OR BUILD_UNTRUSTED)
  IF ($ENV{PDO_INTERPRETER} STREQUAL "gipsy")
       ADD_SUBDIRECTORY (packages/tinyscheme)
  ENDIF()
ENDIF()

IF (BUILD_TRUSTED)
  ADD_SUBDIRECTORY (interpreter)
ENDIF()

ADD_SUBDIRECTORY (crypto)
ADD_SUBDIRECTORY (tests)
