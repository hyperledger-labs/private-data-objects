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

CMAKE_MINIMUM_REQUIRED(VERSION 3.2 FATAL_ERROR)
find_package(PkgConfig REQUIRED)

option(UNTRUSTED_ONLY "Build only untrusted components" OFF)

INCLUDE(CMakeVariables.txt)

################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################

FILE(GLOB PROJECT_HEADERS *.h cdi/*.h packages/base64/*.h packages/parson/*.h state/*.h)
FILE(GLOB PROJECT_SOURCES *.cpp cdi/*.cpp packages/base64/*.cpp packages/parson/*.cpp state/*.cpp)

SET(COMMON_PRIVATE_INCLUDE_DIRS "." "tests" "cdi" "crypto" "crypto/verify_ias_report" "packages/base64" "packages/parson" "state")
SET(COMMON_CXX_FLAGS ${DEBUG_FLAGS} "-m64" "-fvisibility=hidden" "-fpie" "-fPIC" "-fstack-protector" "-std=c++11" "-Wall")

SET(U_CRYPTO_LIB_NAME updo-crypto)
SET(T_CRYPTO_LIB_NAME tpdo-crypto)

################################################################################
# Untrusted Common Library
################################################################################

SET(UNTRUSTED_LIB_NAME updo-common)
PROJECT(${UNTRUSTED_LIB_NAME} CXX)

pkg_check_modules (OPENSSL REQUIRED openssl>=1.1.0g)

ADD_LIBRARY(${UNTRUSTED_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_GENERATED_IAS_SOURCES} ${PROJECT_SOURCES})

TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_LIB_NAME} PRIVATE ${COMMON_PRIVATE_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_LIB_NAME} PUBLIC ${SGX_SDK}/include)

TARGET_COMPILE_OPTIONS(${UNTRUSTED_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS} ${OPENSSL_CFLAGS})

TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_LIB_NAME} PRIVATE "-D_UNTRUSTED_=1")

################################################################################
# Block Store Library
################################################################################

SET(BLOCK_STORE_LIB_NAME updo-lmdb-block-store)
PROJECT(${BLOCK_STORE_LIB_NAME} CXX)

ADD_LIBRARY(${BLOCK_STORE_LIB_NAME} STATIC packages/block_store/lmdb_block_store.cpp)

TARGET_INCLUDE_DIRECTORIES(${BLOCK_STORE_LIB_NAME} PRIVATE ${COMMON_PRIVATE_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BLOCK_STORE_LIB_NAME} PUBLIC ${SGX_SDK}/include)

TARGET_COMPILE_OPTIONS(${BLOCK_STORE_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS} ${OPENSSL_CFLAGS})
TARGET_COMPILE_DEFINITIONS(${BLOCK_STORE_LIB_NAME} PRIVATE "-D_UNTRUSTED_=1")

option(BLOCK_STORE_DEBUG "Debug logging for block store operations" OFF)
if (BLOCK_STORE_DEBUG)
    TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_LIB_NAME} PRIVATE "-DBLOCK_STORE_DEBUG=1")
endif()

################################################################################
# Trusted Common Library
################################################################################

if(NOT UNTRUSTED_ONLY)
	SET(TRUSTED_LIB_NAME tpdo-common)
	PROJECT(${TRUSTED_LIB_NAME} CXX)

	ADD_LIBRARY(${TRUSTED_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_GENERATED_IAS_SOURCES} ${PROJECT_SOURCES})

	TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PRIVATE ${COMMON_PRIVATE_INCLUDE_DIRS})
	TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC ${SGX_SDK}/include)
	TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC ${SGX_SSL}/include)
	TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC ${SGX_SDK}/include/tlibc)
	TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC ${SGX_SDK}/include/libcxx)

	TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE ${COMMON_CXX_FLAGS})
	TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE -nostdinc)
	TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE -nostdinc++)
	TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE -fno-builtin-printf)

endif()


################################################################################
# Other libraries in common
################################################################################

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
link_directories(${CMAKE_BINARY_DIR})

if(NOT UNTRUSTED_ONLY)
	ADD_SUBDIRECTORY (packages/tinyscheme)
endif()
ADD_SUBDIRECTORY (interpreter)
ADD_SUBDIRECTORY (tests)
ADD_SUBDIRECTORY (crypto)
