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

################################################################################
# Configure Environment
################################################################################

# Read environment variables
SET(SGX_SDK "$ENV{SGX_SDK}")
SET(SGX_SSL "$ENV{SGX_SSL}")

# Error checking on environment variables
if("${SGX_SDK} " STREQUAL " ")
    message(FATAL_ERROR "SGX_SDK evironment variable not defined!")
endif()
if("${SGX_SSL} " STREQUAL " ")
    message(FATAL_ERROR "SGX_SSL evironment variable not defined!")
endif()

if("$ENV{DEBUG} " STREQUAL " ")
    SET(DEBUG_FLAGS "-O2")
    message(STATUS "Compiling with optimizations (-O2). To use debug flags, set the DEBUG environment variable.")
else()
    SET(DEBUG_FLAGS "-O0" "-g")
    message(STATUS "Compiling in debug mode without optimizations (-O0 -g)")
endif()

################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################

FILE(GLOB PROJECT_HEADERS *.h crypto/*.h packages/base64/*.h packages/parson/*.h)
FILE(GLOB PROJECT_SOURCES *.cpp crypto/*.cpp packages/base64/*.cpp packages/parson/*.cpp)

SET(GENERIC_PRIVATE_INCLUDE_DIRS "." "tests" "crypto" "packages/base64" "packages/parson")
SET(GENERIC_PUBLIC_INCLUDE_DIRS "${SGX_SDK}/include")
SET(GENERIC_CXX_FLAGS ${DEBUG_FLAGS} "-m64" "-fvisibility=hidden" "-fpie" "-fPIC" "-fstack-protector" "-std=c++11" "-Wall")

pkg_check_modules (OPENSSL REQUIRED openssl>=1.1.0g)

################################################################################
# Untrusted Common Library
################################################################################

SET(UNTRUSTED_LIB_NAME updo-common)
PROJECT(${UNTRUSTED_LIB_NAME} CXX)

ADD_LIBRARY(${UNTRUSTED_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_LIB_NAME} PRIVATE ${GENERIC_PRIVATE_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_LIB_NAME} PUBLIC ${GENERIC_PUBLIC_INCLUDE_DIRS})

TARGET_COMPILE_OPTIONS(${UNTRUSTED_LIB_NAME} PRIVATE ${GENERIC_CXX_FLAGS} ${OPENSSL_CFLAGS})

TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_LIB_NAME} PRIVATE "-D_UNTRUSTED_=1")

################################################################################
# Trusted Common Library
################################################################################

SET(TRUSTED_LIB_NAME tpdo-common)
PROJECT(${TRUSTED_LIB_NAME} CXX)

ADD_LIBRARY(${TRUSTED_LIB_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PRIVATE ${GENERIC_PRIVATE_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC ${GENERIC_PUBLIC_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC "${SGX_SSL}/include")
TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC "${SGX_SDK}/include/tlibc")
TARGET_INCLUDE_DIRECTORIES(${TRUSTED_LIB_NAME} PUBLIC "${SGX_SDK}/include/libcxx")

TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE ${GENERIC_CXX_FLAGS})
TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE "-nostdinc")
TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE "-nostdinc++")
TARGET_COMPILE_OPTIONS(${TRUSTED_LIB_NAME} PRIVATE "-fno-builtin-printf")

################################################################################
# Untrusted Test Application
################################################################################

SET(UNTRUSTED_TEST_NAME utest)
PROJECT(${UNTRUSTED_TEST_NAME} CXX)

ADD_EXECUTABLE(${UNTRUSTED_TEST_NAME} tests/untrusted/TestUntrusted.cpp tests/testCrypto.cpp)

# Same compile options as untrusted library
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${GENERIC_PRIVATE_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE "tests")
TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PUBLIC ${GENERIC_PUBLIC_INCLUDE_DIRS})

TARGET_COMPILE_OPTIONS(${UNTRUSTED_TEST_NAME} PRIVATE ${GENERIC_CXX_FLAGS})

TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_TEST_NAME} PRIVATE "-D_UNTRUSTED_=1")

# Link the untrusted test application against the untrusted library and openssl
TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} ${UNTRUSTED_LIB_NAME} ${OPENSSL_LDFLAGS})

# Register this application as a test
enable_testing()
add_test(NAME ${UNTRUSTED_TEST_NAME} COMMAND env LD_LIBRARY_PATH=${OPENSSL_LIBRARY_DIRS}:${LD_LIBRARY_PATH} ./${UNTRUSTED_TEST_NAME})

################################################################################
# Run the tests automatically after building
################################################################################

SET(TEST_TARGET TestAfterBuild)
ADD_CUSTOM_TARGET(${TEST_TARGET} ALL COMMAND ctest --output-on-failure)
ADD_DEPENDENCIES(${TEST_TARGET} ${UNTRUSTED_TEST_NAME})

################################################################################
# Other libraries in common
################################################################################

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
link_directories(${CMAKE_BINARY_DIR})
IF($ENV{GIPSY_ENABLED})
ADD_SUBDIRECTORY (packages/tinyscheme)
ENDIF()
ADD_SUBDIRECTORY (interpreter)

