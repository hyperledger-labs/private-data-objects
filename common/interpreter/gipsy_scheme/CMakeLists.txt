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

################################################################################
# Configure Environment
################################################################################

# Read environment variables
SET(TINY_SCHEME_SRC "$ENV{TINY_SCHEME_SRC}")

# Error checking on environment variables
if("${TINY_SCHEME_SRC} " STREQUAL " ")
    message(WARNING "TINY_SCHEME_SRC environment variable not defined! Optional gipsy pcontract.so utility for building contracts will not be compiled.")
endif()

################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################

FILE(GLOB PROJECT_HEADERS *.h packages/init-package.h packages/catch-package.h packages/oops-package.h)
FILE(GLOB PROJECT_SOURCES *.cpp)

SET(GENERIC_PRIVATE_INCLUDE_DIRS "." "../../crypto" "./packages" "../.." "../../packages/tinyscheme")
SET(GENERIC_PUBLIC_INCLUDE_DIRS "${SGX_SDK}/include")
SET(GENERIC_CXX_FLAGS ${DEBUG_FLAGS} "-Wall" "-fPIC" "-Wno-write-strings" "-std=c++11")

################################################################################
# Package headers compiled from scheme
################################################################################

ADD_CUSTOM_COMMAND(OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/packages/package.h
                   COMMAND packages/build-init-package.sh
                   ARGS --package "packages/package" -- "packages/init-package.scm" "packages/catch-package.scm" "packages/oops-package.scm"
                   DEPENDS "packages/init-package.scm" "packages/catch-package.scm" "packages/oops-package.scm"
                   WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set_property(SOURCE GipsyInterpreter.cpp APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/packages/package.h)

#################################################################################
## Trusted Static Gipsy Library
#################################################################################

SET(GIPSY_STATIC_NAME gipsy)
PROJECT(${GIPSY_STATIC_NAME} CXX)

ADD_LIBRARY(${GIPSY_STATIC_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${GENERIC_PRIVATE_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE "../../packages/tinyscheme")
TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE "..")
TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PUBLIC ${GENERIC_PUBLIC_INCLUDE_DIRS})
TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PUBLIC "${SGX_SDK}/include/tlibc")
TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PUBLIC "${SGX_SDK}/include/libcxx")
TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PUBLIC "${SGX_SSL}/include")

TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "${GENERIC_CXX_FLAGS}")
TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "-nostdinc")
TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "-nostdinc++")
TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "-fno-builtin-printf")

TARGET_COMPILE_DEFINITIONS(${GIPSY_STATIC_NAME} PRIVATE "-DUSE_DL=1")

################################################################################
# Untrusted Shared Gipsy Library
#
# NOTE: This uses the public version of tinyscheme which is NOT included
#       in this project!
################################################################################

if(NOT "${TINY_SCHEME_SRC} " STREQUAL " ")
    SET(CMAKE_SHARED_LIBRARY_PREFIX "")

    SET(PCONTRACT_NAME pcontract)
    PROJECT(${PCONTRACT_NAME} CXX)

    # Only SchemeExtensions in the shared library
    ADD_LIBRARY(${PCONTRACT_NAME} SHARED ${PROJECT_HEADERS} SchemeExtensions.cpp)

    TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${GENERIC_PRIVATE_INCLUDE_DIRS})
    TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PUBLIC ${GENERIC_PUBLIC_INCLUDE_DIRS})
    TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PUBLIC ${TINY_SCHEME_SRC})

    TARGET_COMPILE_OPTIONS(${PCONTRACT_NAME} PRIVATE "${GENERIC_CXX_FLAGS}")

    TARGET_COMPILE_DEFINITIONS(${PCONTRACT_NAME} PRIVATE "-DUSE_DL=1")

    # Link the untrusted common library
    TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${UNTRUSTED_LIB_NAME} "-lcrypto" "-lssl")
endif()
