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

################################################################################
# Configure Environment
################################################################################


################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################

FILE(GLOB PROJECT_HEADERS *.h packages/init-package.h packages/catch-package.h packages/oops-package.h packages/dispatch-package.h)
FILE(GLOB PROJECT_SOURCES *.cpp)

SET(GENERIC_CXX_FLAGS ${DEBUG_FLAGS} "-Wall" "-fPIC" "-Wno-write-strings" "-std=c++11")

################################################################################
# Package headers compiled from scheme
################################################################################
SET(GIPSY_PACKAGE_SRC "packages/init-package.scm" "packages/catch-package.scm" "packages/oops-package.scm" "packages/dispatch-package.scm")

set_property(SOURCE GipsyInterpreter.cpp APPEND PROPERTY OBJECT_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/packages/package.h)

#################################################################################
## Trusted Static Gipsy Library
#################################################################################
IF (BUILD_TRUSTED)
  SET(GIPSY_STATIC_NAME gipsy)
  PROJECT(${GIPSY_STATIC_NAME} CXX)

  ADD_LIBRARY(${GIPSY_STATIC_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${TINYSCHEME_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${INTERP_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/packages)
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE "${SGX_SDK}/include")
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE "${SGX_SDK}/include/tlibc")
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE "${SGX_SDK}/include/libcxx")
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE "${SGX_SSL}/include")

  TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "${GENERIC_CXX_FLAGS}")
  TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "-nostdinc")
  TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "-nostdinc++")
  TARGET_COMPILE_OPTIONS(${GIPSY_STATIC_NAME} PRIVATE "-fno-builtin-printf")

  TARGET_COMPILE_DEFINITIONS(${GIPSY_STATIC_NAME} PRIVATE "-DUSE_DL=1")
ENDIF()

################################################################################
# Untrusted Shared Gipsy Library
#
# NOTE: This uses the public version of tinyscheme which is NOT included
#       in this project!
################################################################################
IF (BUILD_UNTRUSTED)
  SET(CMAKE_SHARED_LIBRARY_PREFIX "")

  SET(PCONTRACT_NAME pcontract)
  PROJECT(${PCONTRACT_NAME} CXX)

  # Only SchemeExtensions in the shared library
  ADD_LIBRARY(${PCONTRACT_NAME} SHARED ${PROJECT_HEADERS} SchemeExtensions.cpp)

  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${COMMON_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${TINYSCHEME_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/packages)
  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE "${SGX_SDK}/include")

  TARGET_COMPILE_OPTIONS(${PCONTRACT_NAME} PRIVATE "${GENERIC_CXX_FLAGS}")

  TARGET_COMPILE_DEFINITIONS(${PCONTRACT_NAME} PRIVATE "-DUSE_DL=1")
  TARGET_COMPILE_DEFINITIONS(${PCONTRACT_NAME} PRIVATE "-D_UNTRUSTED_=1")

  # Link the untrusted common library
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${U_COMMON_LIB_NAME})
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${OPENSSL_LDFLAGS})
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${BLOCK_STORE_LIB_NAME})
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${U_CRYPTO_LIB_NAME})
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} "-lssl" "-llmdb")
ENDIF()
