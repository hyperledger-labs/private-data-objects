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

# This file has been modified to accommodate changes in the way we
# build the gipsy interpreter. Specifically, that packages file is
# no longer generated automatically because of problems with the
# tinyscheme garbage collector as it runs on ubuntu 20.04. If the gipsy
# packages are changed, then package.h must be rebuilt by hand and added
# to the distribution.

################################################################################
# Common components for both trusted and untrusted common libraries
################################################################################

FILE(GLOB PROJECT_HEADERS *.h packages/package.h)
FILE(GLOB PROJECT_SOURCES *.cpp)

#################################################################################
## Trusted Static Gipsy Library
#################################################################################
IF (BUILD_TRUSTED)
  SET(GIPSY_STATIC_NAME gipsy)
  PROJECT(${GIPSY_STATIC_NAME} CXX)

  ADD_LIBRARY(${GIPSY_STATIC_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})
  SGX_PREPARE_TRUSTED(${GIPSY_STATIC_NAME})

  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${TINYSCHEME_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${INTERPRETER_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${GIPSY_STATIC_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/packages)

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
  SGX_PREPARE_UNTRUSTED(${PCONTRACT_NAME})

  TARGET_COMPILE_DEFINITIONS(${PCONTRACT_NAME} PRIVATE "USE_DL=1")
  TARGET_COMPILE_DEFINITIONS(${PCONTRACT_NAME} PRIVATE "_UNTRUSTED_=1")

  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/packages)
  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${TINYSCHEME_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${PCONTRACT_NAME} PRIVATE ${INTERPRETER_INCLUDE_DIRS})

  # Link the untrusted common library
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} "-Wl,--start-group")
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${COMMON_UNTRUSTED_LIBS})
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} ${OPENSSL_LDFLAGS})
  TARGET_LINK_LIBRARIES(${PCONTRACT_NAME} "-Wl,--end-group")

ENDIF()
