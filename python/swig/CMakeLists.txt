# Copyright 2023 Intel Corporation
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

OPTION(BUILD_CLIENT "Build modules for running clients without SGX" OFF)

CMAKE_MINIMUM_REQUIRED(VERSION 3.10 FATAL_ERROR)
FIND_PACKAGE(PkgConfig REQUIRED)

PROJECT(pdo-common-swig DESCRIPTION "PDO client crypto and KVS SWIG python bindings")

IF (NOT DEFINED ENV{PDO_SOURCE_ROOT})
  MESSAGE(FATAL_ERROR "PDO_SOURCE_ROOT not defined")
ENDIF()
SET(PDO_SOURCE_ROOT $ENV{PDO_SOURCE_ROOT})

LIST(APPEND CMAKE_MODULE_PATH "${PDO_SOURCE_ROOT}/common/cmake")

SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

INCLUDE(ProjectVariables)
INCLUDE(CommonVariables)

################################################################################
# SWIG setup
################################################################################

# Set cmake policies for SWIG
# Standard target names
# source: https://cmake.org/cmake/help/v3.14/policy/CMP0078.html
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.13")
  # policy introduced in CMake 3.13
  CMAKE_POLICY(SET CMP0078 NEW)
endif()

# UseSWIG takes in -module flag set in SWIG_MODULE_NAME
# source: https://cmake.org/cmake/help/v3.14/policy/CMP0086.html
if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.14")
  # policy introduced in CMake 3.14
  CMAKE_POLICY(SET CMP0086 NEW)
endif()

FIND_PACKAGE(SWIG 4.0 REQUIRED COMPONENTS python)
IF(NOT SWIG_FOUND)
  MESSAGE(FATAL_ERROR "SWIG not found")
  IF(NOT SWIG_python_FOUND)
    MESSAGE(FATAL_ERROR "SWIG Python bindings cannot be generated")
  ENDIF()
ENDIF()
INCLUDE(UseSWIG)

############################################################################
# Set up common flags
############################################################################

LIST(APPEND COMMON_SWIG_COMPILE_DEFS "_UNTRUSTED_=1")
LIST(APPEND COMMON_SWIG_COMPILE_DEFS "_CLIENT_ONLY_=1")

LIST(APPEND COMMON_SWIG_INCLUDE_DIRS ${Python3_INCLUDE_DIRS})
LIST(APPEND COMMON_SWIG_INCLUDE_DIRS ${COMMON_SOURCE_DIR})
LIST(APPEND COMMON_SWIG_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/crypto)
LIST(APPEND COMMON_SWIG_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/state)

SET(COMMON_SWIG_LIBS ${C_COMMON_LIB_NAME} ${C_CRYPTO_LIB_NAME})

SET(PDO_COMMON_PY_DIR ${PDO_SOURCE_ROOT}/python/pdo/common)

ADD_COMPILE_DEFINITIONS(${COMMON_SWIG_COMPILE_DEFS})

############################################################################
# Build both bindings modules
############################################################################
ADD_SUBDIRECTORY(crypto)
ADD_SUBDIRECTORY(key-value)