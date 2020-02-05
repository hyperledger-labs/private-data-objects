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
# Interpreter
################################################################################

if(NOT UNTRUSTED_ONLY)
    FILE(GLOB PROJECT_HEADERS *.h)
    FILE(GLOB PROJECT_SOURCES *.cpp)

    PROJECT(pdo_contracts CXX)

    ADD_LIBRARY(${PROJECT_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})

    TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE ${DEBUG_FLAGS} -fpic -Wno-write-strings -std=c++11)
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE "-nostdinc")
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE "-nostdinc++")
    TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE "-fno-builtin-printf")

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PRIVATE ".." "../state" "../crypto")
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC ${SGX_SSL}/include)

    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC "${SGX_SDK}/include")
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC "${SGX_SDK}/include/tlibc")
    TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PUBLIC "${SGX_SDK}/include/libcxx")
endif()

################################################################################
# Interpreter subdirectories
################################################################################

IF ($ENV{PDO_INTERPRETER} STREQUAL "gipsy")
  ADD_DEFINITIONS(-DUSE_GIPSY_INTERPRETER)
  ADD_SUBDIRECTORY (gipsy_scheme)
ELSEIF ($ENV{PDO_INTERPRETER} STREQUAL "wawaka")
  ADD_DEFINITIONS(-DUSE_WAWAKA_INTERPRETER)
  ADD_SUBDIRECTORY (wawaka_wasm)
ELSE()
  MESSAGE(FATAL_ERROR "Unknown PDO_INTERPRETER, $ENV{PDO_INTERPRETER}!")
ENDIF()
