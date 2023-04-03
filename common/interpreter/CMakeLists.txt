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
# Interpreter
################################################################################

IF (NOT BUILD_TRUSTED)
   MESSAGE(FATAL_ERROR "interpreters should build only for an enclave")
ENDIF()

FILE(GLOB PROJECT_HEADERS *.h)
FILE(GLOB PROJECT_SOURCES *.cpp)

PROJECT(${INTERPRETER_LIB_NAME} CXX)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})
SGX_PREPARE_TRUSTED(${PROJECT_NAME})

################################################################################
# Interpreter subdirectories
################################################################################

IF (PDO_INTERPRETER MATCHES "^wawaka")
  ADD_SUBDIRECTORY(wawaka_wasm)
ELSE()
  MESSAGE(FATAL_ERROR "Unknown PDO_INTERPRETER, $ENV{PDO_INTERPRETER}!")
ENDIF()
