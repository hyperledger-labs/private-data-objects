# Copyright 2019 Intel Corporation
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

cmake_minimum_required (VERSION 3.5 FATAL_ERROR)

INCLUDE(contract-build.cmake)

# ---------------------------------------------
# Set up the default source list
# ---------------------------------------------
SET (WASM_SOURCE)
FILE(GLOB WAWAKA_COMMON_SOURCE ${PDO_SOURCE_ROOT}/contracts/wawaka/common/*.cpp)
FILE(GLOB WAWAKA_CONTRACT_SOURCE  ${PDO_SOURCE_ROOT}/contracts/wawaka/common/contract/*.cpp)
LIST(APPEND WASM_SOURCE ${WAWAKA_COMMON_SOURCE})
LIST(APPEND WASM_SOURCE ${WAWAKA_CONTRACT_SOURCE})
LIST(APPEND WASM_SOURCE ${PDO_SOURCE_ROOT}/common/packages/parson/parson.cpp)

# ---------------------------------------------
# Build the wawaka contract common library
# ---------------------------------------------
SET(WW_CONTRACT_COMMON_LIB ww-contract-common)

ADD_LIBRARY(${WW_CONTRACT_COMMON_LIB} STATIC ${WASM_SOURCE})

STRING(REPLACE ";" " " WASM_BUILD_OPTIONS "${WASM_BUILD_OPTIONS}")
STRING(REPLACE ";" " " WASM_LINK_OPTIONS "${WASM_LINK_OPTIONS}")
SET(CMAKE_CXX_FLAGS ${WASM_BUILD_OPTIONS} CACHE INTERNAL "")
SET(CMAKE_CXX_COMPILER_TARGET "wasm32-wasi")

TARGET_INCLUDE_DIRECTORIES(${WW_CONTRACT_COMMON_LIB} PUBLIC ${WASM_INCLUDES})
TARGET_LINK_LIBRARIES(${WW_CONTRACT_COMMON_LIB} LINK_PUBLIC ${WASM_LIBRARIES})

SET_PROPERTY(TARGET ${WW_CONTRACT_COMMON_LIB} APPEND_STRING PROPERTY LINK_FLAGS "${WASM_LINK_OPTIONS}")

# ---------------------------------------------
# Build the wawaka test contracts
# ---------------------------------------------
LIST(APPEND WASM_LIBRARIES "${PDO_SOURCE_ROOT}/contracts/wawaka/build/lib${WW_CONTRACT_COMMON_LIB}.a")

ADD_SUBDIRECTORY(mock-contract)
ADD_SUBDIRECTORY(interface-test)
ADD_SUBDIRECTORY(interpreter-test)
ADD_SUBDIRECTORY(memory-test)
ADD_SUBDIRECTORY(attestation-test)
