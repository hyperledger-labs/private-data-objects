# Copyright 2022 Intel Corporation
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

# ---------------------------------------------
# Set up the include list
# ---------------------------------------------
SET (WW_COMMON_INCLUDES)
LIST(APPEND WW_COMMON_INCLUDES ${PDO_SOURCE_ROOT}/contracts/wawaka/common)
LIST(APPEND WW_COMMON_INCLUDES ${PDO_SOURCE_ROOT}/contracts/wawaka/common/contract)
LIST(APPEND WW_COMMON_INCLUDES ${PDO_SOURCE_ROOT}/common/interpreter/wawaka_wasm)
LIST(APPEND WW_COMMON_INCLUDES ${PDO_SOURCE_ROOT}/common/packages/parson)
LIST(APPEND WW_COMMON_INCLUDES ${PDO_SOURCE_ROOT}/common/packages/base64)
LIST(APPEND WW_COMMON_INCLUDES ${PDO_SOURCE_ROOT}/common)

# ---------------------------------------------
# Set up the default source list
# ---------------------------------------------
FILE(GLOB WAWAKA_COMMON_SOURCE ${PDO_SOURCE_ROOT}/contracts/wawaka/common/*.cpp)
FILE(GLOB WAWAKA_CONTRACT_SOURCE  ${PDO_SOURCE_ROOT}/contracts/wawaka/common/contract/*.cpp)

SET (WW_COMMON_SOURCES)
LIST(APPEND WW_COMMON_SOURCES ${WAWAKA_COMMON_SOURCE})
LIST(APPEND WW_COMMON_SOURCES ${WAWAKA_CONTRACT_SOURCE})
LIST(APPEND WW_COMMON_SOURCES ${PDO_SOURCE_ROOT}/common/packages/parson/parson.cpp)

# ---------------------------------------------
# Build the wawaka contract common library
# ---------------------------------------------
SET(WW_COMMON_LIB ww_contract_common)

ADD_LIBRARY(${WW_COMMON_LIB} STATIC ${WW_COMMON_SOURCES})
TARGET_INCLUDE_DIRECTORIES(${WW_COMMON_LIB} PUBLIC ${WW_COMMON_INCLUDES})

SET_PROPERTY(TARGET ${WW_COMMON_LIB} APPEND_STRING PROPERTY COMPILE_OPTIONS "${WASM_BUILD_OPTIONS}")
SET_PROPERTY(TARGET ${WW_COMMON_LIB} APPEND_STRING PROPERTY LINK_OPTIONS "${WASM_LINK_OPTIONS}")
SET_TARGET_PROPERTIES(${WW_COMMON_LIB} PROPERTIES EXCLUDE_FROM_ALL TRUE)
