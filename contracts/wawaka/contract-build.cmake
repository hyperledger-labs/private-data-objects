# Copyright 2020 Intel Corporation
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

IF(NOT EXISTS $ENV{PDO_HOME})
  MESSAGE(FATAL "PDO_HOME environment variable not defined")
ENDIF()
SET(PDO_HOME "$ENV{PDO_HOME}")

IF(NOT EXISTS $ENV{PDO_SOURCE_ROOT})
  MESSAGE(FATAL "PDO_SOURCE_ROOT environment variable not defined")
ENDIF()
SET(PDO_SOURCE_ROOT $ENV{PDO_SOURCE_ROOT})
SET(WAWAKA_ROOT ${PDO_SOURCE_ROOT}/contracts/wawaka)

IF (NOT DEFINED ENV{WASM_SRC})
  MESSAGE(FATAL_ERROR "WASM_SRC environment variable not defined!")
ENDIF()
SET(WASM_SRC "$ENV{WASM_SRC}")

IF (NOT DEFINED ENV{WASM_MEM_CONFIG})
  MESSAGE(FATAL_ERROR "WASM_MEM_CONFIG environment variable not defined!")
ENDIF()
SET(WASM_MEM_CONFIG "$ENV{WASM_MEM_CONFIG}")

# this should be set by the WAMR toolchain file
IF (NOT DEFINED WASI_SDK_DIR)
  MESSAGE(FATAL_ERROR "WASM_SDK_DIR was not defined, check toolchain defines")
ENDIF()

# ---------------------------------------------
# Set up the memory configuration
# ---------------------------------------------

# LINEAR_MEMORY: Maximum size for a WASM module's linear memory (module's
# internal stack + static globals + padding); needs to be multiple of 64KB

# INTERNAL_STACK_SIZE: Size of a WASM module's internal data stack
# (part of LINEAR_MEMORY)

IF (WASM_MEM_CONFIG STREQUAL "SMALL")
  SET(INTERNAL_STACK_SIZE 24576)
  SET(LINEAR_MEMORY 65536)
  message(STATUS "Building contracts for SMALL memory configuration")
ELSEIF (WASM_MEM_CONFIG STREQUAL "LARGE")
  SET(INTERNAL_STACK_SIZE 98304)
  SET(LINEAR_MEMORY 262144)
  message(STATUS "Building contracts for LARGE memory configuration")
ELSE()
  SET(INTERNAL_STACK_SIZE 49152)
  SET(LINEAR_MEMORY 131072)
  message(STATUS "Building contracts for MEDIUM memory configuration")
ENDIF ()

# ---------------------------------------------
# Set up the compiler configuration
# ---------------------------------------------

SET(CMAKE_EXECUTABLE_SUFFIX ".wasm")
SET(CMAKE_CXX_COMPILER_TARGET "wasm32-wasi")

SET(CONTRACT_INSTALL_DIRECTORY "${PDO_HOME}/contracts")

SET(WASM_BUILD_OPTIONS)
LIST(APPEND WASM_BUILD_OPTIONS "-O3")
LIST(APPEND WASM_BUILD_OPTIONS "-fPIC")
LIST(APPEND WASM_BUILD_OPTIONS "-fno-exceptions")
LIST(APPEND WASM_BUILD_OPTIONS "-nostdlib")
LIST(APPEND WASM_BUILD_OPTIONS "-std=c++11")
LIST(APPEND WASM_BUILD_OPTIONS "-DUSE_WASI_SDK=1")

SET(WASM_LINK_OPTIONS)
LIST(APPEND WASM_LINK_OPTIONS "-Wl,--initial-memory=${LINEAR_MEMORY}")
LIST(APPEND WASM_LINK_OPTIONS "-Wl,--max-memory=${LINEAR_MEMORY}")
LIST(APPEND WASM_LINK_OPTIONS "-z stack-size=${INTERNAL_STACK_SIZE}")
LIST(APPEND WASM_LINK_OPTIONS "-Wl,--allow-undefined")

LIST(APPEND WASM_LINK_OPTIONS "-Wl,--export=ww_dispatch")
LIST(APPEND WASM_LINK_OPTIONS "-Wl,--export=ww_initialize")

# ---------------------------------------------
# Set up the library list
#
# Note that we are, by default, picking up the the c++ library
# from WASI_SDK. With the specified options, this should provide
# access to many of the functions from the standard c++ library.
# ---------------------------------------------
SET (WASM_INCLUDES)
SET (WASM_SOURCE)
SET (WASM_LIBRARIES)
LIST(APPEND WASM_LIBRARIES "${WASI_SDK_DIR}/share/wasi-sysroot/lib/wasm32-wasi/libc++.a")

# ---------------------------------------------
# Set up the default source list
# ---------------------------------------------
## -----------------------------------------------------------------
# Define the function for building contracts
#
# Intention is that the contract writer add to the WASM_BUILD_OPTIONS,
# WASM_LINK_OPTIONS, WASM_INCLUDES and WASM_LIBRARIES to add custom
# files and link options
## -----------------------------------------------------------------
FUNCTION(BUILD_CONTRACT contract)
  STRING(REPLACE ";" " " WASM_BUILD_OPTIONS "${WASM_BUILD_OPTIONS}")
  STRING(REPLACE ";" " " WASM_LINK_OPTIONS "${WASM_LINK_OPTIONS}")

  ADD_EXECUTABLE( ${contract} ${ARGN})

  SET(CMAKE_CXX_FLAGS ${WASM_BUILD_OPTIONS} CACHE INTERNAL "")
  SET(CMAKE_CXX_COMPILER_TARGET "wasm32-wasi")

  TARGET_INCLUDE_DIRECTORIES(${contract} PUBLIC ${WASM_INCLUDES})
  TARGET_LINK_LIBRARIES(${contract} LINK_PUBLIC ${WASM_LIBRARIES})

  SET(b64contract ${CMAKE_CURRENT_BINARY_DIR}/_${contract}.b64)
  ADD_CUSTOM_COMMAND(
    TARGET ${contract}
    POST_BUILD
    COMMAND base64
    ARGS -w 0 ${contract}.wasm > ${b64contract})
  SET_SOURCE_FILES_PROPERTIES(${b64contract} PROPERTIES GENERATED TRUE)
  SET_DIRECTORY_PROPERTIES(PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${b64contract})

  # this can be replaced in later versions of CMAKE with target_link_options
  SET_PROPERTY(TARGET ${contract} APPEND_STRING PROPERTY LINK_FLAGS "${WASM_LINK_OPTIONS}")
  INSTALL(FILES ${b64contract} DESTINATION ${CONTRACT_INSTALL_DIRECTORY})
ENDFUNCTION()
