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

CMAKE_MINIMUM_REQUIRED(VERSION 3.2 FATAL_ERROR)

IF(NOT EXISTS $ENV{PDO_HOME})
  MESSAGE(FATAL "PDO_HOME environment variable not defined")
ENDIF()

SET(PDO_TOP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../")

SET(CONTRACT_EXPORTS "\"['_ww_dispatch', '_ww_initialize']\"")

SET(EMCC_BUILD_OPTIONS)
LIST(APPEND EMCC_BUILD_OPTIONS "-s WASM=1")
LIST(APPEND EMCC_BUILD_OPTIONS "-s BINARYEN_TRAP_MODE=clamp")
LIST(APPEND EMCC_BUILD_OPTIONS "-s ASSERTIONS=1")
LIST(APPEND EMCC_BUILD_OPTIONS "-s STACK_OVERFLOW_CHECK=2")
LIST(APPEND EMCC_BUILD_OPTIONS "-s SIDE_MODULE=1")

SET(EMCC_LINK_OPTIONS "${EMCC_BUILD_OPTIONS}")
LIST(APPEND EMCC_LINK_OPTIONS "-s TOTAL_MEMORY=65536")
LIST(APPEND EMCC_LINK_OPTIONS "-s TOTAL_STACK=4096")
LIST(APPEND EMCC_LINK_OPTIONS "-s EXPORTED_FUNCTIONS=${CONTRACT_EXPORTS}")

STRING(REPLACE ";" " " EMCC_BUILD_OPTIONS "${EMCC_BUILD_OPTIONS}")
STRING(REPLACE ";" " " EMCC_LINK_OPTIONS "${EMCC_LINK_OPTIONS}")

# the -O2 is actually required for the moment because it removes
# uncalled functions that clutter the wasm file
SET(CMAKE_CXX_FLAGS "-O2 -fPIC -fno-exceptions ${EMCC_BUILD_OPTIONS}")
SET(CMAKE_EXECUTABLE_SUFFIX ".wasm")

FILE(GLOB COMMON_SOURCE common/*.cpp)

SET(LIBRARY_SOURCE ${PDO_TOP_DIR}/common/packages/parson/parson.cpp)

SET(PACKAGE_INCLUDES
  ${PDO_TOP_DIR}/contracts/wawaka/common
  ${PDO_TOP_DIR}/common/interpreter/wawaka_wasm
  ${PDO_TOP_DIR}/common/packages/parson
  ${PDO_TOP_DIR}/common)

INCLUDE_DIRECTORIES(
  ${PACKAGE_INCLUDES}
  ${WASM_SRC}/core/app-framework/base/native
  ${WASM_SRC}/core/app-framework/app-native-shared/bi-inc
  ${WASM_SRC}/core/app-framework/base/app)

SET(CONTRACT_INSTALL_DIRECTORY "$ENV{PDO_HOME}/contracts")

FUNCTION(BUILD_CONTRACT contract)
  ADD_EXECUTABLE(${contract} ${ARGN} ${COMMON_SOURCE} ${LIBRARY_SOURCE} )
  SET(b64contract ${CMAKE_CURRENT_BINARY_DIR}/_${contract}.b64)
  ADD_CUSTOM_COMMAND(
    TARGET ${contract}
    POST_BUILD
    COMMAND base64
    ARGS -w 0 ${contract}.wasm > ${b64contract})
  SET_SOURCE_FILES_PROPERTIES(${b64contract} PROPERTIES GENERATED TRUE)
  SET_DIRECTORY_PROPERTIES(PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${b64contract})
  # this can be replaced in later versions of CMAKE with target_link_properties
  SET_PROPERTY(TARGET ${contract} APPEND_STRING PROPERTY LINK_FLAGS "${EMCC_LINK_OPTIONS}")
  INSTALL(FILES ${b64contract} DESTINATION ${CONTRACT_INSTALL_DIRECTORY})
ENDFUNCTION()

FUNCTION(BUILD_AOT_CONTRACT contract)
  ADD_EXECUTABLE(${contract} ${ARGN} ${COMMON_SOURCE} ${LIBRARY_SOURCE} )
  SET(b64contract ${CMAKE_CURRENT_BINARY_DIR}/_${contract}.b64)
  ADD_CUSTOM_COMMAND(
    TARGET ${contract}
    POST_BUILD
    COMMAND $ENV{WASM_SRC}/wamr-compiler/build/wamrc
    ARGS -sgx --format=aot -o ${contract}.aot ${contract}.wasm
    COMMAND base64
    ARGS -w 0 ${contract}.aot > ${b64contract})
  SET_SOURCE_FILES_PROPERTIES(${b64contract} PROPERTIES GENERATED TRUE)
  SET_DIRECTORY_PROPERTIES(PROPERTY ADDITIONAL_MAKE_CLEAN_FILES ${b64contract})
  # this can be replaced in later versions of CMAKE with target_link_properties
  SET_PROPERTY(TARGET ${contract} APPEND_STRING PROPERTY LINK_FLAGS "${EMCC_LINK_OPTIONS}")
  INSTALL(FILES ${b64contract} DESTINATION ${CONTRACT_INSTALL_DIRECTORY})
ENDFUNCTION()

ADD_SUBDIRECTORY(interface-test)
ADD_SUBDIRECTORY(mock-contract)
ADD_SUBDIRECTORY(interpreter-test)
ADD_SUBDIRECTORY(memory-test)
