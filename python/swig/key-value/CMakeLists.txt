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

PROJECT(pdo-common-kvs DESCRIPTION "PDO key-value SWIG python bindings")

SET(KVS_SWIG_DIR ${PDO_SOURCE_ROOT}/python/swig/key-value)

SET(KVS_SWIG_SOURCE ${KVS_SWIG_DIR}/key_value_swig.i
  ${KVS_SWIG_DIR}/block_store.cpp
  ${KVS_SWIG_DIR}/key_value.cpp
  ${KVS_SWIG_DIR}/swig_utils.cpp
  ${PDO_SOURCE_ROOT}/common/c11_support.cpp)
SET(KVS_SWIG_TARGET key_value_swig)

# These properties correspond to the (now deprecated) SWIG_FLAGS, so we
# apply them only to the swig template. This also ensures that cmake does not
# pass these flags to the g++ compiler, too.
SET_PROPERTY(SOURCE ${KVS_SWIG_DIR}/key_value_swig.i PROPERTY CPLUSPLUS ON)
SET_PROPERTY(SOURCE ${KVS_SWIG_DIR}/key_value_swig.i PROPERTY COMPILE_OPTIONS "-threads")

SWIG_ADD_LIBRARY(${KVS_SWIG_TARGET} TYPE SHARED LANGUAGE python SOURCES ${KVS_SWIG_SOURCE} OUTPUT_DIR ${PDO_COMMON_PY_DIR})

LIST(APPEND KVS_SWIG_INCLUDE_DIRS ${KVS_SWIG_DIR})
LIST(APPEND KVS_SWIG_INCLUDE_DIRS ${COMMON_SWIG_INCLUDE_DIRS})

# this ensures the generated .so file is placed along with the .py files
SET_PROPERTY(TARGET ${KVS_SWIG_TARGET} PROPERTY LIBRARY_OUTPUT_DIRECTORY ${PDO_COMMON_PY_DIR})

SET_PROPERTY(TARGET ${KVS_SWIG_TARGET} PROPERTY SWIG_USE_TARGET_INCLUDE_DIRECTORIES FALSE)
# The BEFORE property is needed to prepend the swig headers before the global
# include_libraries set by common/cmake/CommonVariables.cmake
# Without this setting, the global common headers clash with the swig-specific headers
# causing a compilation error in the swig-generated code.
TARGET_INCLUDE_DIRECTORIES(${KVS_SWIG_TARGET} BEFORE PRIVATE ${KVS_SWIG_INCLUDE_DIRS})

LIST(APPEND KVS_SWIG_LIBS ${COMMON_SWIG_LIBS})
LIST(APPEND KVS_SWIG_LIBS "pdo-lmdb-block-store;lmdb")
LIST(APPEND KVS_SWIG_LIBS ${OPENSSL_LINK_LIBRARIES})

LIST(APPEND KVS_SWIG_LIBRARY_DIRS ${COMMON_LIBRARY_DIR})

TARGET_LINK_DIRECTORIES(${KVS_SWIG_TARGET} PRIVATE ${KVS_SWIG_LIBRARY_DIRS})
TARGET_LINK_LIBRARIES(${KVS_SWIG_TARGET} ${KVS_SWIG_LIBS})