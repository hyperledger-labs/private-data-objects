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

PROJECT(pdo-common DESCRIPTION "PDO common and client package")

IF (NOT DEFINED ENV{PDO_SOURCE_ROOT})
  MESSAGE(FATAL_ERROR "PDO_SOURCE_ROOT not defined")
ENDIF()
SET(PDO_SOURCE_ROOT $ENV{PDO_SOURCE_ROOT})

LIST(APPEND CMAKE_MODULE_PATH "${PDO_SOURCE_ROOT}/build/cmake")

INCLUDE(PythonBuild)

ADD_SUBDIRECTORY(swig)

# This will ensure that the SWIG bindings are built before
# the python wheel
SET(SWIG_DEPS crypto key_value_swig)
BUILD_PYTHON_WHEEL(WITH_DEPS SRC_DIR ${PDO_SOURCE_ROOT}/python NAME pdo
  TARGET_DEPS ${SWIG_DEPS})