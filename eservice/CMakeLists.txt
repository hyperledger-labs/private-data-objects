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
FIND_PACKAGE(PkgConfig REQUIRED)

IF (NOT DEFINED ENV{PDO_SOURCE_ROOT})
  MESSAGE(FATAL_ERROR "PDO_SOURCE_ROOT not defined")
ENDIF()
SET(PDO_SOURCE_ROOT $ENV{PDO_SOURCE_ROOT})

LIST(APPEND CMAKE_MODULE_PATH "${PDO_SOURCE_ROOT}/common/cmake")
LIST(APPEND CMAKE_MODULE_PATH "${PDO_SOURCE_ROOT}/build/cmake")

SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

INCLUDE(ProjectVariables)
INCLUDE(CommonVariables)
INCLUDE(SGX)

SET(DEPS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/deps")

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# PROJECTS
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
PROJECT(eservice)

ADD_SUBDIRECTORY (lib/libpdo_enclave)
ADD_SUBDIRECTORY (pdo/eservice/enclave)
