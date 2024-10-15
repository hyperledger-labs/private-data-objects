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

################################################################################
# Common variables
################################################################################

# These options apply to all PDO projects
ADD_COMPILE_OPTIONS(-m64 -fvisibility=hidden -fpie -fPIC -fstack-protector)
ADD_COMPILE_OPTIONS($<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

OPTION(PDO_DEBUG_BUILD "Build with debugging turned on" 1)

IF (DEFINED ENV{PDO_DEBUG_BUILD})
  SET(PDO_DEBUG_BUILD $ENV{PDO_DEBUG_BUILD})
ENDIF()

IF (${PDO_DEBUG_BUILD})
  ADD_COMPILE_OPTIONS(-Og -g)
  ADD_COMPILE_DEFINITIONS(PDO_DEBUG_BUILD=1)
  MESSAGE(STATUS "Compiling in debug mode without optimizations (-Og -g)")
ELSE()
  ADD_COMPILE_OPTIONS(-O2)
  ADD_COMPILE_DEFINITIONS(PDO_DEBUG_BUILD=0)
  MESSAGE(STATUS "Compiling with optimizations (-O2). To use debug flags, set the DEBUG environment variable.")
ENDIF()

# The verbose build flag allows warning messages
# to be turned off. This removes a lot of the verbosity
# of the OpenSSL/SGXSSL deprecation warnings. In general
# we do not want to ignore those messages to verbose is
# set to true by default.
OPTION(PDO_VERBOSE_BUILD "Build with all warnings turned on" TRUE)

IF (DEFINED ENV{PDO_VERBOSE_BUILD})
  SET(PDO_VERBOSE_BUILD $ENV{PDO_VERBOSE_BUILD})
ENDIF()

IF (${PDO_VERBOSE_BUILD})
  ADD_COMPILE_OPTIONS(-Wall)
ELSE()
  # this should not be necessary (no -Wall), but make
  # sure we don't pick up the OpenSSL/SGXSSL deprecation warnings
  ADD_COMPILE_OPTIONS(-Wno-deprecated)
  ADD_COMPILE_OPTIONS(-Wno-deprecated-declarations)
ENDIF()

IF (NOT DEFINED ENV{PDO_INSTALL_ROOT})
  MESSAGE(FATAL_ERROR "PDO_INSTALL_ROOT not defined")
ENDIF()
SET(PDO_INSTALL_ROOT $ENV{PDO_INSTALL_ROOT})

IF (NOT DEFINED ENV{PDO_SOURCE_ROOT})
  MESSAGE(FATAL_ERROR "PDO_SOURCE_ROOT not defined")
ENDIF()
SET(PDO_SOURCE_ROOT $ENV{PDO_SOURCE_ROOT})

# The memory size option configures enclave and interpreter memory
# size values. The variable may have the value of "SMALL", "MEDIUM" or
# "LARGE". This is a project variable because the configurations
# depend on one another (the interpreter heap size must fit into the
# enclave heap, for example).
SET(PDO_MEMORY_CONFIG "MEDIUM" CACHE STRING "Set memory size parameters for enclave and interpreter")
IF (DEFINED ENV{PDO_MEMORY_CONFIG})
  SET(PDO_MEMORY_CONFIG $ENV{PDO_MEMORY_CONFIG})
ENDIF()
SET(MEMORY_SIZE_OPTIONS "SMALL" "MEDIUM" "LARGE")
IF (NOT ${PDO_MEMORY_CONFIG} IN_LIST MEMORY_SIZE_OPTIONS)
  MESSAGE(FATAL_ERROR "Invalid memory size; ${PDO_MEMORY_CONFIG}")
ENDIF()

# Get the current version using the get_version
# utility; note that this will provide 0.0.0 as
# the version if something goes wrong (like running
# without any annotated version tags)
EXECUTE_PROCESS(
  COMMAND ${PDO_SOURCE_ROOT}/bin/get_version
  WORKING_DIRECTORY ${PDO_SOURCE_ROOT}
  OUTPUT_VARIABLE PDO_VERSION
  ERROR_QUIET
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

IF (NOT PDO_VERSION)
  MESSAGE(FATAL_ERROR "Unable to compute PDO_VERSION")
ENDIF()
