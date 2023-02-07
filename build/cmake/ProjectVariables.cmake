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
ADD_COMPILE_OPTIONS(-m64 -fvisibility=hidden -fpie -fPIC -fstack-protector -Wall)
ADD_COMPILE_OPTIONS($<$<COMPILE_LANGUAGE:CXX>:-std=c++11>)

OPTION(PDO_DEBUG_BUILD "Build with debugging turned on" FALSE)

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
