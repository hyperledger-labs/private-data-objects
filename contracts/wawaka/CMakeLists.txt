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
INCLUDE(wawaka_common.cmake)

LIST(APPEND WASM_LIBRARIES ${WW_COMMON_LIB})
LIST(APPEND WASM_INCLUDES ${WW_COMMON_INCLUDES})

ADD_SUBDIRECTORY(mock-contract)
ADD_SUBDIRECTORY(interface-test)
ADD_SUBDIRECTORY(interpreter-test)
ADD_SUBDIRECTORY(memory-test)
ADD_SUBDIRECTORY(attestation-test)
