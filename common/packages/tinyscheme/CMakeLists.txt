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

################################################################################
# Trusted Tinyscheme
################################################################################

FILE(GLOB PROJECT_HEADERS *.h)
FILE(GLOB PROJECT_SOURCES *.c)

PROJECT(tinyscheme C)

ADD_LIBRARY(${PROJECT_NAME} STATIC ${PROJECT_HEADERS} ${PROJECT_SOURCES})
SGX_PREPARE_TRUSTED(${PROJECT_NAME})

# this compiler switch is useful to remove a large number of warnings
# that are specific to the way the tinyscheme project uses switch statements
TARGET_COMPILE_OPTIONS(${PROJECT_NAME} PRIVATE -Wno-switch)
TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PRIVATE SUN_DL=1 USE_DL=1 USE_MATH=1 USE_ASCII_NAMES=0)
