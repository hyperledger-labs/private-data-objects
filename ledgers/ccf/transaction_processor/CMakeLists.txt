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

CMAKE_MINIMUM_REQUIRED(VERSION 3.16)

INCLUDE(${CCF_DIR}/cmake/preproject.cmake)
PROJECT(pdoenc LANGUAGES C CXX)
INCLUDE(${CCF_DIR}/cmake/ccf_app.cmake)

FIND_PACKAGE(ccf_virtual REQUIRED)

# Add the PDO transaction processor target
add_ccf_app(pdoenc
  SRCS pdo_tp.cpp verify_signatures.cpp
  INCLUDE_DIRS ${CCF_DIR}/include/ccf ${CCF_DIR}/include/3rdparty ${CCF_DIR}/include
)

INSTALL(TARGETS pdoenc.virtual DESTINATION lib)
