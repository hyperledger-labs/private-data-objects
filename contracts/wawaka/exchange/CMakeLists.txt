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

FILE(GLOB COMMON_EXCHANGE_SOURCE contracts/exchange_base.cpp contracts/common/*.cpp)
SET(ISSUER_AUTHORITY_BASE contracts/issuer_authority_base.cpp)

BUILD_CONTRACT(asset_type contracts/asset_type.cpp ${COMMON_EXCHANGE_SOURCE})
BUILD_CONTRACT(vetting_organization contracts/vetting_organization.cpp ${ISSUER_AUTHORITY_BASE} ${COMMON_EXCHANGE_SOURCE})
BUILD_CONTRACT(issuer contracts/issuer.cpp ${ISSUER_AUTHORITY_BASE} ${COMMON_EXCHANGE_SOURCE})
