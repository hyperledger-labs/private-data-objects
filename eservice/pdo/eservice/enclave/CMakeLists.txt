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
PROJECT(pdo-enclave-internal CXX C)

SGX_EDGE_UNTRUSTED(${LIBPDO_ENCLAVE_EDL} PROJECT_UNTRUSTED_EDGE_SOURCES)
ADD_CUSTOM_TARGET(${PROJECT_NAME} ALL echo -n DEPENDS ${PROJECT_UNTRUSTED_EDGE_SOURCES})
