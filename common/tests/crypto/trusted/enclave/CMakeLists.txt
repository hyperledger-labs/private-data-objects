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

PROJECT(TestEnclave CXX C)

FILE(GLOB ENCLAVE_HEADERS *.h)
FILE(GLOB ENCLAVE_SOURCES *.cpp ${CRYPTO_TEST_SOURCE})
FILE(GLOB ENCLAVE_EDL *.edl)
FILE(GLOB ENCLAVE_CONFIG *.xml)
FILE(GLOB ENCLAVE_LDS *.lds)

SGX_EDGE_TRUSTED(${ENCLAVE_EDL} ENCLAVE_EDGE_SOURCES)
SET(ENCLAVE_EDL ${ENCLAVE_EDL} PARENT_SCOPE)

ADD_LIBRARY(${PROJECT_NAME} SHARED ${ENCLAVE_HEADERS} ${ENCLAVE_SOURCES} ${ENCLAVE_EDGE_SOURCES} ${ENCLAVE_EDL})
SGX_PREPARE_TRUSTED(${PROJECT_NAME})

ADD_DEPENDENCIES(${PROJECT_NAME} ${T_COMMON_LIB_NAME})
ADD_DEPENDENCIES(${PROJECT_NAME} ${T_CRYPTO_LIB_NAME})

TARGET_COMPILE_DEFINITIONS(${PROJECT_NAME} PRIVATE ${IAS_CA_CERT_REQUIRED_FLAGS})
TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PRIVATE ${CRYPTO_TEST_INCLUDE})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--version-script=${ENCLAVE_LDS})

TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${COMMON_TRUSTED_LIBS})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--end-group)

SGX_PREPARE_TRUSTED_LINK(${PROJECT_NAME})
SGX_SIGN_ENCLAVE(${PROJECT_NAME} ${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem ${ENCLAVE_CONFIG})
