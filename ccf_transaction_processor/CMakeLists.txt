# Copyright 2020 Intel Corporation
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

cmake_minimum_required(VERSION 3.11)

include(${CCF_DIR}/cmake/preproject.cmake)

project(pdoenc LANGUAGES C CXX)

include(${CCF_DIR}/cmake/ccf.cmake)
include(${CCF_DIR}/cmake/ccf_app.cmake)

# Error checking on environment variable
# the PDO TP app will be signed with the RSA key whose locaation is
# pointed to by PDO_ENCLAVE_CODE_SIGN_PEM
IF (NOT EXISTS "$ENV{PDO_ENCLAVE_CODE_SIGN_PEM}")
  MESSAGE(FATAL_ERROR "PDO_ENCLAVE_CODE_SIGN_PEM environment variable not defined!")
ENDIF()
SET(PDO_ENCLAVE_CODE_SIGN_PEM "$ENV{PDO_ENCLAVE_CODE_SIGN_PEM}")

# Add the PDO transaction processor target
add_ccf_app(pdoenc
  SRCS transaction_processor/pdo_tp.cpp transaction_processor/verify_signatures.cpp
  INCLUDE_DIRS ${CCF_DIR}/include/ccf ${CCF_DIR}/include/3rdparty ${CCF_DIR}/include}
)

install(TARGETS pdoenc.virtual DESTINATION lib)

sign_app_library(pdoenc.enclave ../etc/oe_sign.conf ${PDO_ENCLAVE_CODE_SIGN_PEM})
