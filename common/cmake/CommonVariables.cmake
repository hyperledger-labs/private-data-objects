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

# Variable for library names
# c* is for client, sgx is not required for building or using
# u* is for untrusted, untrusted handlers for enclave code
# t* is for trusted, for use inside an enclave

SET(COMMON_SOURCE_DIR ${PDO_SOURCE_ROOT}/common)
SET(COMMON_LIBRARY_DIR ${PDO_SOURCE_ROOT}/common/build)
LINK_DIRECTORIES(${COMMON_LIBRARY_DIR})

SET(C_CRYPTO_LIB_NAME cpdo-crypto)
SET(U_CRYPTO_LIB_NAME updo-crypto)
SET(T_CRYPTO_LIB_NAME tpdo-crypto)

SET(C_COMMON_LIB_NAME cpdo-common)
SET(U_COMMON_LIB_NAME updo-common)
SET(T_COMMON_LIB_NAME tpdo-common)

SET(INTERPRETER_LIB_NAME pdo-contract)

# Block store library does not depend on sgx at all
SET(BLOCK_STORE_LIB_NAME pdo-lmdb-block-store)

IF (NOT DEFINED ENV{PDO_INTERPRETER})
  MESSAGE(FATAL_ERROR "PDO_INTERPRETER not defined")
ENDIF()
SET(PDO_INTERPRETER $ENV{PDO_INTERPRETER})

IF (PDO_INTERPRETER MATCHES "^wawaka")
  SET(COMMON_INTERPRETER_LIBRARIES "iwasm" "wwasm" ${INTERPRETER_LIB_NAME})
ELSE()
  MESSAGE(FATAL_ERROR "Unknown interpreter in PDO_INTERPRETER")
ENDIF()

SET(INTERPRETER_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/interpreter)

# -----------------------------------------------------------------
# COMMON_INCLUDE_DIRS -- variable with the complete list of
# directories to include for the base common libraries
# -----------------------------------------------------------------
LIST(APPEND COMMON_INCLUDE_DIRS ${COMMON_SOURCE_DIR})
LIST(APPEND COMMON_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/state)
LIST(APPEND COMMON_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/crypto)
LIST(APPEND COMMON_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/packages/base64)
LIST(APPEND COMMON_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/packages/parson)
LIST(APPEND COMMON_INCLUDE_DIRS ${COMMON_SOURCE_DIR}/packages/block_store)

# Everyone who includes common must include these directories
# in the include search, set this for all targets
INCLUDE_DIRECTORIES(${COMMON_INCLUDE_DIRS})

# -----------------------------------------------------------------
# COMMON_CLIENT_LIBS -- variable with the complete list of
# libraries that could be linked for client applications
# -----------------------------------------------------------------
LIST(APPEND COMMON_CLIENT_LIBS ${C_COMMON_LIB_NAME})
LIST(APPEND COMMON_CLIENT_LIBS ${C_CRYPTO_LIB_NAME})
LIST(APPEND COMMON_CLIENT_LIBS ${BLOCK_STORE_LIB_NAME})
LIST(APPEND COMMON_CLIENT_LIBS pthread lmdb)

# -----------------------------------------------------------------
# COMMON_UNTRUSTED_LIBS -- variable with the complete list of
# libraries that could be linked for untrusted dependencies
# -----------------------------------------------------------------
LIST(APPEND COMMON_UNTRUSTED_LIBS ${U_COMMON_LIB_NAME})
LIST(APPEND COMMON_UNTRUSTED_LIBS ${U_CRYPTO_LIB_NAME})
LIST(APPEND COMMON_UNTRUSTED_LIBS ${BLOCK_STORE_LIB_NAME})
LIST(APPEND COMMON_UNTRUSTED_LIBS pthread lmdb)

# -----------------------------------------------------------------
# COMMON_TRUSTED_LIBS -- variable with the complete list of
# libraries that could be linked for enclave use
# -----------------------------------------------------------------
LIST(APPEND COMMON_TRUSTED_LIBS ${T_COMMON_LIB_NAME})
LIST(APPEND COMMON_TRUSTED_LIBS ${T_CRYPTO_LIB_NAME})
LIST(APPEND COMMON_TRUSTED_LIBS ${BLOCK_STORE_LIB_NAME})
LIST(APPEND COMMON_TRUSTED_LIBS ${COMMON_INTERPRETER_LIBRARIES})
LIST(APPEND COMMON_TRUSTED_LIBS lmdb)
