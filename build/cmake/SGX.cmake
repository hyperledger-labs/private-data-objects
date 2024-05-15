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
# Environment Variables
################################################################################

IF (NOT DEFINED ENV{PDO_SGX_KEY_ROOT})
  MESSAGE(FATAL_ERROR "PDO_SGX_KEY_ROOT not defined")
ENDIF()
SET(PDO_SGX_KEY_ROOT "$ENV{PDO_SGX_KEY_ROOT}")

IF (NOT DEFINED ENV{SGX_MODE})
  MESSAGE(FATAL_ERROR "SGX_MODE not defined")
ENDIF()
SET(SGX_MODE $ENV{SGX_MODE})

IF (${SGX_MODE} STREQUAL "SIM")
    SET(SGX_USE_SIMULATOR TRUE)

    IF (${PDO_DEBUG_BUILD} STREQUAL "0")
        MESSAGE(FATAL_ERROR "SGX_MODE=SIM does not accept PDO_DEBUG_BUILD=0")
    ENDIF()
ELSE()
    SET(SGX_USE_SIMULATOR FALSE)

    IF (${CMAKE_BUILD_TYPE} STREQUAL "Release")
        IF (${PDO_DEBUG_BUILD} STREQUAL "1")
            MESSAGE(FATAL_ERROR "SGX_MODE=HW and CMAKE_BUILD_TYPE=Release do not accept PDO_DEBUG_BUILD=1")
        ENDIF()
    ENDIF()
ENDIF()

IF (NOT DEFINED ENV{SGX_SDK})
  MESSAGE(FATAL_ERROR "SGX_SDK not defined")
ENDIF()
SET(SGX_SDK $ENV{SGX_SDK})

IF (NOT DEFINED ENV{SGX_SSL})
  MESSAGE(FATAL_ERROR "SGX_SSL not defined")
ENDIF()
SET(SGX_SSL $ENV{SGX_SSL})

# The expectation is that these are set prior to including this file
IF (NOT DEFINED CMAKE_LIBRARY_OUTPUT_DIRECTORY)
  MESSAGE(FATAL_ERROR "CMAKE_LIBRARY_OUTPUTDIRECTORY must be set")
ENDIF()

SET(IAS_CERTIFICATE_URL "https://certificates.trustedservices.intel.com/Intel_SGX_Attestation_RootCA.pem")

################################################################################
# Internal SGX Variables
################################################################################
SET(SGX_EDGER "${SGX_SDK}/bin/x64/sgx_edger8r")
SET(SGX_SIGN "${SGX_SDK}/bin/x64/sgx_sign")

IF (${SGX_USE_SIMULATOR})
  ADD_COMPILE_DEFINITIONS(SGX_SIMULATOR=1)
  SET(TRTS_LIBRARY_NAME "sgx_trts_sim")
  SET(URTS_LIBRARY_NAME "sgx_urts_sim")
  SET(SERVICE_LIBRARY_NAME "sgx_tservice_sim")
ELSE()
  SET(TRTS_LIBRARY_NAME "sgx_trts")
  SET(URTS_LIBRARY_NAME "sgx_urts")
  SET(SERVICE_LIBRARY_NAME "sgx_tservice")
ENDIF()

SET(SGX_TRUSTED_LIBS sgx_tstdc sgx_tcxx sgx_tcrypto ${SERVICE_LIBRARY_NAME})
SET(SGX_UNTRUSTED_LIBS ${URTS_LIBRARY_NAME} pthread)

SET(SGX_SEARCH_PATH "${SGX_SDK}/include:${SGX_SSL}/include")
SET(SGX_TRUSTED_INCLUDE_DIRS
  "${SGX_SDK}/include"
  "${SGX_SDK}/include/tlibc"
  "${SGX_SDK}/include/libcxx")

SET(SGX_UNTRUSTED_INCLUDE_DIRS
  "${SGX_SDK}/include")

SET(SGX_SSL_INCLUDE "${SGX_SSL}/include")

SET(SGX_SSL_LIBRARY_NAME "sgx_tsgxssl")
SET(SGX_SSL_CRYPTO_LIBRARY_NAME "sgx_tsgxssl_crypto")

################################################################################
# Functions
################################################################################

# -----------------------------------------------------------------
# SGX_EDGE_TRUSTED
# Create the trusted files to handle ocalls and ecalls.
# -----------------------------------------------------------------
FUNCTION(SGX_EDGE_TRUSTED EDL EDGE_FILES)
    GET_FILENAME_COMPONENT(EDL_BASE_NAME ${EDL} NAME_WE)
    GET_FILENAME_COMPONENT(EDL_DIR_NAME ${EDL} DIRECTORY)
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

    SET (EDGE_FILES_LIST
      "${CMAKE_CURRENT_BINARY_DIR}/${EDL_BASE_NAME}_t.h"
      "${CMAKE_CURRENT_BINARY_DIR}/${EDL_BASE_NAME}_t.c")
    SET (${EDGE_FILES} ${EDGE_FILES_LIST} PARENT_SCOPE)

    ADD_CUSTOM_COMMAND(
      OUTPUT ${EDGE_FILES_LIST}
      COMMAND "${SGX_EDGER}" --trusted ${EDL} --search-path ${SGX_SEARCH_PATH} --search-path ${EDL_DIR_NAME}
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      DEPENDS ${EDL}
    )
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_EDGE_UNTRUSTED
# Create the untrusted files to handle ocalls and ecalls.
# -----------------------------------------------------------------
FUNCTION(SGX_EDGE_UNTRUSTED EDL EDGE_FILES)
    GET_FILENAME_COMPONENT(EDL_BASE_NAME ${EDL} NAME_WE)
    GET_FILENAME_COMPONENT(EDL_DIR_NAME ${EDL} DIRECTORY)
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})

    SET (EDGE_FILES_LIST
      "${CMAKE_CURRENT_BINARY_DIR}/${EDL_BASE_NAME}_u.h"
      "${CMAKE_CURRENT_BINARY_DIR}/${EDL_BASE_NAME}_u.c")
    SET (${EDGE_FILES} ${EDGE_FILES_LIST} PARENT_SCOPE)

    ADD_CUSTOM_COMMAND(
      OUTPUT ${EDGE_FILES_LIST}
      COMMAND "${SGX_EDGER}" --untrusted ${EDL} --search-path ${SGX_SEARCH_PATH} --search-path ${EDL_DIR_NAME}
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      DEPENDS ${EDL}
    )
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_SIGN_ENCLAVE
# -----------------------------------------------------------------
FUNCTION(SGX_SIGN_ENCLAVE TARGET KEY_FILE CONFIG)
    SET (ENCLAVE $<TARGET_FILE:${TARGET}>)

    SET (SIGNED_ENCLAVE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${TARGET}.signed${CMAKE_SHARED_LIBRARY_SUFFIX})
    SET (SIGNED_ENCLAVE ${SIGNED_ENCLAVE} PARENT_SCOPE)
    SET (SIGNED_ENCLAVE_METADATA ${SIGNED_ENCLAVE}".meta")
    ADD_CUSTOM_COMMAND(
      TARGET ${TARGET}
      POST_BUILD
      COMMAND "${SGX_SIGN}" sign -key "${KEY_FILE}" -enclave "${ENCLAVE}" -out "${SIGNED_ENCLAVE}" -dumpfile "${SIGNED_ENCLAVE_METADATA}" -config "${CONFIG}"
    )
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_PREPARE_UNTRUSTED
# Add the include and link directories necessary for an SGX application
# the runs in user space.
# -----------------------------------------------------------------
FUNCTION(SGX_PREPARE_UNTRUSTED TARGET)
  MESSAGE(STATUS "Prepare target ${TARGET} to use an enclave")

  TARGET_INCLUDE_DIRECTORIES(${TARGET} PRIVATE ${SGX_UNTRUSTED_INCLUDE_DIRS})

  # If we are running in HW mode, we want the versions of
  # the untrusted libraries from /usr/lib. The simulator
  # versions still need to come from the SDK.
  IF (${SGX_USE_SIMULATOR})
    TARGET_LINK_DIRECTORIES(${TARGET} PRIVATE ${SGX_SDK}/lib64)
  ENDIF()

  TARGET_LINK_DIRECTORIES(${TARGET} PRIVATE ${SGX_SSL}/lib64)
  TARGET_LINK_DIRECTORIES(${TARGET} PRIVATE ${SGX_SSL}/lib64/release)

  TARGET_LINK_LIBRARIES(${TARGET} ${SGX_UNTRUSTED_LIBS})
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_PREPARE_TRUSTED
# Add the include and compile options necessary to build code
# that will run inside an enclave.
# -----------------------------------------------------------------
FUNCTION(SGX_PREPARE_TRUSTED TARGET)
  MESSAGE(STATUS "Prepare target ${TARGET} for compilation as an enclave")

  TARGET_INCLUDE_DIRECTORIES(${TARGET} PRIVATE  ${SGX_TRUSTED_INCLUDE_DIRS})
  TARGET_INCLUDE_DIRECTORIES(${TARGET} PRIVATE  ${SGX_SSL_INCLUDE})

  TARGET_COMPILE_OPTIONS(${TARGET} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-nostdinc++>)
  TARGET_COMPILE_OPTIONS(${TARGET} PRIVATE -nostdinc)
  TARGET_COMPILE_OPTIONS(${TARGET} PRIVATE -fno-builtin-printf)
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_PREPARE_TRUSTED_LINK
# Add the link and library flags necessary to build code
# that will run inside an enclave
# -----------------------------------------------------------------
FUNCTION(SGX_PREPARE_TRUSTED_LINK TARGET)
  MESSAGE(STATUS "Add SGX link information for target ${TARGET}")

  TARGET_LINK_DIRECTORIES(${TARGET} PRIVATE ${SGX_SDK}/lib64)
  TARGET_LINK_DIRECTORIES(${TARGET} PRIVATE ${SGX_SSL}/lib64)
  TARGET_LINK_DIRECTORIES(${TARGET} PRIVATE ${SGX_SSL}/lib64/release)

  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--no-undefined)
  TARGET_LINK_LIBRARIES(${TARGET} -nostdlib)
  TARGET_LINK_LIBRARIES(${TARGET} -nodefaultlibs)
  TARGET_LINK_LIBRARIES(${TARGET} -nostartfiles)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,-Bstatic)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,-Bsymbolic)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--no-undefined)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,-pie,-eenclave_entry)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--export-dynamic)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--defsym,__ImageBase=0)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--whole-archive ${SGX_SSL_LIBRARY_NAME} -Wl,--no-whole-archive)
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--whole-archive ${TRTS_LIBRARY_NAME} -Wl,--no-whole-archive)

  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--start-group)
  TARGET_LINK_LIBRARIES(${TARGET} ${SGX_SSL_CRYPTO_LIBRARY_NAME} ${SGX_TRUSTED_LIBS})
  TARGET_LINK_LIBRARIES(${TARGET} -Wl,--end-group)
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_PREPARE_TRUSTED_LINK
# Copy the signed enclave into the dependencies directory and create
# a header file that can be used to verify the MRENCLAVE of the enclave
# that has been created
# -----------------------------------------------------------------
FUNCTION(SGX_DEPLOY_FILES TARGET HEADER_NAME)
  SET (ENCLAVE $<TARGET_FILE:${TARGET}>)
  SET (SIGNED_ENCLAVE ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/${TARGET}.signed${CMAKE_SHARED_LIBRARY_SUFFIX})
  SET (GENERATE_COMMAND "${PDO_SOURCE_ROOT}/build/__tools__/generate_mrenclave_header")
  SET (HEADER_FILE "${DEPS_DIR}/include/eservice_mrenclave.h")
  STRING(TOUPPER "${HEADER_NAME}" VARIABLE_NAME)

  ADD_CUSTOM_COMMAND(
    TARGET ${TARGET}
    POST_BUILD

    # move the enclave library into a "permanent" location
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPS_DIR}/bin"
    COMMAND ${CMAKE_COMMAND} -E copy "${SIGNED_ENCLAVE}" "${DEPS_DIR}/bin"

    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPS_DIR}/include"
    COMMAND ${GENERATE_COMMAND} --metadata ${SIGNED_ENCLAVE}.meta --header ${HEADER_FILE} --enclave ${VARIABLE_NAME}
  )
ENDFUNCTION()

# -----------------------------------------------------------------
# SGX_PREPARE_ENCLAVE_XML
# Generate the xml configuration file which can be then used by
# SGX_SIGN. For now, this is only necessary to set the DisableDebug field.
# -----------------------------------------------------------------
FUNCTION(SGX_PREPARE_ENCLAVE_XML XML_IN XML_OUT)
    IF (${PDO_DEBUG_BUILD} STREQUAL "0")
        SET(DISABLE_DEBUG "1")
    ELSE()
        SET(DISABLE_DEBUG "0")
    ENDIF()
    ADD_CUSTOM_COMMAND(
        OUTPUT ${XML_OUT}
        COMMAND "sed"
            "'s/<DisableDebug>.*<\\/DisableDebug>/<DisableDebug>${DISABLE_DEBUG}<\\/DisableDebug>/'"
            "${XML_IN}>${XML_OUT}")
ENDFUNCTION()
