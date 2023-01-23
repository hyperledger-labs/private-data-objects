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

# Put test artifacts under /tests subdirectory
set(TESTS_OUTPUT_DIR ${CMAKE_BINARY_DIR}/tests)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${TESTS_OUTPUT_DIR})

################################################################################
# Untrusted Test Application
################################################################################
IF (BUILD_UNTRUSTED)
  SET(UNTRUSTED_TEST_NAME u_state_test)
  PROJECT(${UNTRUSTED_TEST_NAME} CXX)

  FILE(GLOB TEST_SOURCES untrusted/*.cpp)
  ADD_EXECUTABLE(${UNTRUSTED_TEST_NAME} ${TEST_SOURCES})
  SGX_PREPARE_UNTRUSTED(${UNTRUSTED_TEST_NAME})

  # Same compile options as untrusted library
  TARGET_INCLUDE_DIRECTORIES(${UNTRUSTED_TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  TARGET_COMPILE_DEFINITIONS(${UNTRUSTED_TEST_NAME} PRIVATE "_UNTRUSTED_=1")

  # Link the untrusted test application against the untrusted library and openssl
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} "-Wl,--start-group")
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} ${COMMON_UNTRUSTED_LIBS})
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} ${OPENSSL_LDFLAGS})
  TARGET_LINK_LIBRARIES(${UNTRUSTED_TEST_NAME} "-Wl,--end-group")

  # Register this application as a test
  ADD_TEST(
    NAME ${UNTRUSTED_TEST_NAME}
    COMMAND env LD_LIBRARY_PATH=${OPENSSL_LIBRARY_DIRS}:${LD_LIBRARY_PATH} ./${UNTRUSTED_TEST_NAME}
    WORKING_DIRECTORY ${TESTS_OUTPUT_DIR}
  )
ENDIF()

################################################################################
# Untrusted Test Application
################################################################################
IF (BUILD_CLIENT)
  SET(CLIENT_TEST_NAME c_state_test)
  PROJECT(${CLIENT_TEST_NAME} CXX)

  FILE(GLOB TEST_SOURCES untrusted/*.cpp)
  ADD_EXECUTABLE(${CLIENT_TEST_NAME} ${TEST_SOURCES})

  # Same compile options as untrusted library
  TARGET_INCLUDE_DIRECTORIES(${CLIENT_TEST_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  TARGET_COMPILE_DEFINITIONS(${CLIENT_TEST_NAME} PRIVATE "_UNTRUSTED_=1")
  TARGET_COMPILE_DEFINITIONS(${CLIENT_TEST_NAME} PRIVATE "_CLIENT_ONLY_=1")

  # Link the untrusted test application against the untrusted library and openssl
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} "-Wl,--start-group")
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} ${C_COMMON_LIB_NAME})
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} ${BLOCK_STORE_LIB_NAME})
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} ${OPENSSL_LDFLAGS})
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} -lpthread)
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} -llmdb)
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} ${C_CRYPTO_LIB_NAME})
  TARGET_LINK_LIBRARIES(${CLIENT_TEST_NAME} "-Wl,--end-group")

  # Register this application as a test
  ADD_TEST(
    NAME ${CLIENT_TEST_NAME}
    COMMAND env LD_LIBRARY_PATH=${OPENSSL_LIBRARY_DIRS}:${LD_LIBRARY_PATH} ./${CLIENT_TEST_NAME}
    WORKING_DIRECTORY ${TESTS_OUTPUT_DIR}
  )
ENDIF()
