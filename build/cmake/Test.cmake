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

IF (NOT DEFINED ENV{PDO_INSTALL_ROOT})
  MESSAGE(FATAL "PDO_INSTALL_ROOT environment variable not defined")
ENDIF()
SET(PDO_INSTALL_ROOT "$ENV{PDO_INSTALL_ROOT}")

# -----------------------------------------------------------------
# Environment Variables
# -----------------------------------------------------------------
SET(TEST_LOG_LEVEL "warn" CACHE STRING "Test log level")
SET(TEST_LOG_FILE "__screen__" CACHE STRING "Test log file")
SET(TEST_SERVICE_HOST $ENV{PDO_HOSTNAME} CACHE STRING "Test services host")
SET(TEST_LEDGER $ENV{PDO_LEDGER_URL} CACHE STRING "Test ledger URL")

# -----------------------------------------------------------------
# This form of invocation gets around the need to ensure that the
# virtual environment has been activated in the wrapper
SET(PDO_TEST_CONTRACT
  ${PDO_INSTALL_ROOT}/bin/pdo-test-contract
  --loglevel ${TEST_LOG_LEVEL}
  --logfile ${TEST_LOG_FILE})

# NOTE: we override the default configuration here because clients
# do not have the full configuration file (eservice1.toml) and
# when running with services these are not required.
SET(PDO_TEST_CONTRACT_WITH_SERVICES
  ${PDO_TEST_CONTRACT}
  --ledger ${TEST_LEDGER}
  --config pcontract.toml
  --pservice http://${TEST_SERVICE_HOST}:7001/ http://${TEST_SERVICE_HOST}:7002 http://${TEST_SERVICE_HOST}:7003
  --eservice-url http://${TEST_SERVICE_HOST}:7101/)

SET(PDO_SHELL
  ${PDO_INSTALL_ROOT}/bin/pdo-shell
  --loglevel ${TEST_LOG_LEVEL}
  --logfile ${TEST_LOG_FILE}
  --ledger ${TEST_LEDGER}
  -m service_host ${TEST_SERVICE_HOST})

# -----------------------------------------------------------------
# ADD_UNIT_TEST
# This function invokes the pdo-test-contract script to process
# a series of expressions through a contract.
# -----------------------------------------------------------------
FUNCTION(ADD_UNIT_TEST contract)
  CMAKE_PARSE_ARGUMENTS(UT "" "EXPRESSIONS ESERVICES PSERVICES" "" ${ARGN})
  IF (DEFINED UT_EXPRESSIONS)
    SET(expression_file ${UT_EXPRESSIONS})
  ELSE()
    SET(expression_file ${CMAKE_CURRENT_SOURCE_DIR}/${contract}/test-short.json)
  ENDIF()

  ADD_TEST(
    NAME unit-${contract}
    COMMAND ${PDO_TEST_CONTRACT} --no-ledger --contract ${contract} --expressions ${expression_file})
ENDFUNCTION()

# -----------------------------------------------------------------
# ADD_UNIT_TEST_WITH_SERVICES
# This function invokes the pdo-test-contract script to process
# a series of expressions through a contract. It requires services.
# -----------------------------------------------------------------
FUNCTION(ADD_UNIT_TEST_WITH_SERVICES contract)
  CMAKE_PARSE_ARGUMENTS(UT "" "EXPRESSIONS ESERVICES PSERVICES" "" ${ARGN})
  IF (DEFINED UT_EXPRESSIONS)
    SET(expression_file ${UT_EXPRESSIONS})
  ELSE()
    SET(expression_file ${CMAKE_CURRENT_SOURCE_DIR}/${contract}/test-short.json)
  ENDIF()

  ADD_TEST(
    NAME system-unit-${contract}
    COMMAND ${PDO_TEST_CONTRACT_WITH_SERVICES} --contract ${contract} --expressions ${expression_file})
ENDFUNCTION()

# -----------------------------------------------------------------
# ADD_SYSTEM_TEST
# This function invokes a pdo-shell script on an optional set of
# parameters. The assumption is that the script loads site.psh to
# pick up the service configuration. TEST_SERVICE_HOST will be used
# to configure the services host in site.psh.
# -----------------------------------------------------------------
FUNCTION(ADD_SYSTEM_TEST contract)
  CMAKE_PARSE_ARGUMENTS(ST "" "SCRIPT" "PARAMS" ${ARGN})
  IF (DEFINED ST_SCRIPT)
    SET(script_file ${ST_SCRIPT})
  ELSE()
    SET(script_file ${CMAKE_CURRENT_SOURCE_DIR}/${contract}/scripts/${contract}.psh)
  ENDIF()

  ADD_TEST(
    NAME system-${contract}
    COMMAND ${PDO_SHELL} ${script_file} ${ST_PARAMS})
ENDFUNCTION()
