#!/bin/bash

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

# -----------------------------------------------------------------
# -----------------------------------------------------------------
source ${PDO_SOURCE_ROOT}/bin/lib/common.sh
check_python_version

PDO_LOG_LEVEL=${PDO_LOG_LEVEL:-info}

# -----------------------------------------------------------------
yell run unit tests for python, common, contracts and eservice
# -----------------------------------------------------------------
say run unit tests for python package
cd ${PDO_SOURCE_ROOT}/python
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

say run unit tests for common library
cd ${PDO_SOURCE_ROOT}/common/build
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

say run unit tests for eservice
cd ${PDO_SOURCE_ROOT}/eservice
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

say run unit tests for contracts
cd ${PDO_SOURCE_ROOT}/contracts
try make TEST_LOG_LEVEL=${PDO_LOG_LEVEL} test > /dev/null

# -----------------------------------------------------------------
yell start tests without provisioning or enclave services
# -----------------------------------------------------------------
say start request test
try pdo-test-request --no-ledger --iterations 100 \
    --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}

# execute the common tests
for test_file in ${PDO_SOURCE_ROOT}/build/tests/common/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start test ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
done

# execute interpreter specific tests
INTERPRETER_NAME=${PDO_INTERPRETER}
if [[ "$PDO_INTERPRETER" =~ ^"wawaka-" ]]; then
    INTERPRETER_NAME="wawaka"
fi

for test_file in ${PDO_SOURCE_ROOT}/build/tests/${INTERPRETER_NAME}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start interpreter-specific test ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
done

say start request test with tampered block order, this should fail
pdo-test-request --no-ledger \
    --tamper-block-order \
    --logfile __screen__ --loglevel ${PDO_LOG_LEVEL}
if [ $? == 0 ]; then
    die request test with tampered block order succeeded though it should have failed
fi

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all unit tests
exit 0
