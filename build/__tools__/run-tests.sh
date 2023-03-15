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
# -----------------------------------------------------------------
if [ "${PDO_INTERPRETER}" == "wawaka-aot" ]; then
    die Automated tests for the wawaka-aot interpreter are currently not supported.
fi

# -----------------------------------------------------------------
# UNIT TESTS WITH NO SERVICES
# -----------------------------------------------------------------
try ${PDO_SOURCE_ROOT}/build/tests/unit-test.sh

# -----------------------------------------------------------------
# SERVICES TESTS
# -----------------------------------------------------------------
function cleanup {
    yell "shutdown services"
    ${PDO_HOME}/bin/ps-stop.sh > /dev/null
    ${PDO_HOME}/bin/es-stop.sh > /dev/null
    ${PDO_HOME}/bin/ss-stop.sh > /dev/null
    rm -f ${SAVE_FILE} ${ESDB_FILE}
}

trap cleanup EXIT

try ${PDO_HOME}/bin/ss-start.sh --loglevel ${PDO_LOG_LEVEL}
try ${PDO_HOME}/bin/ps-start.sh --loglevel ${PDO_LOG_LEVEL} --ledger ${PDO_LEDGER_URL} --clean
try ${PDO_HOME}/bin/es-start.sh --loglevel ${PDO_LOG_LEVEL} --ledger ${PDO_LEDGER_URL} --clean

try ${PDO_SOURCE_ROOT}/build/tests/service-test.sh

# -----------------------------------------------------------------
# -----------------------------------------------------------------
yell completed all tests
exit 0
