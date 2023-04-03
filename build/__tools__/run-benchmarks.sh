#!/bin/bash

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

# -----------------------------------------------------------------
# -----------------------------------------------------------------
SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh
check_python_version

# -----------------------------------------------------------------
# -----------------------------------------------------------------
: "${PDO_SOURCE_ROOT:-$(die Missing environment variable PDO_SOURCE_ROOT)}"
: "${PDO_INTERPRETER:-$(die Missing environment variable PDO_INTERPRETER)}"

# wawaka contracts reside under same directory, regardless of execution mode
PDO_INTERPRETER_NAME=${PDO_INTERPRETER}
if [[ "$PDO_INTERPRETER" =~ ^"wawaka-" ]]; then
    PDO_INTERPRETER_NAME="wawaka"
fi

# build interpreter specific benchmark contracts
yell --------------- Building benchmark contracts ---------------
cd $SRCDIR/contracts/${PDO_INTERPRETER_NAME}/benchmarks
try make all
try make install

# add benchmark results directory
mkdir -p $SRCDIR/contracts/${PDO_INTERPRETER_NAME}/benchmarks/data

# execute interpreter specific benchmarks
yell --------------- Executing benchmarks ---------------
for test_file in ${PDO_SOURCE_ROOT}/build/benchmarks/${PDO_INTERPRETER_NAME}/*.json ; do
    test_contract=$(basename ${test_file} .json)
    say start ${PDO_INTERPRETER} benchmark ${test_contract} without services
    try pdo-test-contract --no-ledger --contract ${test_contract} \
        --expressions ${test_file} \
        --logfile __screen__ --loglevel info
done
