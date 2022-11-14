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

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit
fi

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh

yell --------------- COMMON ---------------
cd $SRCDIR/common/crypto/verify_ias_report
rm -f ias-certificates.cpp

#cd $SRCDIR/common/interpreter/gipsy_scheme/packages
#rm -f package.h package.scm

cd $SRCDIR/common
rm -rf build

yell --------------- BIN ---------------
cd $SRCDIR/bin
make clean

yell --------------- PYTHON ---------------
cd $SRCDIR/python
make clean

yell --------------- ESERVICE ---------------
cd $SRCDIR/eservice
make clean

yell --------------- PSERVICE ---------------
cd $SRCDIR/pservice/lib/libpdo_enclave
rm -f contract_enclave_mrenclave.cpp

cd $SRCDIR/pservice
make clean

yell --------------- CLIENT ---------------
cd $SRCDIR/client
make clean

yell --------------- CONTRACTS ---------------
cd $SRCDIR/contracts
make clean
