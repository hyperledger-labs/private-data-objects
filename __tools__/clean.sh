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
SRCDIR="$(realpath ${SCRIPTDIR}/..)"

# --------------- COMMON ---------------
cd $SRCDIR/common
rm -rf build

# --------------- PYTHON ---------------
cd $SRCDIR/python
make clean

# --------------- ESERVICE ---------------
cd $SRCDIR/eservice
make clean

# --------------- PSERVICE ---------------
cd $SRCDIR/pservice
make clean

# --------------- CLIENT ---------------
cd $SRCDIR/client
make clean

# --------------- CONTRACTS ---------------
cd $SRCDIR/contracts
make clean
