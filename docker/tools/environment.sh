#!/bin/bash
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

# -----------------------------------------------------------------
# This script initializes the default environment. All variables
# should be set to reasonable defaults. The first five are expected
# to be set through the dockerfiles build arguments.
# -----------------------------------------------------------------

# these variables may be configured to change the behavior of the image
# all should be set through the build variables in the dockerfiles.
export SGX_MODE=${SGX_MODE:-SIM}
export PDO_LEDGER_TYPE=${PDO_LEDGER_TYPE:-ccf}
export PDO_INTERPRETER=${PDO_INTERPRETER:-wawaka}
export WASM_MEM_CONFIG=${WASM_MEM_CONFIG:-MEDIUM}
export PDO_DEBUG_BUILD=${PDO_DEBUG_BUILD:-0}

# these variables are internal to the layout of the container and immutable
export PDO_SOURCE_ROOT=/project/pdo/src
export PDO_INSTALL_ROOT=/project/pdo/run
export PDO_HOME=${PDO_INSTALL_ROOT}/opt/pdo

export PDO_LEDGER_KEY_ROOT=${PDO_HOME}/keys/ledger
export PDO_LEDGER_KEY_SKF=${PDO_LEDGER_KEY_ROOT}/pdo_validator.priv
export WASM_SRC="${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime"

if [ ${PDO_LEDGER_TYPE,,} = "ccf" ]; then
    export PDO_DEFAULT_SIGCURVE=SECP384R1
else
    export PDO_DEFAULT_SIGCURVE=SECP256K1
fi

export XFER_DIR=${XFER_DIR:-/project/pdo/xfer}

export PDO_SGX_KEY_ROOT=${PDO_SOURCE_ROOT}/build/keys/sgx_mode_${SGX_MODE,,}

# set up the ccf directories, ccf_base is where the ccf
# core is installed, ccf_pdo_dir is where the pdo tp
# components will be installed, and ccf_ledger_dir is
# where the ccf python virtual environment will be built
export CCF_BASE=/opt/ccf_virtual
export CCF_PDO_DIR=${PDO_INSTALL_ROOT}
export CCF_LEDGER_DIR=${PDO_HOME}/ccf
