#!/bin/bash
# Copyright 2024 Intel Corporation
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

set -e

apt-get update

# install quote library, necessary for dcap attestation generation
# install quote verify library, necessary for attestation conversion and verification
# (though inside the enclave we use the static libraries of DCAP)
apt-get install -y \
    --no-install-recommends \
    libsgx-dcap-ql-dev \
    libsgx-dcap-quote-verify-dev

# -----------------------------------------------------------------
# SGX DCAP Primitives
# -----------------------------------------------------------------
apt-get install -y -q \
    libboost-dev \
    libboost-system-dev \
    libboost-thread-dev \
    protobuf-c-compiler \
    libprotobuf-c-dev \
    protobuf-compiler

# Note: libsgx-dcap-default-qpl-dev adds libdcap_quoteprov.so and /usr/include/sgx_default_quote_provider.h
apt-get install -y \
    basez \
    clang \
    libsgx-dcap-default-qpl \
    libsgx-dcap-default-qpl-dev \
    jq

export DCAP=1.22

git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git ${DCAP_PRIMITIVES} \
    && cd ${DCAP_PRIMITIVES}/QuoteVerification \
    && git checkout DCAP_${DCAP} \
    && git submodule update --init --recursive

cd ${DCAP_PRIMITIVES}/QuoteGeneration \
    && ./download_prebuilt.sh \
    && make GEN_STATIC=1

# NOTE: below the build (./release) is run twice. Unfortunately, this is necessary because both builds fails
# when run separately in a clean environment, but succeed if they run in sequence, and produce the expected result.
# This issue has been communicated to the developers of the DCAP primitives. 
cd ${DCAP_PRIMITIVES}/QuoteVerification/QVL/Src
./release -DBUILD_ENCLAVE=ON -DBUILD_TESTS=OFF || true
./release -DBUILD_ENCLAVE=ON -DBUILD_ATTESTATION_APP=OFF -DBUILD_TESTS=OFF

# set up the qcnl to connect to the local pccs for dcap verification collateral
echo '{\n\
    "pccs_url": "https://localhost:8081/sgx/certification/v4/", \n\
    "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",\n\
    "use_secure_cert": false\n\
    }' > /etc/sgx_default_qcnl.conf

