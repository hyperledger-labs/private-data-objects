# ------------------------------------------------------------------------------
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
# ------------------------------------------------------------------------------

ARG PDO_VERSION
FROM pdo_base:${PDO_VERSION}

ARG UBUNTU_VERSION=22.04
ARG UBUNTU_NAME=jammy

ARG SGX=2.25
ARG OPENSSL=3.0.14
ARG SGXSSL=3.0_Rev4

RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu ${UBUNTU_NAME} main" >> /etc/apt/sources.list \
 && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
 && apt-get update \
 && apt-get install -y \
    # We do not need daemons like AESMD as we run them on host (side-steps also
    # issues with config of /etc/aesmd.conf like proxy ..). Without this option
    # aesmd and lots of other plugsin are automatically pulled in.
    # See SGX Installation notes and, in particular, linux/installer/docker/Dockerfile
    # in linux-sgx git repo of sdk/psw source.
    --no-install-recommends \
    libsgx-urts \
    libsgx-uae-service \
    libsgx-dcap-ql-dev \
    libsgx-dcap-quote-verify-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install SGX SDK
WORKDIR /opt/intel
RUN SGX_SDK_BIN_REPO=https://download.01.org/intel-sgx/sgx-linux/${SGX}/distro/ubuntu${UBUNTU_VERSION}-server \
  && SGX_SDK_BIN_FILE=$(wget -P /tmp --delete-after --spider --recursive --level=1 --no-parent ${SGX_SDK_BIN_REPO} 2>&1 | perl  -ne 'if (m|'${SGX_SDK_BIN_REPO}'/(sgx_linux_x64_sdk.*)|) { print "$1\n"; }') \
  && wget -q -P /tmp ${SGX_SDK_BIN_REPO}/${SGX_SDK_BIN_FILE} \
  && chmod +x /tmp/${SGX_SDK_BIN_FILE} \
  && echo -e "no\n/opt/intel" | /tmp/${SGX_SDK_BIN_FILE} \
  && rm /tmp/${SGX_SDK_BIN_FILE}

ENV SGX_SDK=/opt/intel/sgxsdk

# -----------------------------------------------------------------
# LVI mitigations, needed to compile sgxssl, requires a
#   recent version of binutils (>= 2.32). Ubuntu 18.04 only
#   has 2.30 but Intel ships binary distro for 2.32.51.20190719
# -----------------------------------------------------------------
WORKDIR /opt/intel
RUN SGX_SDK_BINUTILS_REPO=https://download.01.org/intel-sgx/sgx-linux/${SGX} \
  && SGX_SDK_BINUTILS_FILE=$(wget -P /tmp --delete-after --spider --recursive --level=1 --no-parent ${SGX_SDK_BINUTILS_REPO} 2>&1 | perl  -ne 'if (m|'${SGX_SDK_BINUTILS_REPO}'/(as.ld.objdump.*)|) { print "$1\n"; }') \
  && wget -q -P /tmp ${SGX_SDK_BINUTILS_REPO}/${SGX_SDK_BINUTILS_FILE} \
  && mkdir sgxsdk.extras \
  && cd sgxsdk.extras \
  && tar -zxf /tmp/${SGX_SDK_BINUTILS_FILE} \
  && rm /tmp/${SGX_SDK_BINUTILS_FILE}

ENV PATH="/opt/intel/sgxsdk.extras/external/toolset/ubuntu${UBUNTU_VERSION}:${PATH}"

# -----------------------------------------------------------------
# SGXSSL
# Note that the SGX_MODE variable only determines the mode for
# running tests. We do not want the tests to run in HW mode here.
# This allows us to keep this image mode-agnostic.
# -----------------------------------------------------------------
WORKDIR /tmp
RUN . /opt/intel/sgxsdk/environment \
    && git clone --depth 1 --branch ${SGXSSL} 'https://github.com/intel/intel-sgx-ssl.git' \
    && wget -q -P /tmp/intel-sgx-ssl/openssl_source https://www.openssl.org/source/openssl-${OPENSSL}.tar.gz \
    && cd /tmp/intel-sgx-ssl/Linux \
    && bash -c "make SKIP_INTELCPU_CHECK=TRUE SGX_MODE=SIM NO_THREADS=1 DESTDIR=/opt/intel/sgxssl VERBOSE=0 all &> /dev/null" \
    && make install \
    && make clean \
    && rm -rf /tmp/intel-sgx-ssl

ENV SGX_SSL="/opt/intel/sgxssl"


# -----------------------------------------------------------------
# SGX DCAP Primitives
# -----------------------------------------------------------------
RUN apt-get update
RUN apt-get install -y -q \
        libboost-dev \
        libboost-system-dev \
        libboost-thread-dev \
        protobuf-c-compiler \
        libprotobuf-c-dev \
        protobuf-compiler
RUN apt-get install -y \
        basez \
        clang \
        libsgx-dcap-default-qpl \
        #libsgx-dcap-default-qpl-dev adds libdcap_quoteprov.so and /usr/include/sgx_default_quote_provider.h
        libsgx-dcap-default-qpl-dev \
        jq

ARG DCAP=1.19
ENV DCAP_PRIMITIVES=/tmp/SGXDataCenterAttestationPrimitives

RUN git clone https://github.com/intel/SGXDataCenterAttestationPrimitives.git ${DCAP_PRIMITIVES} \
    && cd ${DCAP_PRIMITIVES}/QuoteVerification \
    && git checkout DCAP_${DCAP} \
    && git submodule update --init --recursive

RUN cd ${DCAP_PRIMITIVES}/QuoteGeneration \
        && ./download_prebuilt.sh \
        && make GEN_STATIC=1

# NOTE: below the build (./release) is run twice. Unfortunately, this is necessary because both builds fails
# when run separately in a clean environment, but succeed if they run in sequence, and produce the expected result.
# This issue has been communicated to the developers of the DCAP primitives.
RUN cd ${DCAP_PRIMITIVES}/QuoteVerification/QVL/Src \
    && ./release -DBUILD_ENCLAVE=ON -DBUILD_TESTS=OFF ; ./release -DBUILD_ENCLAVE=ON -DBUILD_ATTESTATION_APP=OFF -DBUILD_TESTS=OFF

RUN echo '{\n\
    "pccs_url": "https://localhost:8081/sgx/certification/v4/", \n\
    "collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/",\n\
    "use_secure_cert": false\n\
    }' > /etc/sgx_default_qcnl.conf


# -----------------------------------------------------------------
# -----------------------------------------------------------------
WORKDIR /project/pdo

ARG UNAME=pdo_services
ENV UNAME=${UNAME}

ARG UID=1000
ARG GID=$UID

RUN groupadd -f -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -d /project/pdo -o -s /bin/bash $UNAME
RUN chown --recursive $UNAME:$UNAME /project/pdo
USER $UNAME

#this is necessary for git operations such as "git describe --tags" from the new user
RUN git config --global --add safe.directory ${DCAP_PRIMITIVES}

ENTRYPOINT ["/bin/bash"]
