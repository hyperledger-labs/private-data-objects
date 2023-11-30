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

FROM pdo_base

ARG UBUNTU_VERSION=20.04
ARG UBUNTU_NAME=focal

ARG SGX=2.22
ARG OPENSSL=3.0.12
ARG SGXSSL=3.0_Rev1

ARG SGX_MODE SIM
ENV SGX_MODE $SGX_MODE

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
RUN [ "$UBUNTU_VERSION" = "20.04" ] \
  && SGX_SDK_BINUTILS_REPO=https://download.01.org/intel-sgx/sgx-linux/${SGX} \
  && SGX_SDK_BINUTILS_FILE=$(wget -P /tmp --delete-after --spider --recursive --level=1 --no-parent ${SGX_SDK_BINUTILS_REPO} 2>&1 | perl  -ne 'if (m|'${SGX_SDK_BINUTILS_REPO}'/(as.ld.objdump.*)|) { print "$1\n"; }') \
  && wget -q -P /tmp ${SGX_SDK_BINUTILS_REPO}/${SGX_SDK_BINUTILS_FILE} \
  && mkdir sgxsdk.extras \
  && cd sgxsdk.extras \
  && tar -zxf /tmp/${SGX_SDK_BINUTILS_FILE} \
  && rm /tmp/${SGX_SDK_BINUTILS_FILE}

ENV PATH="/opt/intel/sgxsdk.extras/external/toolset/ubuntu${UBUNTU_VERSION}:${PATH}"

# -----------------------------------------------------------------
# SGXSSL
# Note that we build sgxssl with SIM mode; the SGX_MODE only changes
# the mode for running tests and we do not want the tests run in HW
# mode
# -----------------------------------------------------------------
WORKDIR /tmp
RUN . /opt/intel/sgxsdk/environment \
    && git clone --depth 1 --branch ${SGXSSL} 'https://github.com/intel/intel-sgx-ssl.git' \
    && wget -q -P /tmp/intel-sgx-ssl/openssl_source https://www.openssl.org/source/openssl-${OPENSSL}.tar.gz \
    && cd /tmp/intel-sgx-ssl/Linux \
    && bash -c "make SGX_MODE=SIM NO_THREADS=1 DESTDIR=/opt/intel/sgxssl VERBOSE=0 all &> /dev/null" \
    && make install \
    && make clean \
    && rm -rf /tmp/intel-sgx-ssl

ENV SGX_SSL="/opt/intel/sgxssl"

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

ENTRYPOINT ["/bin/bash"]
