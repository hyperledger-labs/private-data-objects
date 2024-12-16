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
# syntax=docker/dockerfile:1

ARG CCF_VERSION=4.0.1-virtual
FROM mcr.microsoft.com/ccf/app/dev:${CCF_VERSION}

ARG REBUILD=0
ARG UBUNTU_VERSION=20.04
ARG UBUNTU_NAME=focal

ENV TERM=screen-256color

USER root

# -----------------------------------------------------------------
# Install base packages
# -----------------------------------------------------------------
ARG ADD_APT_PKGS=

ENV DEBIAN_FRONTEND="noninteractive"
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y -q --no-install-recommends \
        libsecp256k1-dev \
        lsof \
        python \
        python3-dev \
        python3-venv \
        python3-virtualenv \
        virtualenv \
        net-tools \
        wget \
        ${ADD_APT_PKGS}

RUN echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu ${UBUNTU_NAME} main" >> /etc/apt/sources.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y --no-install-recommends \
        sgx-aesm-service \
        libsgx-dcap-ql \
        libsgx-urts \
        libsgx-uae-service \
        libsgx-headers

RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------
# Create the pdo_user account and group that will be used for
# future installations into the pdo install directory
# -----------------------------------------------------------------
ARG UNAME=pdo_user
ENV UNAME=${UNAME}

ARG UID=1000
ARG GID=$UID

RUN groupadd -f -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -d /project/pdo -o -s /bin/bash $UNAME

# -----------------------------------------------------------------
USER $UNAME

WORKDIR /project/pdo
ENTRYPOINT ["/bin/bash"]
