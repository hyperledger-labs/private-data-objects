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
ARG UBUNTU_VERSION=22.04
ARG UBUNTU_NAME=jammy

FROM ubuntu:${UBUNTU_VERSION}

ENV TERM=screen-256color

# -----------------------------------------------------------------
# Install base packages
# -----------------------------------------------------------------
ARG ADD_APT_PKGS=

ENV DEBIAN_FRONTEND="noninteractive"
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update \
    && apt-get install -y -q --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        dh-autoreconf \
        git \
        gnupg \
        libcurl4-openssl-dev \
        liblmdb-dev \
        libprotobuf-dev \
        libsecp256k1-dev \
        libssl-dev \
        libtool \
        make \
        ocaml \
        ocamlbuild \
        pkg-config \
        protobuf-compiler \
        python3 \
        python3-dev \
        python3-venv \
        python3-virtualenv \
        software-properties-common \
        swig \
        tar \
        unzip \
        virtualenv \
        wget \
        xxd \
        net-tools \
        dnsutils \
        ${ADD_APT_PKGS} \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------
# Install WASI toolkit
# -----------------------------------------------------------------
ARG WASI_VERSION=24
ARG WASI_PACKAGE="wasi-sdk-${WASI_VERSION}.0-x86_64-linux.deb"

WORKDIR /tmp
RUN wget -q https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/${WASI_PACKAGE} \
    && dpkg --install ${WASI_PACKAGE} \
    && rm ${WASI_PACKAGE}

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
# Prep for the installation
# -----------------------------------------------------------------
USER $UNAME

WORKDIR /project/pdo/tools
COPY tools/environment.sh ./
