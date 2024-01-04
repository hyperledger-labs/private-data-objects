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
ARG UBUNTU_VERSION=20.04
ARG UBUNTU_NAME=focal

FROM ubuntu:${UBUNTU_VERSION}

ENV TERM=screen-256color

# -----------------------------------------------------------------
# Install base packages
# -----------------------------------------------------------------
ARG ADD_APT_PKGS=

ENV DEBIAN_FRONTEND "noninteractive"
RUN apt-get update \
    && apt-get install -y -q \
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
        python \
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
##ARG WASI_VERSION=12
ARG WASI_VERSION=21
ARG WASI_PACKAGE="wasi-sdk_${WASI_VERSION}.0_amd64.deb"

WORKDIR /tmp
RUN wget -q https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_VERSION}/${WASI_PACKAGE} \
    && dpkg --install ${WASI_PACKAGE} \
    && rm ${WASI_PACKAGE}

WORKDIR /project/pdo/tools
COPY tools/environment.sh ./
