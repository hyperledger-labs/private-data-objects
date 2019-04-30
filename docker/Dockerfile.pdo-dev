# Copyright 2017 Intel Corporation
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

# Description:
#   Builds the environment with all prerequistes needed to build Private Data Objects.
#
#  Configuration (build) paramaters
#  - proxy configuration: 	https_proxy http_proxy ftp_proxy, no_proxy  (default: undefined)
#  - ubuntu base image to use: 	UBUNTU_VERSION (default: bionic)
#  - sgx sdk version: 		SGX_SDK (default: sgx_2.4)
#  - openssl version: 		OPENSSL (default: 1.1.0j)
#  - sgxssl version: 		SGXSSL  (default: v2.4.1)
#  - additional apt packages:	ADD_APT_PKGS (default: )

# Build:
#   $ docker build docker -f docker/Dockerfile.pdo-dev -t pdo-dev
#   if behind a proxy, you might want to add also below options
#   --build-arg https_proxy=$https_proxy --build-arg http_proxy=$http_proxy --build-arg ftp_proxy=$ftp_proxy --build-arg=$no_proxy
#   if you want to build with different version than 16.04/xenial, add a build arg UBUNTU_VERSION, e.g., for 18.04 do --build-arg UBUNTU_VERSION=bionic
#
# Run:
#   $ cd <directory where you checked out private-data-objects>
#   $ docker run -it pdo-dev
#   - to run with SGX HW, add options '--device=/dev/isgx -v /var/run/aesmd:/var/run/aesmd ')
#     then you can build system as "usual", e.g., to build it as
#        . /project/pdo/src/build/common-config.sh
#        make -C /project/pdo/src/build/
#     etc etc
#     Note: your host SGX PSW runtime should be at a similar level than the one in the container
#     or the PSW/aesmd might cause enclave launch problems
#   - if behind a proxy, you might want to add also below options
#     --env https_proxy=$https_proxy --env http_proxy=$http_proxy --env ftp_proxy=$ftp_proxy --env no_proxy=$no_proxy
#   - if you want to debug with gdb and alike, you also might want to add options
#     '--security-opt seccomp=unconfined --security-opt apparmor=unconfined --cap-add=SYS_PTRACE '
#   - for develooping based on source in host you might map source into container with an option
#     like -v $(pwd):/project/pdo/src/private-data-objects/

ARG UBUNTU_VERSION=bionic
# 16.04 -> xenial, 17.10 -> artful, 18.04 -> bionic
# NOTE: xenial might not work anymore (see below), preferred choice is bionic ..

FROM ubuntu:${UBUNTU_VERSION}

ARG UBUNTU_VERSION=bionic
# for bizare docker reason, we have to redefine it here ...

ARG SGX_SDK=sgx_2.4
ARG OPENSSL=1.1.0j
ARG SGXSSL=v2.4.1

ARG ADD_APT_PKGS=

# Add necessary packages
# TODO(xenial): we need to namnually install protobuf 3 as xenial has v2
# Note: ocamlbuild is required by PREREQ but does not exist for xenial. However, the relevant componets are part of 'ocaml' package, later ubuntu split up that package ...
RUN apt-get update \
 && apt-get install -y -q\
    autoconf \
    automake \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    dh-autoreconf \
    git \
    libcurl4-openssl-dev \
    liblmdb-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    make \
    ocaml \
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
    $ADD_APT_PKGS \
 && if [ "$UBUNTU_VERSION" = "bionic" ] || [ "$UBUNTU_VERSION" = "artful" ]; then \
	apt-get install -y -q libsecp256k1-dev ocamlbuild xxd; \
    fi \
 && apt-get -y -q upgrade \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
# environment variables
# we keep all definitions in '/etc/profile.d/pdo.sh'. Alas, this is called only for login shells
# so add it at least to /etc/bash.bashrc. Nothing equivalent seems to exist for dash/sh, which is used
# during build, so in that case we will have to explicitly '. /etc/profile.d/pdo.sh'.
# NOTE: There seems to be _nothing_ which is guaranteed to be always called, e.g., /etc/environment
#   also does not work as it is not always called
 && sed -i '1s;^;. /etc/profile.d/pdo.sh\n;' /etc/bash.bashrc

# Install SGX SDK
# we install from source as with binary distribution it's difficult to get library dependencies correct
# and work-around the somewhat hacky way we have to install PSW (where we really only need the rts libs
# but not the aesmd service which we assume to run in the host)
# Notes:
# - to make PSW installer work we have to
#   - disable test for presence of kernel modules (as during build we are not really seeing them)
#   - skip install and configure of aesmd service
# - install before openssl as this might cause additional trouble

RUN mkdir -p /opt/intel
WORKDIR /opt/intel
RUN git clone --branch ${SGX_SDK} https://github.com/01org/linux-sgx.git \
 && cd linux-sgx \
 && ./download_prebuilt.sh \
# installer usually refuses to install PSW without kernel module, hence override it here so we still can install it as at runtime driver might be there, just not at build time!
 && sed -i '1,$s;grep intel_sgx /lib/modules/$(uname -r)/modules.builtin &> /dev/null;true # grep intel_sgx /lib/modules/$(uname -r)/modules.builtin &> /dev/null;' linux/installer/bin/install-sgx-psw.bin.tmpl \
 && sed -i '1,$s;${SGX_PACKAGES_PATH}/${PSW_PKG_NAME}/scripts/install.sh;# ${SGX_PACKAGES_PATH}/${PSW_PKG_NAME}/scripts/install.sh;' linux/installer/bin/install-sgx-psw.bin.tmpl \
 && make \
 && make sdk_install_pkg \
 && make psw_install_pkg \
 && cd .. \
 && echo "yes" | ./linux-sgx/linux/installer/bin/sgx_linux_x64_sdk_*.bin \
 && ./linux-sgx/linux/installer/bin/sgx_linux_x64_psw_*.bin \
 && rm -rf linux-sgx \
 && echo ". /opt/intel/sgxsdk/environment" >> /etc/profile.d/pdo.sh

# ("Untrusted") OpenSSL
WORKDIR /tmp
RUN wget https://www.openssl.org/source/openssl-${OPENSSL}.tar.gz
# && tar -zxvf openssl-${OPENSSL}.tar.gz \
# && cd openssl-${OPENSSL}/ \
# && ./config \
# && THREADS=8 \
# && make -j$THREADS \
# && make test \
# && make install -j$THREADS \
# && ldconfig \
# && ln -s /etc/ssl/certs/* /usr/local/ssl/certs/ \
# && cd .. \
# && rm -rf openssl-${OPENSSL}
# Note: we do _not_ delete openssl-${OPENSSL}.tar.gz as we re-use it below ..


# ("trusted") SGX OpenSSL
# Note: This will compile in HW or SIM mode depending on the availability of
# /dev/isgx and /var/run/aesmd/aesm.socket
# Notes: there is no way to pass device /dev/isgx and socket (volume) /var/run/aesmd:/var/run/aesmd to docker
# at build time, However, as we only build libraries here, the mode does not matter for the actual build
# artifact and so we build with the safe SGX_MODE=SIM.  (It also means the build tests are run only in
# simulator but we count on the sgxssl team hopefully releasing only versions which work on both cases :-)
WORKDIR /tmp
RUN git clone  --branch ${SGXSSL} https://github.com/intel/intel-sgx-ssl.git \
 && . /opt/intel/sgxsdk/environment \
 && (cd intel-sgx-ssl/openssl_source; mv /tmp/openssl-${OPENSSL}.tar.gz . ) \
 && (cd intel-sgx-ssl/Linux; make SGX_MODE=SIM DESTDIR=/opt/intel/sgxssl all test ) \
 && (cd intel-sgx-ssl/Linux; make install ) \
 && rm -rf /tmp/intel-sgx-ssl \
 && echo "export SGX_SSL=/opt/intel/sgxssl" >> /etc/profile.d/pdo.sh

# Install Tinyscheme
RUN mkdir -p /opt/tinyscheme
WORKDIR /opt/tinyscheme
RUN wget https://downloads.sourceforge.net/project/tinyscheme/tinyscheme/tinyscheme-1.41/tinyscheme-1.41.zip \
 && unzip tinyscheme-1.41.zip \
 && rm tinyscheme-1.41.zip  \
 && cd tinyscheme-1.41  \
 && make FEATURES='-DUSE_DL=1 -DUSE_PLIST=1' \
 && echo "export TINY_SCHEME_SRC=$(pwd)" >> /etc/profile.d/pdo.sh

# environment setup as required by PDO
# Note
# - though this works though only for docker run, if you derive images from
#   this one you might have to specify explicitly variables like PDO_HOME,
#   PDO_ENCLAVE & SGX_MODE!
# - make sure /etc/environment is always included for bash
RUN \
    mkdir -p /project/pdo \
 && echo "export PDO_INSTALL_ROOT=/project/pdo/build" >> /etc/profile.d/pdo.sh \
 && echo "export PDO_HOME=/project/pdo/build/opt/pdo" >> /etc/profile.d/pdo.sh \
 && echo "export PDO_ENCLAVE_CODE_SIGN_PEM=/project/pdo/enclave.pem" >> /etc/profile.d/pdo.sh \
 && openssl genrsa -3 3072 > /project/pdo/enclave.pem \
 && echo "if ([ -c /dev/isgx ] && [ -S /var/run/aesmd/aesm.socket ]); then export SGX_MODE=HW; else export SGX_MODE=SIM; fi;" >> /root/.bashrc

WORKDIR /project/pdo/

ENTRYPOINT ["/bin/bash"]
