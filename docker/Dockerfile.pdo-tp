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
#   Build Container for PDO Sawtooth Transaction Processor
#   (As Sawtooth requires Ubuntu 16.04 xenial and doesn't support 18.04 and PDO does support
#    only 18.04 we need a separate container from the main PDO container pdo-build)
#
#  Configuration (build) paramaters
#  - proxy configuration:               https_proxy http_proxy ftp_proxy  (default: undefined)
#  - pdo repo to use:                   PDO_REPO_URL  (default: https://github.com/hyperledger-labs/private-data-objects.git)
#  - pdo repo branch to use:            PDO_REPO_BRANCH (default: master)

# Build:
#   $ docker build -f docker/Dockerfile.pdo-tp -t pdo-tp docker
#   if behind a proxy, you might want to add also below options
#   --build-arg https_proxy=$https_proxy --build-arg http_proxy=$http_proxy --build-arg ftp_proxy=$ftp_proxy
#   if you want to build with the source locally commented, then use root-directory of
#   source tree as context directory and add '--build-arg PDO_REPO_URL=file:///tmp/build-src/.git', e.g.,
#      docker build -f docker/Dockerfile.pdo-dev -t pdo-build --build-arg PDO_REPO_URL=file:///tmp/build-src/.git .
#
# Run:
#   $ cd ....../private-datdda-objects
#   $ docker run -it pdo-tp
#   Notes:
#   - if behind a proxy, you might want to add also below options
#     --env https_proxy=$https_proxy --env http_proxy=$http_proxy --env ftp_proxy=$ftp_proxy
#

# Get source of PDO
# to allow using local development branch we copy whatever docker directory is passed
# (and so would contain .git if we call it as docker build . -f docker/.... which then
# can be used via PDO_REPO_BRANCH build-arg) but also do that via multi-stage so we don't load
# the whole stuff into the image itself.
FROM hyperledger/sawtooth-intkey-tp-python:1.0 as source-extractor

RUN apt-get update && apt-get install -y git

ARG PDO_REPO_URL=https://github.com/hyperledger-labs/private-data-objects.git
ARG PDO_REPO_BRANCH=master

RUN mkdir /tmp/build-src
COPY . /tmp/build-src

WORKDIR /project/pdo/

RUN mkdir src && cd src \
 && git clone --single-branch --branch ${PDO_REPO_BRANCH} ${PDO_REPO_URL} private-data-objects


FROM hyperledger/sawtooth-intkey-tp-python:1.0

COPY --from=source-extractor /project/pdo /project/pdo

# Get dependencies
RUN apt-get update \
  && apt-get install -y \
    curl wget \
    git \
    python3-cryptography \
    python3-sawtooth-* \
    zip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* \
  && cd /tmp \
  && curl -OL https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip \
  && unzip protoc-3.2.0-linux-x86_64.zip -d protoc-3 \
  && mv protoc-3/bin/* /usr/local/bin/ \
  && mv protoc-3/include/* /usr/local/include/ \
  && rm -rf protoc*

# Build
RUN cd /project/pdo/src/private-data-objects \
  && (cd common/crypto/verify_ias_report; ./build_ias_certificates_cpp.sh) \
  && sawtooth/bin/build_sawtooth_proto

CMD /project/pdo/src/private-data-objects/sawtooth/bin/pdo-tp -v -v --connect tcp://validator:4004 --debug-on
