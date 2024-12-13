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

# syntax = docker/dockerfile:experimental
# above enable build-kit extension for 'RUN --mount=type= ..' extension used below
# to cache pip downloads between builds, cutting down noticeably build time.
# Note that cache is cleaned with the "uusal" docker prune commans, e.g., docker builder prune.

ARG PDO_VERSION=latest
FROM pdo_base:${PDO_VERSION}

# -----------------------------------------------------------------
# set up the PDO sources
# -----------------------------------------------------------------
ARG REBUILD=0

ARG PDO_DEBUG_BUILD=1
ENV PDO_DEBUG_BUILD=${PDO_DEBUG_BUILD}

ARG PDO_LEDGER_TYPE=ccf
ENV PDO_LEDGER_TYPE=${PDO_LEDGER_TYPE}

ARG PDO_INTERPRETER=wawaka
ENV PDO_INTERPRETER=${PDO_INTERPRETER}

ARG PDO_LOG_LEVEL=info
ENV PDO_LOG_LEVEL=${PDO_LOG_LEVEL}

# -----------------------------------------------------------------
# use the identity created in the base container
# -----------------------------------------------------------------
ARG UNAME=pdo_user
ENV UNAME=${UNAME}

USER $UNAME

# -----------------------------------------------------------------
# -----------------------------------------------------------------
# copy the source files into the image
WORKDIR /project/pdo
COPY --chown=${UNAME}:${UNAME} repository /project/pdo/src

# copy the tools because we want to be able to
# use them even without a mount point after the
# container is created
WORKDIR /project/pdo/tools
COPY --chown=${UNAME}:${UNAME} tools/*.sh ./

# build it!!!
RUN --mount=type=cache,target=/project/pdo/.cache/pip \
    /project/pdo/tools/build_client.sh

RUN rm -f /project/pdo/.bashrc; ln -s /project/pdo/tools/bashrc_client.sh /project/pdo/.bashrc

ENTRYPOINT [ "/bin/bash" ]
