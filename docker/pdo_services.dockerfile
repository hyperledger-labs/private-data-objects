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
FROM pdo_services_base:${PDO_VERSION}

# -----------------------------------------------------------------
# set up the PDO sources
# -----------------------------------------------------------------
ARG REBUILD=0

ARG SGX_MODE=SIM
ENV SGX_MODE=$SGX_MODE

ARG PDO_DEBUG_BUILD=1
ENV PDO_DEBUG_BUILD=${PDO_DEBUG_BUILD}

ARG PDO_LEDGER_TYPE=ccf
ENV PDO_LEDGER_TYPE=${PDO_LEDGER_TYPE}

ARG PDO_INTERPRETER=wawaka
ENV PDO_INTERPRETER=${PDO_INTERPRETER}

ARG PDO_MEMORY_CONFIG=MEDIUM
ENV PDO_MEMORY_CONFIG=${PDO_MEMORY_CONFIG}

ARG PDO_LOG_LEVEL=info
ENV PDO_LOG_LEVEL=${PDO_LOG_LEVEL}

# copy the source files into the image using the user
# identity that was created in the base container
ARG UNAME=pdo_user
ENV UNAME=${UNAME}

USER $UNAME
WORKDIR /project/pdo
COPY --chown=${UNAME}:${UNAME} repository /project/pdo/src

# copy the tools because we want to be able to
# use them even without a mount point after the
# container is created
WORKDIR /project/pdo/tools
COPY --chown=${UNAME}:${UNAME} tools/*.sh ./

# build it!
RUN --mount=type=cache,target=/project/pdo/.cache/pip \
    /project/pdo/tools/build_services.sh

# Network ports for running services
EXPOSE 7001 7002 7003 7004 7005
EXPOSE 7101 7102 7103 7104 7105
EXPOSE 7201 7202 7203 7204 7205

# Note that the entry point when specified with exec syntax
# can be extended through the docker run interface far more
# easily than if you use the other specification format of
# a single string
WORKDIR /project/pdo
ENTRYPOINT ["/project/pdo/tools/start_services.sh"]
