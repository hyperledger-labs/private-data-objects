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

ARG PDO_VERSION
FROM pdo_ccf_base:${PDO_VERSION}

# -----------------------------------------------------------------
# set up the PDO sources
# -----------------------------------------------------------------
ARG REBUILD=0

ARG SGX_MODE=SIM
ENV SGX_MODE=$SGX_MODE

ARG PDO_DEBUG_BUILD=1
ENV PDO_DEBUG_BUILD=${PDO_DEBUG_BUILD}

# XFER_DIR is the directory where the networkcert.pem file is
# stored; ccf will write the file and other containers will read it
ARG XFER_DIR=/project/pdo/xfer
ENV XFER_DIR=${XFER_DIR}

# copy the source files into the image
WORKDIR /project/pdo
COPY --chown=${UNAME}:${UNAME} repository /project/pdo/src

# copy the tools because we want to be able to
# use them even without a mount point after the
# container is created
WORKDIR /project/pdo/tools
COPY --chown=${UNAME}:${UNAME} tools/*.sh ./

# build it!!!
ARG UID=1000
ARG GID=${UID}
RUN --mount=type=cache,uid=${UID},gid=${GID},target=/project/pdo/.cache/pip \
    /project/pdo/tools/build_ccf.sh

# Network ports for running services
EXPOSE 6600

# can be extended through the docker run interface far more
# easily than if you use the other specification format of
# a single string
WORKDIR /project/pdo
ENTRYPOINT ["/project/pdo/tools/start_ccf.sh"]
