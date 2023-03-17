# syntax=docker/dockerfile:1

ARG CCF_VERSION=1.0.19
FROM ccfciteam/ccf-app-ci:${CCF_VERSION}
#FROM ccfciteam/ccf-app-ci:1.0.19

ENV TERM=screen-256color

# -----------------------------------------------------------------
# Install base packages
# -----------------------------------------------------------------
ARG ADD_APT_PKGS=

ENV DEBIAN_FRONTEND "noninteractive"
RUN apt-get update \
    && apt-get install -y -q \
        python \
        python3-dev \
        python3-venv \
        python3-virtualenv \
        virtualenv \
        net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------
# set up the PDO sources
# -----------------------------------------------------------------
ARG REBUILD 0

ARG SGX_MODE SIM
ENV SGX_MODE=$SGX_MODE

ARG PDO_REPO_URL=https://github.com/hyperledger-labs/private-data-objects.git
ARG PDO_REPO_BRANCH=main

ARG PDO_DEBUG_BUILD=0
ENV PDO_DEBUG_BUILD=${PDO_DEBUG_BUILD}

# XFER_DIR is the directory where the networkcert.pem file is
# stored; ccf will write the file and other containers will read it
ARG XFER_DIR=/project/pdo/xfer
ENV XFER_DIR=${XFER_DIR}

WORKDIR /project/pdo/tools
COPY tools/environment.sh ./
COPY tools/build_ccf.sh ./
COPY tools/start_ccf.sh ./
COPY tools/run_ccf_tests.sh ./

WORKDIR /project/pdo
RUN git clone --single-branch --branch ${PDO_REPO_BRANCH} --recurse-submodules ${PDO_REPO_URL} src \
    && tools/build_ccf.sh

# Network ports for running services
EXPOSE 6600

ARG PDO_HOSTNAME
ENV PDO_HOSTNAME=$PDO_HOSTNAME

ARG PDO_LEDGER_URL
ENV PDO_LEDGER_URL=$PDO_LEDGER_URL

ENTRYPOINT /project/pdo/tools/start_ccf.sh