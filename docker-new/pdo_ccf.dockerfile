# syntax=docker/dockerfile:1

FROM pdo_ccf_base

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

# copy the tools because we want to be able to
# use them even without a mount point after the
# container is created
WORKDIR /project/pdo/tools
COPY tools/*.sh ./

WORKDIR /project/pdo
RUN git clone --single-branch --branch ${PDO_REPO_BRANCH} --recurse-submodules ${PDO_REPO_URL} src \
    && tools/build_ccf.sh

# Network ports for running services
EXPOSE 6600

ARG PDO_HOSTNAME
ENV PDO_HOSTNAME=$PDO_HOSTNAME

ARG PDO_LEDGER_URL
ENV PDO_LEDGER_URL=$PDO_LEDGER_URL

# Note that the entry point when specified with exec syntax
# can be extended through the docker run interface far more
# easily than if you use the other specification format of
# a single string
ENTRYPOINT ["/project/pdo/tools/start_ccf.sh"]
