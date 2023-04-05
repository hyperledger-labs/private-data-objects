FROM pdo_services_base

# -----------------------------------------------------------------
# set up the PDO sources
# -----------------------------------------------------------------
ARG REBUILD 0

ARG PDO_REPO_URL=https://github.com/hyperledger-labs/private-data-objects.git
ARG PDO_REPO_BRANCH=main

ARG PDO_DEBUG_BUILD=0
ENV PDO_DEBUG_BUILD=${PDO_DEBUG_BUILD}

ARG PDO_LEDGER_TYPE=ccf
ENV PDO_LEDGER_TYPE=${PDO_LEDGER_TYPE}

ARG PDO_INTERPRETER=wawaka
ENV PDO_INTERPRETER=${PDO_INTERPRETER}

ARG WASM_MEM_CONFIG=MEDIUM
ENV WASM_MEM_CONFIG=${WASM_MEM_CONFIG}

# copy the tools because we want to be able to
# use them even without a mount point after the
# container is created
WORKDIR /project/pdo/tools
COPY tools/*.sh ./

WORKDIR /project/pdo
RUN git clone --single-branch --branch ${PDO_REPO_BRANCH} --recurse-submodules ${PDO_REPO_URL} src \
    && tools/build_services.sh

# Network ports for running services
EXPOSE 7001 7002 7003 7004 7005
EXPOSE 7101 7102 7103 7104 7105
EXPOSE 7201 7202 7203 7204 7205

ARG PDO_HOSTNAME
ENV PDO_HOSTNAME=$PDO_HOSTNAME

ARG PDO_LEDGER_URL
ENV PDO_LEDGER_URL=$PDO_LEDGER_URL

# Note that the entry point when specified with exec syntax
# can be extended through the docker run interface far more
# easily than if you use the other specification format of
# a single string
WORKDIR /project/pdo
ENTRYPOINT ["/project/pdo/tools/start_services.sh"]
