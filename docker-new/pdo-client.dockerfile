FROM pdo-base

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

WORKDIR /project/pdo/tools
COPY tools/environment.sh ./
COPY tools/build_client.sh ./
COPY tools/start_client.sh ./
COPY tools/run_client_tests.sh ./

WORKDIR /project/pdo
RUN git clone --single-branch --branch ${PDO_REPO_BRANCH} --recurse-submodules ${PDO_REPO_URL} src \
    && tools/build_client.sh

ARG PDO_HOSTNAME
ENV PDO_HOSTNAME=$PDO_HOSTNAME

ARG PDO_LEDGER_URL
ENV PDO_LEDGER_URL=$PDO_LEDGER_URL

ENTRYPOINT /project/pdo/tools/start_client.sh
