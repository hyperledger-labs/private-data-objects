FROM pdo_base

# -----------------------------------------------------------------
# -----------------------------------------------------------------
WORKDIR /project/pdo

ARG UNAME=pdo_client
ARG UID=1000
ARG GID=$UID

RUN groupadd -f -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -d /project/pdo -o -s /bin/bash $UNAME
RUN chown --recursive $UNAME:$UNAME /project/pdo
USER $UNAME

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
    && tools/build_client.sh

ARG PDO_HOSTNAME
ENV PDO_HOSTNAME=$PDO_HOSTNAME

ARG PDO_LEDGER_URL
ENV PDO_LEDGER_URL=$PDO_LEDGER_URL

# the client is set up for interactive access; the environment can be
# set up by source /project/pdo/tools/start_client.sh with the arguments
# to build a new client environment or copy one from the xfer directory
ENTRYPOINT [ "/bin/bash" ]
