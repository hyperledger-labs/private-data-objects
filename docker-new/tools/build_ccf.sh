#!/bin/bash

source /project/pdo/tools/environment.sh

# these variables should be unused during build
export PDO_HOSTNAME=
export PDO_LEDGER_URL=

make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor environment
make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor keys
make -C ${PDO_SOURCE_ROOT}/ccf_transaction_processor install
