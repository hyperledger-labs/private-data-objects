#!/bin/bash

source /opt/intel/sgxsdk/environment
source /project/pdo/tools/environment.sh

# these variables should be unused during build
export PDO_HOSTNAME=
export PDO_LEDGER_URL=

make -C ${PDO_SOURCE_ROOT}/build environment
make -C ${PDO_SOURCE_ROOT}/build template
make -C ${PDO_SOURCE_ROOT}/build system-keys
make -C ${PDO_SOURCE_ROOT}/build verified-build
