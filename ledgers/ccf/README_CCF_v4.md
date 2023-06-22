<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Microsoft CCF based PDO Transaction Processor


This document explains how to deploy PDO TP built out of CCF version 4.0.1, and use it for local PDO testing and development. CCF upgrade to version 4.0.1 is work in progress, and not yet ready for docker testing or remote-node CCF deployment. Also, not tested behind a proxy.

## Install CCF


```bash
git clone https://github.com/microsoft/CCF.git
cd CCF
git checkout ccf-4.0.1
cd getting_started/setup_vm/
./run.sh app-dev.yml --extra-vars "platform=virtual" --extra-vars "clang_version=15" --extra-vars "ccf_ver=4.0.1"
sudo apt-get install -y sgx-aesm-service libsgx-urts libsgx-uae-service
export CCF_BASE=/opt/ccf_virtual/
```


## Build PDO TP

```bash
source ${PDO_SOURCE_ROOT}/build/common-config.sh
cd ${PDO_SOURCE_ROOT}/ledgers/ccf
make
```


## Deploy PDO TP

The following steps will start a single node ledger available for transactions at `PDO_LEDGER_URL`. We use the CCF provided `/opt/ccf_virtual/bin/sandbox.sh` script to deploy CCF app using default values for end point address, governance scripts. The script will also automatically generate CCF member certificates to be used for Governance. The start script will automatically copy thekeys to `PDO_LEDGER_KEY_ROOT`.

```bash
source $PDO_HOME/ccf/bin/activate
$PDO_HOME/ccf/bin/start_ccf_network.sh
```

## Test PDO

```bash
source $PDO_INSTALL_ROOT/_dev/bin/activate
cd ${PDO_SOURCE_ROOT}/build/__tools__
./run-tests.sh
```

## Stop PDO TP
```bash
$PDO_HOME/ccf/bin/stop_cchost.sh
```