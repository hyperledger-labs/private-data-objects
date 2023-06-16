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
mkdir build
cd build
cmake .. -GNinja -DCCF_DIR=${CCF_BASE} -DCOMPILE_TARGET=virtual
ninja
```


## Deploy PDO TP

The following steps will use CCF provided `/opt/ccf_virtual/bin/sandbox.sh` script to deploy CCF app using default values for end point address, governance scripts. The script will also automatically generate CCF member certificates to be used for Governance. (the script most certainly has options to override these default values, need to study them)

```bash
cd ${PDO_SOURCE_ROOT}/ledgers/ccf/build
/opt/ccf_virtual/bin/sandbox.sh -p ${PDO_SOURCE_ROOT}/ledgers/ccf/build/libpdoenc
```

Carry out the rest of the steps in a new terminal on the same machine.

```bash
export PDO_LEDGER_URL=http://127.0.0.1:8000
export PDO_LEDGER_KEY_ROOT=${PDO_SOURCE_ROOT}/ledgers/ccf/build/workspace/sandbox_common/
cd ${PDO_LEDGER_KEY_ROOT}
cp service_cert.pem networkcert.pem
cp member0_cert.pem memberccf_cert.pem
cp member0_privk.pem memberccf_privk.pem
```

## Install PDO

Follow instructions at https://github.com/hyperledger-labs/private-data-objects/blob/main/docs/host_install.md to build PDO. Note that as part of PDO installation, we will install ccf==1.10.19 Python package as part of PDO's virtual environment. This package is required for futher steps described below.

If PDO is already installed on your system, please regenerate the PDO config files using the above values of PDO_LEDGER_URL and PDO_LEDGER_KEY_ROOT.


## Generate and Fetch Ledger Authority, Register Enclave Attestation Verification Policy

The following operations are done by CCF member prior to usage of the PDOT TP by PDO clients.

```bash
source ${PDO_SOURCE_ROOT}/build/_dev/bin/activate
cd ${PDO_SOURCE_ROOT}/ledgers/ccf/scripts/
python generate_ledger_authority.py
python fetch_ledger_authority.py
python register_enclave_attestation_verification_policy.py
```


## Test PDO

```bash
cd ${PDO_SOURCE_ROOT}/build/__tools__
./run-tests.sh
```
