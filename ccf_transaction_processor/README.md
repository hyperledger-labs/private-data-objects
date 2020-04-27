<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Microsoft CCF based PDO Transaction Processor

This folder contains software for PDO transaction processor (TP) based
on Microsoft's CCF blockchain.  The software is located under
$PDO_SOURCE_ROOT/transaction_processor/. The TP software is written and
tested for CCF tag 0.9.2. Compatibility with other CCF versions is not
guaranteed.

The instructions below  can be used to build and deploy CCF based PDO
TP. Make sure the following env variables are defined:

1) PDO_SOURCE_ROOT : points to PDO local git repo directory.

2) PDO_INSTALL_ROOT : CCF will be installed at PDO_INSTALL_ROOT/opt/pdo/ccf/.

3) PDO_HOME : `export PDO_HOME=${PDO_INSTALL_ROOT}/opt/pdo/`.

4) HOSTNAME : CCF's first node will be deployed at HOSTNAME:6006. One can simply set HOSTNAME to be the ip address
of the VM that can be used to ping the VM from other machines.

## Get CCF Source Code

CCF tag 0.9.2 is included as a submodule within PDO. Download the
submodule using the following commands:

```bash
cd $PDO_SOURCE_ROOT
git submodule init
git submodule update
```

## Install CCF Dependencies

CCF/PDO combo has been tested under a scenario where CCF is deployed in
a standalone VM, and where PDO cients/services are deployed at other VMs.
Further, the CCF/PDO combo has been tested only for the CCF virtual enclave mode.
The dependencies needed to deploy CCF in an Ubuntu 18.04 VM with virtual enclave mode can be installed by running
the following command:

```bash
cd $PDO_SOURCE_ROOT/ccf_transaction_processor/CCF/getting_started/setup_vm/
./setup_nodriver.sh
```

The above script works only when the VM is not behind any proxies. If
there are proxies, make the following changes before executing the above
command:

A. In the setup_nosgx.sh file, modify the command
`sudo add-apt-repository ppa:ansible/ansible -y`
by adding the `-E` option. The modified command looks like
`sudo -E add-apt-repository ppa:ansible/ansible -y`.
Add a `sudo` prefix to the
`ansible-playbook ccf-dependencies-no-driver.yml`
command appearing in the same file.

B. In ccf-dependencies-no-driver.yml (present under the same folder),
add the environment option for proxies (see
https://docs.ansible.com/ansible/latest/user_guide/playbooks_environment.html
for reference)

```bash
environment:
    http_proxy: <specify-http-proxy-here>
    https_proxy: <specify-https-proxy-here>
```

C. Add the repo used by ansible scripts for installing python 3.7

```bash
sudo add-apt-repository ppa:deadsnakes/ppa
```

## Build and Install

To build CCF and the PDO-TP the PDO environment variables must be
set. See the PDO configuration script for more information.

To build and install CCF and the PDO-TP,
```bash
cd ${PDO_SOURCE_ROOT}/ccf_transaction_processor
make clean
make
```

## Configure

See the CCF documentation for information about configuring CCF. The
`cchost` configuration file used by the PDO control scripts can be found
at `${PDO_HOME}/ccf/etc/cchost.toml`. The CCF governance script can be
found at `${PDO_HOME}/ccf/etc/gov.lua`.


## Start/Stop CCF Network

You can start a new CCF network with the PDO transaction processor using
the script at `${PDO_HOME}/ccf/bin/start_ccf_network.sh`. That script
will start the first node in the CCF network, open the network, add the
user account that will be used for other PDO transactions, and generate
the ledger authority key. The ledger authority key will be stored in the
file `${PDO_HOME}/ccf/keys/ledger_authority_pub.pem`. This key can be
used to verify claims about the state of the ledger.

Note that a CCF network must run continuously; it cannot be fully
stopped and restarted. Directions for adding additional nodes will be
forthcoming.

The script `${PDO_HOME}/ccf/bin/stop_cchost.sh` can be used to stop the
instance of `cchost` running on the local server.

## Share CCF (TLS) Authentication Keys

CCF uses mutually authenticated TLS channels for transactions. Keys are
located at `$PDO_HOME/ccf/keys`. The network certificate is
`networkcert.pem`. User public certificate is `user0_cert.pem` and
private key is `user0_privk.pem`.  Note that the keys are created as
part of CCF deployment and are unique to the specific instance of CCF.

In our usage, CCF users are PDO clients, and PDO client authentication
is implemented within the transaction processor itself. Thus, we do not
utilize the client authentication feature provided by CCF. However to
satisfy the CCF's requirement that only authorized CCF users can submit
transactions to CCF, share `user0_cert.pem` and `user0_privk.pem` with
all the PDO clients. These two keys and the network certificate
`networkcert.pem` must be stored under $PDO_LEDGER_KEY_ROOT (as part of
PDO deployment). The user keys must be renamed as `userccf_cert.pem` and
`userccf_privk.pem` respectively.

## Test the Deployment with Ping Test

PDO TP contains a simple `ping` rpc that returns success every time it
is queried. Test the PDO-TP deployment using this rpc. Invoke the
following commands to issue 100 ping rpcs. The net througput is reported
at the end of the test.

```bash
${PDO_SOURCE_ROOT}/ccf_transaction_processor/scripts/ping_test.py
```

## Generate Ledger Authority Key

Responses to read-transactions include a payload signature, where the
signature is generated within PDO-TP.  The required signing keys must be
generated before PDO-TP can be opened up for business from PDO
clients. This will be done automatically if you start the CCF network
with the script `${PDO_HOME}/ccf/bin/start_ccf_network.sh`.

Otherwise, you may invoke the following commands to generate and save
the ledger authority key.

```bash
${PDO_HOME}/ccf/bin/generate_ledger_authority.py
${PDO_HOME}/ccf/bin/fetch_ledger_authority.py
```

If successful, the rpc returns after 1) creating one set of signing keys
locally within the CCF enclave, and 2) scheduling them for global
commit. The ledger authority verifying key can be obtained using the
`get_ledger_verifying_key` rpc. The verifying key is returned only after
global commit is successful.

The read-payload-signature feature may be used by PDO clients to
establish offline verifiable proof of transaction commits as desired by
the PDO smart contract application. Note that for trust purposes, it is
recommended that any entity that uses the verifying_key gets it directly
from the CCF service using the `get_ledger_verifying_key` rpc.

## Using CCF ledger using PDO

We highlight some quick details about how PDO clients can use a CCF
based PDO-TP deployment. The information below can be found at
[PDO docs](../docs) as well.

1. Set the following environment variables:

```bash
export PDO_LEDGER_TYPE=ccf
export PDO_LEDGER_URL=http://ip-address:6006
```

Here, ip-address is the address of the node which hosts the CCF instance.

2. Set env PDO_LEDGER_KEY_ROOT and save CCF's network certificate
   `networkcert.pem` and user keys @ PDO_LEDGER_KEY_ROOT. Note that the
   user cert and private keys must be named as `userccf_cert.pem` and
   `userccf_privk.pem` respectively.

3. Do a clean build of PDO

```bash
cd $PDO_SOURCE_ROOT/build/
make clean
make
```

A clean build is an easy way to ensure updated creation of config files
and PDO keys that are compatible with CCF.

4. Run unit tests
```bash
cd $PDO_SOURCE_ROOT/build/__tools__
./run-tests.sh
```
