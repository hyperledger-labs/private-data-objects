<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Microsoft CCF based PDO Transaction Processor

This folder contains software for PDO transaction processor (TP) based
on Microsoft's CCF blockchain.  The software is located under
`${PDO_SOURCE_ROOT}/ccf_transaction_processor/`. The TP software is
written and tested for CCF tag 1.0.19. Compatibility with other CCF
versions is not guaranteed. Currently PDO/CCF combo is supported
only for virtual enclaves.

The instructions below can be used to build and deploy the CCF-based PDO
TP. The PDO TP uses many of environment variables defined in the PDO
configuration script `common-config.sh`. We recommend that you read the
[PDO environment variables documentation](../docs/environment.md) first.

In some circumstances you may wish to override the default values of the
variables for the PDO TP.

* `PDO_HOSTNAME` : the name of host interface used to access the TP;
typically this would be set to `localhost` for local testing or the
external name of the host to provide network access.

* `PDO_LEDGER_KEY_ROOT` : the directory where PDO TP keys will be
created; if you are only running the PDO TP on a server you may find it
easier to point this to a directory in the CCF tree such as
`${PDO_HOME}/ccf/keys`.

In addition, the PDO TP assumes that the environment variable `CCF_BASE`
points to the directory where CCF is installed.

IMPORTANT: When installing CCF and PDO on the same VM for local testing,
please install PDO first and then CCF. See [PDO docs](../docs) for
detailed instructions on installing PDO.

## Install CCF

Please follow instructions at https://microsoft.github.io/CCF/release/1.x/build_apps/install_bin.html to install CCF version 1.0.19. Below, we provide a quick summary of the steps  to install CCF version 1.0.19 on bare metal with SGX simuation mode.

Please set `CCF_BASE` to `/opt/ccf. For installing dependencies, download the CCF repo, change branch to ccf-1.0.19 and execute the following commands:

```bash
cd getting_started/setup_vm/
./run.sh app-dev.yml
```

The above command may throw an error message suggesting that CCF installation failed; if so, please ignore this error message. 

Install CCF 1.0.19 via debian package
```bash
export CCF_VERSION=1.0.19
wget https://github.com/microsoft/CCF/releases/download/ccf-${CCF_VERSION}/ccf_${CCF_VERSION}_amd64.deb
$ sudo apt install ./ccf_${CCF_VERSION}_amd64.deb
```

Note that CCF needs to be installed only on the machine where PDO TP
is being installed. CCF is not required by PDO clients to use a CCF based PDO TP.

## Build and Install PDO TP

To build the PDO TP the [PDO environment variables](../docs/environment.md)
must be set. See the PDO configuration script `common-config.sh` for
more information.

To build and install the PDO TP,
```bash
source ${PDO_SOURCE_ROOT}/build/common-config.sh
cd ${PDO_SOURCE_ROOT}/ccf_transaction_processor
make clean
make
```

## Configure

See the CCF documentation for information about configuring CCF. The
`cchost` configuration file used by the PDO control scripts can be found
at `${PDO_HOME}/ccf/etc/cchost.toml`. The CCF governance script can be
found at `${PDO_HOME}/ccf/etc/constitution.js`. We note that this governance script is
the based on default governance scripts found as part of the CCF repo.

## Start/Stop CCF Network

You can start a new CCF network with the PDO transaction processor using
the following commands:

```bash
source ${PDO_HOME}/ccf/bin/activate
${PDO_HOME}/ccf/bin/start_ccf_network.sh
```

The above script will start the first node in the CCF network, open the network,
add the user account that will be used for other PDO transactions, and generate
the ledger authority key. The ledger authority key will be stored in the
file `${PDO_LEDGER_KEY_ROOT}/ledger_authority_pub.pem`. This key can be
used to verify claims about the state of the ledger.

Note that a CCF network must run continuously; it cannot be fully
stopped and restarted. Directions for adding additional nodes will be
forthcoming.

The script `${PDO_HOME}/ccf/bin/stop_cchost.sh` can be used to stop the
instance of `cchost` running on the local server. When the final instance
of `cchost` terminates, the ledger will be irretrievably terminated.

## Share CCF (TLS) Authentication Keys

CCF uses mutually authenticated TLS channels for member transactions. User transactions
use one-way TLS (pdo clients remain anonymous while submitting transactions to CCF). CCF
member keys and network certificate are located at `${PDO_HOME}/ccf/keys`. The network certificate ('networkcert.pem`) is created as part of CCF deployment and is unique to the specific instance of CCF.

## Test the Deployment with Ping Test

PDO TP contains a simple `ping` rpc that returns success every time it
is queried. Test the PDO TP deployment using this rpc. Invoke the
following commands to issue 100 ping rpcs. The net througput is reported
at the end of the test.

```bash
source $PDO_HOME/ccf/bin/activate
${PDO_SOURCE_ROOT}/ccf_transaction_processor/scripts/ping_test.py
```

While invoking the test from a remote machine, be sure to 1) copy the
CCF keys from the directory pointed to by the environment variable
`PDO_LEDGER_KEY_ROOT` on the server where the transaction processor is
running to the directory pointed to by `PDO_LEDGER_KEY_ROOT` on the
client host, and 2) set `PDO_LEDGER_URL` to http://ccf-ip-address:6600,
where `ccf-ip-address` is the IP address associated with the host name
where CCF listens (see `PDO_HOSTNAME` above).

## Generate Ledger Authority Key

Responses to read-transactions include a payload signature, where the
signature is generated within PDO TP.  The required signing keys must be
generated before PDO TP can be opened up for business from PDO
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

The `read-payload-signature` feature may be used by PDO clients to
establish offline verifiable proof of transaction commits as desired by
the PDO smart contract application. Note that for trust purposes, it is
recommended that any entity that uses the verifying_key gets it directly
from the CCF service using the `get_ledger_verifying_key` rpc.

## Using CCF ledger using PDO

We highlight some quick details about how PDO clients can use a CCF
based PDO TP deployment. The information below can be found at
[PDO docs](../docs) as well.

1. Set the following environment variables:

```bash
export PDO_LEDGER_TYPE=ccf
export PDO_LEDGER_URL=http://ccf-ip-address:6600
```

As noted above `ccf-ip-address` is the IP address associated with the
host named in the variable `PDO_HOSTNAME` (see above) during CCF
deployment.

2. Ensure that the PDO TP netwrok certificate `networkcert.pem` is stored in the directory
`${PDO_LEDGER_KEY_ROOT}`.

3. Do a clean build of PDO (if installing on the same VM CCF is
installed, this will wipe out CCF, so as noted above install PDO first
and then CCF)

```bash
cd ${PDO_SOURCE_ROOT}/build
make clean
make
```

A clean build is an easy way to ensure updated creation of config files
and PDO keys that are compatible with CCF. Alternatively, the overhead of a clean build
can be avoided by executing the following two commands (in place of `make clean`) if
the intention is to switch between PDO ledgers.

```bash
source ${PDO_SOURCE_ROOT}/build/common-config.sh
make -C ${PDO_SOURCE_ROOT}/build force-conf keys
```

4. Run unit tests
```bash
cd ${PDO_SOURCE_ROOT}/build
make test
```
