<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Microsoft CCF based PDO Transaction Processor

This folder contains software for PDO transaction processor (TP) based
on Microsoft's CCF blockchain.  The software is located under
`${PDO_SOURCE_ROOT}/ccf_transaction_processor/`. The TP software is
written and tested for CCF tag 0.11.7. Compatibility with other CCF
versions is not guaranteed.

The instructions below can be used to build and deploy the a single node CCF-based PDO
TP, operating under SGX virtual mode, on bare-metal. Multi-node CCF deployment as well as
deployment of CCF on SGX hardware are supported via docker containers (see below after instructions for
bare-metal installation).

The PDO TP uses many of environment variables defined in the PDO
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

## Install CCF Base

CCF Base with tag 0.11.7 is to be directly installed using the tarball
from CCF release page.  The following commands will install CCF in the
folder pointed to be the `CCF_BASE` environment variable.

```bash
wget https://github.com/microsoft/CCF/releases/download/ccf-0.11.7/ccf.tar.gz -P /tmp
tar -xvf /tmp/ccf.tar.gz -C /tmp
mv /tmp/ccf-0.11.7/ ${CCF_BASE}
```

We note that CCF Base needs to be installed in PDO clients/eservice
nodes when CCF is used as PDO ledger.  The CCF base contains CCF client
modules that will be ued by PDO clients/eservice when submitting
transactions to the CCF ledger. The rest of the steps below are only
needed on the node where CCF based pdo-tp is getting built.

## Install CCF Dependencies

CCF/PDO combo has been tested under a scenario where CCF is deployed in
a standalone VM, and where PDO cients/services are deployed either
locally or at other VMs. The dependencies needed to deploy CCF
in an Ubuntu 18.04 VM with virtual enclave mode can be installed by
running the following command:

```bash
cd $CCF_BASE/getting_started/setup_vm/
./run.sh ccf-dev.yml
```

The above script works only when the VM is not behind any proxies. If
there are proxies, make the following changes before executing the above
command:

A. In the run.sh file, modify the command
`sudo add-apt-repository ppa:ansible/ansible -y`
by adding the `-E` option. The modified command looks like
`sudo -E add-apt-repository ppa:ansible/ansible -y`.
Add a `sudo` prefix to the `ansible-playbook` command at the end of this file.

B. In ccf-dev.yml (present under the same folder),
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

## Build and Install PDO TP

To build the PDO TP the [PDO environment variables](../docs/environment.md)
must be set. See the PDO configuration script `common-config.sh` for
more information.

To build and install the PDO TP,
```bash
cd ${PDO_SOURCE_ROOT}/ccf_transaction_processor
make clean
make
```

Note that CCF uses `ninja` tool for build. If the VM has a small memory
(< 4GB), it might be required to reduce the parallelism in the build
process by setting the env `NINJA_OPTION`. For example, the following
environment restricts ninja to 2 parallel jobs.

```bash
export NINJA_OPTION=-j2
```

## Configure

See the CCF documentation for information about configuring CCF. The
`cchost` configuration file used by the PDO control scripts can be found
at `${PDO_HOME}/ccf/etc/cchost.toml`. The CCF governance script can be
found at `${PDO_HOME}/ccf/etc/gov.lua`. We note that this governance script is
the template governance script found as part of the CCF repo.

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
stopped and restarted.

The script `${PDO_HOME}/ccf/bin/stop_cchost.sh` can be used to stop the
instance of `cchost` running on the local server. When the final instance
of `cchost` terminates, the ledger will be irretrievably terminated.

## Share CCF (TLS) Authentication Keys

CCF uses mutually authenticated TLS channels for transactions. Keys are
located at `${PDO_HOME}/ccf/keys`. The network certificate is
`networkcert.pem`. User public certificate is `userccf_cert.pem` and
private key is `userccf_privk.pem`.  Note that the keys are created as
part of CCF deployment and are unique to the specific instance of CCF.

In our usage, CCF users are PDO clients, and PDO client authentication
is implemented within the transaction processor itself. Thus, we do not
utilize the client authentication feature provided by CCF. However to
satisfy the CCF's requirement that only authorized CCF users can submit
transactions to CCF, share `userccf_cert.pem` and `userccf_privk.pem` with
all the PDO clients. These two keys and the network certificate
`networkcert.pem` must be stored under the path `${PDO_LEDGER_KEY_ROOT}`
(as part of PDO deployment).

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

2. Ensure that the PDO TP keys are stored in the directory
`${PDO_LEDGER_KEY_ROOT}`. The directory should contain the CCF
network certificate, `networkcert.pem`, and the user keys
`userccf_cert.pem` and `userccf_privk.pem`.

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
## CCF based PDO TP deployment on SGX enabled HW

As per CCF documentation (https://microsoft.github.io/CCF/ccf-0.11.7/quickstart/index.html), CCF with full security guarantees requires SGX hardware with FLC. Below we provide instructions to deployment for CCF on SGX HW via docker containers running on Azure Confidential Compute (ACC) VMs. For instructions on how to deploy an ACC VM suitable for CCF installation, please see https://microsoft.github.io/CCF/ccf-0.11.7/quickstart/index.html. Essentially, the only requirement from the host platform is that the DCAP aware SGX driver (See https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver/linux) is installed and loaded. If installed, the device nodes can be found at /dev/sgx (/dev/sgx/enclave and /dev/sgx/provision). The rest of the dependencies required to deploy PDO TP will be automatically taken care of within the docker container.

Note: The instructions below have been tested only on ACC VMs and not on other SGX enabled platforms.

Set the env variable HOST_IP to the ip-address of the host machine. (The docker container will use HOST networking mode). Run the following commands to build and deploy a single node docker container running PDO TP that is available for business transactions at http://HOST_IP:6600

```bash
cd ${PDO_SOURCE_ROOT}
docker-compose -f docker/ccf-pdo.accvm.yaml build
docker-compose -f docker/ccf-pdo.accvm.yaml up
```
Once the container starts, CCF keys can be found at ${PDO_SOURCE_ROOT}/docker/ccf_keys. As noted earlier, share the user keys and network certificate with PDO clients. Usage of the PDO TP remains same as described earlier.

### Multi-Node CCF Deployment

We now provide instructions for adding an additional node to an already running CCF network. Once again, we provide deployment instructions via docker containers.

Note: Multi-node CCF deployment under SGX HW mode has been tested only on ACC VMs.

Set the env variables HOST_IP and CCF_FIRST_NODE_IP. HOST_IP refers to the ip-address of the host machine where the additional CCF node will be deployed. CCF_FIRST_NODE_IP refers to the ip-address of the remote machine where the first CCF node is already running.

Get the CCF keys, including member keys, from the first CCF node and store them under ${PDO_SOURCE_ROOT}/docker/ccf_keys in this second node. Member keys are required to add the second node as trusted node to the existing CCF network. (This way of multi-node deployment where keys of the single member are shared across nodes is suitable for scenarios where the multiple nodes are hosted in a cloud platform such as ACC, and where all nodes are managed by the same member.)

Run the following commands to build and deploy the additional CCF node.

```bash
cd ${PDO_SOURCE_ROOT}
docker-compose -f docker/ccf-pdo.accvm.yaml build
docker-compose -f docker/ccf-pdo.accvm.yaml up
```
Note these above commands are exactly the same as the ones used to deploy the first node. The presence of the env variable CCF_FIRST_NODE_IP on the second node is used to automatically decide if the new node will join an existing network or start a new CCF network.

Assuming that the deployment is successful, business transactions can be issued to either of the two nodes. If the host ips of the two nodes are HOST_IP_1 and HOST_IP_2, the CCF network is available for  business transactions at http://HOST_IP_1:6600 as well as at http://HOST_IP_2:6600.

Further nodes can be added in a similar manner as described above. CCF-based PDO-TP uses Raft as the consensus algorithm. In this case, CCF tolerates up to (N-1)/2 crashed nodes, where N is the number of nodes in the CCF network. If more than (N-1)/2 nodes fail, catastrophic recovery must be performed to bring back PDO TP. Please see https://microsoft.github.io/CCF/ccf-0.11.7/operators/recovery.html for additional details.