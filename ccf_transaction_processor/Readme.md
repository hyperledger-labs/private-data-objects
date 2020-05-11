<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

## Microsoft CCF based PDO Transaction Processor

This folder contains software for PDO transaction processor (TP) based on Microsoft's CCF blockchain.
The software is located under $PDO_SRC/transaction_processor/. The TP software is written and tested for CCF tag 0.9.2. Compatability with other CCF versions is not guaranteed. 

The instructions below may be followed to build and deploy CCF based PDO TP.

# Get CCF Source Code

CCF tag 0.9.2 is included as a submodule within PDO. Download the submodule using the following commands:

cd $PDO_SRC
git submodule init
git submodule update


# Install CCF Dependencies

CCF/PDO combo has been tested under a scenario where CCF is deployed in a standalone VM. Further, the CCF/PDO combo
has been tested only for the CCF virtual enclave mode. The dependencies needed to deploy CCF in an Ubuntu 18.04  VM
with  virtual enclave mode can be installed by running the following command:

$PDO_SRC/ccf_transaction_processor/CCF/getting_started/setup_vm/setup_nosgx.sh.

The above script works only when the VM is not behind any proxies. If there are proxies, make the following changes
before executing the above comamnd:

        A. In the setup_nosgx.sh file, modify the command `sudo add-apt-repository ppa:ansible/ansible -y` by adding the `-E` option.
           The modified command looks like `sudo -E add-apt-repository ppa:ansible/ansible -y`. It may also be necesssary to add a `sudo`
           prefix to the `ansible-playbook ccf-dependencies-no-driver.yml` command appearing in the same file.

        B. In ccf-dependencies-no-driver.yml and ccf-dependencies.yml files (present under the same folder), add the environment option for proxies
           (see https://docs.ansible.com/ansible/latest/user_guide/playbooks_environment.html for reference)

                environment:
                    http_proxy: <specify-http-proxy-here>
                    https_proxy: <specify-https-proxy-here>

#Build CCF & PDO-TP 

Copy the transaction processor source files to the CCF src/apps/ folder

mkdir $PDO_SRC/ccf_transaction_processor/CCF/src/apps/pdo_tp
cp $PDO_SRC/ccf_transaction_processor/transaction_processor/*.* $PDO_SRC/ccf_transaction_processor/CCF/src/apps/pdo_tp/

CCF uses a combination of cmake& ninja to build the applcaition. Execute the following steps to complete the build process:

        A. Add the following lines to the CMakelists.txt found at $PDO_SRC/ccf_transaction_processor/CCF.
           (look for other add_ccf_app in this file, add just above or below this)

                add_ccf_app(
                  pdoenc SRCS src/apps/pdo_tp/pdo_tp.cpp
                  src/apps/pdo_tp/verify_signatures.cpp
                )

        B. Create the build folder

                mkdir $PDO_SRC/ccf_transaction_processor/CCF/build

        C. Set the build flags

                $PDO_SRC/ccf_transaction_processor/CCF/build
                cmake -GNinja -DCOMPILE_TARGETS=virtual -DBUILD_END_TO_END_TESTS=OFF -DBUILD_SMALLBANK=OFF      
                              -DBUILD_TESTS=OFF-DBUILD_UNIT_TESTS=OFF ..   


        D. Build using ninja

                ninja

           If the VM has a small memory (< 4GB), it might be required to reduce the parallelism in the build process using the `-j` flag for
           the `ninja` command, say ninja -j2 or even ninja -j1 (the default seems to be ninja -j4).


If build is successful, the libpdoenc.virtual.so library is created inside the build folder (ignore any other targets that get created)


# Deploy CCF with PDO-TP as the application

The following commands starts a single node CCF under the virtual enclave mode.  PDO-TP is the hosted application.

cd $PDO_SRC/ccf_transaction_processor/CCF/build
python3.7 -m venv env
source env/bin/activate
pip install -q -U -r ../tests/requirements.txt
python ../tests/start_network.py --gov-script ../src/runtime_config/gov.lua  --label pdo_tp -e virtual --package libpdoenc.virtual.so --node <ip-address:6006>

A single node CCF instance hosting the PDO TP will be available for business use @ ip-address:6006. Here `ip-address` is the address of this VM that can be used to ping this machine from other VMs (this is our use case). Set ip-address to 127.0.0.1 for local testing. If you are behind a proxy, add ip-address to the list of no_proxy bash env variable.

# Share CCF Keys

CCF uses mutually authenticated TLS channels for transactions. Keys are located at
$PDO_SRC/ccf_transaction_processor/CCF/build/workspace/pdo_tp_common. The network certificate is `networkcert.pem`.
User public certificate is `user0_cert.pem` and private key is `user0_privk.pem`. 

In our usage, CCF users are PDO clients, and PDO client authentication is implemented within the transaction processor itself. Thus, we do not utilize the client authentication feature provided by CCF. However to satisfy the CCF's requirement that only authorized CCF users can submit transactions to CCF, share `user0_cert.pem` and `user0_privk.pem` with all the PDO clients. These two keys must be stored under $PDO_LEDGER_KEY_ROOT (as part of PDO deployment) under the names `userccf_cert.pem` and `userccf_privk.pem` respectively.

# Test the Deployment with Ping Test

PDO TP contains a simple `ping` rpc that returns success everytime it is queried. Test the PDO-TP deployment using this rpc. Invoke the following commands to issue 100 ping rpcs. The net througput is reported at the end of the test.

cd $PDO_SRC/ccf_transaction_processor/test
./test.sh <ip-address>

The CCF port is assumed to be 6006.

# Generate Signing Keys used to sign Payloads of Read Transactions

Responses to read-transactions include a payload signature, where the signature is generated within PDO-TP. 
The required signing keys must be generated before PDO-TP can be opened up for business from PDO clients.
Invoke the following commands to generate the signing keys.

cd $PDO_SRC/ccf_transaction_processor/generate_signing_keys
./gen_keys.sh <ip-address>

If successful, the rpc returns after 1) creating one set of signing keys locally within the CCF enclave, and 2) scheduling
them for global commit. The corresponding verifying key can be obtained using the `get_ledger_verifying_key`
rpc. Verifying key is returned only after global commmit is successful. Invoke the following commands to 
check that signing keys have been globally committed before opening up CCF for business from PDO clients.

./get_verifying_keys.sh <ip-address>

The read-paylaod-signature feature may be used by PDO clients to establish offline verifiable proof of transaction commits as desired by the PDO smart contract application. Note that for trust purposes, it is recommended that any entity that uses the verifying_key gets it directly from the CCF service using the `get_ledger_verifying_key` rpc.

