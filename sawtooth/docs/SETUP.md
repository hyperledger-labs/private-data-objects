<!--- -*- mode: markdown; fill-column: 80 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Introduction #

This document describes how to setup Sawtooth Registry Transaction Processor for PDO - Private Data Objects.
For additional information on how to use the Transaction Processor and PDO-CLI command line utility for development
refer to the [USAGE](USAGE.md) document.


There are three PDO transaction families.
* Contract enclave registry
* Contract (instance) registry
* CCL (Coordination and Commit Log) registry

All three families are executed by a single transaction processor.
This document describes how to install, launch and smoke-test this transaction processor.
Refer to their descriptions in folder sawtooth/doc for the details on their capabilities and APIs
The protocol buffer messages are located in folder python/sawtooth/pdo_protos/protobufs.
Python classes build from the protocol buffer messages above are placed in folder python/sawtooth/pdo_protos.


# I) Install Sawtooth Blockchain #

Before setting up PDO transaction families, install sawtooth blockchain according to instructions at
[Sawtooth Documentation](https://sawtooth.hyperledger.org/docs/core/releases/1.0.1/app_developers_guide/ubuntu.html)
Make sure that Sawtooth validator, HHTP REST API, and Settings Transaction Processor are up and running.


Pull PDO source code from [PDO GITHUB](https://github.com/hyperledger-labs/private-data-objects)

If you want to use Sawtooth source code from the GITHUB instead of installing Sawtooth for app development,
PDO and Sawtooth top folders should be peers, e.g.
```
~/
    PDO/
        ...
    Sawtooth/
        ...
```

If PDO and Sawtooth source code folders are not peers in the same folder, then helper scripts in pdo/sawtooth/bin must be modified accordingly.



# II) Install Python3 Cryptography Module #
Install python3-cryptography module, version 1.7.1-2 or higher if you don't have it already installed.
It is required for RSA sign and verify operations. Installing Sawtooth 1.0.1 doesn't seem to install this dependency.
To install it run following commands
```
sudo apt-get update
sudo apt-get install python3-cryptography=1.7.2-1
```


# III) Initialize Configuration Settings #
For details on how to start Sawtooth Settings Transaction Processor
refer to [Sawtooth Documentation](https://sawtooth.hyperledger.org/docs/core/releases/1.0.1/app_developers_guide/ubuntu.html)


## 1) Configure required transaction families ##
* `sawtooth_settings` must be set to not break normal sawtooth operations
* `pdo_contract_enclave_registry` is for contract enclave TF
* `pdo_contract_instance_registry` is for contract instance TF
* `ccl_contract` is for CCL

Optionally, include additional families as needed.
E.g. example below includes "intkey" family that can be helpful for basic testing
```
sawset proposal create sawtooth.validator.transaction_families='[{"family": "intkey", "version": "1.0"},\
    {"family":"sawtooth_settings", "version":"1.0"},\
    {"family": "pdo_contract_enclave_registry", "version": "1.0"},\
    {"family": "pdo_contract_instance_registry", "version": "1.0"},\
    {"family": "ccl_contract", "version": "1.0"}]'
```


## 2) Set parameters needed for the proof data validation. ##
In the examples below measurements and basenames values provided inline and report public key is read from the PEM file.

The last of these three commands requires a key file distributed with
Hyperledger Private Data Objects (https://raw.githubusercontent.com/hyperledger/sawtooth-poet/master/sgx/packaging/ias_rk_pub.pem) these
commands should be run from the top-level directory of the PDO repository.

```
sawset proposal create pdo.test.registry.measurements='c99f21955e38dbb03d2ca838d3af6e43ef438926ed02db4cc729380c8c7a174e'
sawset proposal create pdo.test.registry.basenames='b785c58b77152cbe7fd55ee3851c499000000000000000000000000000000000'
sawset proposal create pdo.test.registry.public_key="$(wget -q -O - https://raw.githubusercontent.com/hyperledger/sawtooth-poet/master/sgx/packaging/ias_rk_pub.pem)"
```



# V) Build Protocol Buffers #

Before launching Transaction Processors first time or when PDO protocol buffer
definitions are changed, build python protocol buffers files using following
command. Notice that this command must be executed from the top PDO source
code folder.

Note that some distributions do not have a new enough version of
the protobuf compiler; if you get an error message about proto 3 not being
supported, refer to the following section.
```
sawtooth/bin/build_sawtooth_proto
```

If you get an error about proto 3 not being supported (`Unrecognized syntax
identifier "proto3" This parser only recognizes "proto2"`), you will need to
manually compile and install a recent version of the protobuf compiler. If the
previous command succeeded you do **not** need to do this. Follow these steps
and then re-run the above command to build the sawtooth protobufs.
```
wget https://github.com/google/protobuf/releases/download/v3.5.1/protobuf-python-3.5.1.tar.gz
tar xzf protobuf-python-3.5.1.tar.gz
cd protobuf-3.5.1
./configure
make -j16
make check -j16
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib
```

Verify that three `*.pb2.py` files were built (or rebuilt) in folder `python/sawtooth/pdo_protos`.

# V) Launch PDO Transaction Processors #

An example below starts the Transaction Processor with default parameters
assuming that the command is ran from the PDO top folder
```
sawtooth/bin/pdo-tp
```
Notice that Transaction Processor running in default mode disables any debug support meaning
that created PDO registry entries cannot be deleted and enclaves running in the SGX simulation mode are not supported.


Example below show how to start the Transaction Processor with
- verbose logging output (-v -v)
- explicitly specified connect endpoint for the validator connection (in this case the same as default)
- debug mode on (`--debug-on`) that allows to delete Sawtooth state entries and register enclaves
  without proof data (a.k.a. running in the SGX simulation mode)

```
sawtooth/bin/pdo-tp -v -v --connect tcp://localhost:4004 --debug-on
```

To stop the transaction processor type CTRL-C.
There are could be a delay 1-2 seconds before it stops.



# VI) Testing PDO Transaction Processors

First, make sure that protobuf dependent python files are generated as defined
in section "Launch PDO Transaction Processors"


```
sawtooth/bin/pdo-cli ping
```

As a part of "ping", pdo-cli utility will create a dummy contract registry entry and then will try to delete it.
You should see output like below if the transaction processor is running in the debug mode (with --debug-on option).

```
Executing a contract register transaction... it may take up to 2 minutes
OK
Retrieving a contract registry entry...

Ping successful

Removing the added contract registry entry...
Removal of the contract succeeded

```


You should see output like below if the transaction processor is not running in the debug mode (no --debug-on option).
In this case attempt to delete just created contract registry entry fails. This is an expected if the debug mode is OFF.

```
Executing a contract register transaction... it may take up to 2 minutes
OK
Retrieving a contract registry entry...

Ping successful

Removing the added contract registry entry...
Removal of the contract failed, likely, because transaction processor is running in debug OFF mode

```

For additional information on pdo-cli command line utility refer to section
"PDO Sawtooth CLI Utility" in the [USAGE](USAGE.md) document.
