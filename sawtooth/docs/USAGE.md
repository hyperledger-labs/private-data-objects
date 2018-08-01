<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Introduction #

This document provides information on how to use the PDO Sawtooth Transaction Processor
and PDO-CLI command line utility for PDO (Private Data Objects) development.

It assumes familiarity with how to setup Sawtooth Registry Transaction Processor for PDO described in
the [SETUP](SETUP.md) document.


There are three PDO transaction families.
* Contract enclave registry
* Contract (instance) registry
* CCL (Coordination and Commit Log) registry

All three families are executed by a single transaction processor.
This document describes how to install, launch and smoke-test this transaction processor.
Refer to documents in folder sawtooth/docs for details on their capabilities and APIs


# I) API for Accessing Sawtooth from PDO
There are three python classes that can be used to access PDO Sawtooth registries
- PdoAddressHelper in python/sawtooth/helpers/pdo_address_helper.py. This class includes methods for
    - Retrieving PDO registry namespace prefixes
    - Retrieving PDO registry namespaces
    - Retrieving PDO family names
    - Creating Sawtooth addresses from the PDO ids
- PdoRegistryHelper in in python/sawtooth/helpers/pdo_connect.py. It inherits from the PdoAddressHelper.
  In addition, it provides "getters" for retrieving PDO registry entries. See below for the details.
- PdoClientConnectHelper in in python/sawtooth/helpers/pdo_connect.py. It inherits from the PdoRegistryHelper.
  In addition, it provides API for submitting Sawtooth transactions to the PDO transaction Processor.
  There are two APIs for submitting transactions as serialized protocol buffers and as JSON input.
  See below for the details.

**API for retrieving PDO registry entries from Sawtooth global state**

PdoRegistryHelper provides convenience wrappers for getting PDO registries items from the Sawtooth Global State.
They return a state item as a dictionary with field names matching corresponding protocol buffer definition.

```
def get_enclave_dict(self, enclave_id)
def get_contract_dict(self, contract_id)
def get_ccl_info_dict(self, contract_id)
def get_ccl_state_dict(self, contract_id, state_hash)

```


**API for submitting transaction to PDO Transaction Processor in JSON format**

PdoClientConnectHelper provides an API for submitting PDO Sawtooth transactions in the JSON format

```
def execute_json_transaction(self,
                             json_input,
                             address_family,
                             wait,
                             exception_type=None,
                             verbose=False,
                             timeout_exception_type=TimeoutError,
                             transaction_output_list=None,
                             transaction_input_list=None,
                             transaction_dependency_list=None):
```

Its parameters:
- `json-input` is a string containing JSON input. Its format define in section "PDO Sawtooth CLI Utility" below.
  - One exception: key 'af' is ignored. Instead, PDO family is defined by 'address_family' parameter
- `address_family` must match either enclave, or contract, or CCL PDO family
    - `pdo_contract_enclave_registry`: to submit PDO enclave registry transaction
    - `pdo_contract_instance_registry`: to submit PDO contract registry transaction
    - `ccl_contract`: to submit PDO CCL transaction
- `wait` defines in seconds a timeout to wait for the transaction to complete
    - It can be 0 or None if no waiting is required
- `exception_type` is a type of exception. Exception of this type will be raised if an error encountered.
  If 'exception_type' is None, no exception is raised, instead the method returns False on error and True on success.
  It should be noticed that this exception type is relevant only to errors discovered by this method itself.
  Other functions called by this method can raise different exceptions types regardless 'exception_type' value
- `verbose` defines if this method produces (debug) output. Default is None - no output
- `timeout_exception_type` defines an exception type to raise if the timeout provided by parameter "wait" expires.
- `transaction_input_list` - defines Sawtooth global state input dependency list. If it is not provided,
  the function will generate a default list. This list is broad, suatable for development, but not for production
- `transaction_output_list` - defines Sawtooth global state output dependency list. If it is not provided,
  the function will generate a default list. This list is broad, suatable for development, but not for production
- `transaction_dependency_list` - defines Sawtooth transaction dependency list to be completed before this transaction.
  If it is not provided, no default list is generated (the list is empty)


**API for submitting transaction to PDO Transaction Processor as a serialized protocol buffer**

PdoClientConnectHelper provides an API for submitting PDO Sawtooth transactions as serialized protocol buffer
```
def send_transaction(self,
                     payload,
                     family,
                     wait=None,
                     transaction_output_list=None,
                     transaction_input_list=None,
                     verbose=False,
                     exception_type=TimeoutError,
                     transaction_dependency_list=None):
```
- `payload` contains a serialized protocol buffer to be submitted to the PDO Transactions Processor
- `family` must match either enclave, or contract, or CCL PDO family
    - `pdo_contract_enclave_registry`: to submit PDO enclave registry transaction
    - `pdo_contract_instance_registry`: to submit PDO contract registry transaction
    - `ccl_contract`: to submit PDO CCL transaction
- `wait` defines in seconds a timeout to wait for the transaction to complete
    - It can be 0 or None if no waiting is required
- `transaction_input_list` - defines Sawtooth global state input dependency list. If it is not provided,
  the function will generate a default list. This list is broad, suatable for development, but not for production
- `transaction_output_list` - defines Sawtooth global state output dependency list. If it is not provided,
  the function will generate a default list. This list is broad, suatable for development, but not for production
- `verbose` defines if this method produces (debug) output. Default is None - no output
- `exception_type` defines an exception type to raise if the transaction fails
  or the timeout provided by parameter "wait" expires.
- `transaction_dependency_list` - defines Sawtooth transaction dependency list to be completed before this transaction.
  If it is not provided, no default list is generated (the list is empty)



# II) PDO Sawtooth CLI Utility

There is a command line utility that can be accessed using pdo-cli wrapper in the sawtooth/bin folder.
Its source code is in folder sawtooth/pdo-cli

**Submitting Transactions**

PDO CLI accepts transaction input in JSON format.

JSON input includes
- Required key `verb` that defines transaction type
    - For enclave registry it is one of `register` or `delete`
    - For contract registry it is one of `register`, `add-enclaves`, 'remove-enclaves', or `delete`
    - For CCL registry it is one of `initialize`, `update`, `terminate`, or `delete`
- Optional key `af` that defines address family. If this key is not present, address family must be specified as a command line option (see examples below)
- Transaction specific keys as defined below
    - Enclave register JSON input should include
        - All fields except details from PdoContractEnclaveTransaction protobuf definition
        - All fields from PdoContractEnclaveRegister protobuf definition
    - Enclave delete JSON input should include
        - All fields except details from PdoContractEnclaveTransaction protobuf definition
    - Contract register JSON input should include
        - All fields except details from PdoContractTransaction protobuf definition
        - All fields from PdoContractRegister protobuf definition
    - Contract add-enclaves JSON input should include
        - All fields except details from PdoContractTransaction protobuf definition
        - All fields from PdoContractAddEnclaves protobuf definition
    - Contract remove-enclaves JSON input should include
        - All fields except details from PdoContractTransaction protobuf definition
        - All fields from PdoContractRemoveEnclaves protobuf definition
    - Contract delete JSON input should include
        - All fields except details from PdoContractTransaction protobuf definition
    - CCL transaction JSON input should include
        - All fields from CCL_TransactionPayload protobuf definition.
            - In case of delete transaction most of fields can be empty
                - Key state\_update.contract\_id must be set to delete a corresponding CCL_Information entry
                - For each CCL_State that should be deleted a state\_update.dependency\_list object must be included in the payload


Protobuf definitions can be found in folder python/sawtooth/pdo_protos/protobufs.

CLI command format is

```
bin/pdo-cli json\
            [--keyfile <signer-private-key>]\
            [--enclave-keyfile <enclave-private-key>]\
            [--wait <seconds-to-wait>]\
            [--url <connect-url>]\
            [-e | --enclave]\
            [-c | --contract]\
            [--ccl | --CCL]\
            [-v | --verbose]\
            <json-input-file>
```

Only one of [-e | --enclave], [-c | --contract], or [--ccl | --CCL] can be defined at the same time.
This option is required only if JSON input file does not include 'af' key.

Option [-v | --verbose] works as a counter, more times it is on the command line, the more verbose output.
A shorter version example is -vvv.

Option [--keyfile] is optional; if not provided, a one-time-use key will be auto-geneated by the utility.

Option [--enclave-keyfile] is used to sign CCL transactions if the json input requires, but does not include signature.
If the JSON input contains an empty enclave signature field, this key-file is required for the utility
to auto-generate the signature. The enclave key file contains a private key that must match verifying key
in the corresponding enclave registry entry.

It should be noted that pdo-cli utility may perform some auto adjustments to the JSON input
if corresponding fields are empty to simplify BAT creation, e.g.
- as mentioned above, enclave signature auto-generation (for transactions that require it)
- PDO signature auto-generation (for transactions that require it)
- locating contract id (if it is empty for add and remove enclaves and CCL transactions).
  In this only one contract entry must be in the contract registry and its id will be used
- Performs base64 encoding for some fields, e.g. state hash if they have not been already BASE64 encoded

JSON input examples can be found in folder sawtooth/tests

This folder also includes a run-all shell script that executes number of JSON transactions.
This script must be launched from the tests folder.
Notice that they have to be executed in particular order to succeed and with a --wait delay.
Below is the order of execution.
```
../bin/pdo-cli json --keyfile key-enclave.priv --wait 10 enclave-register-with-simulated-proof-data.json
../bin/pdo-cli json --keyfile key-enclave.priv --wait 10 enclave-register-without-proof-data.json

../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 contract-register.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 contract-add-enclave-1.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key-2.priv --wait 10 contract-add-enclave-2.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key-2.priv --wait 10 contract-remove-enclave-2.json

../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 ccl-initialize.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 ccl-update-AB.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 ccl-update-BC.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 ccl-update-CD.json
../bin/pdo-cli json --keyfile key-contract.priv --enclave-keyfile enclave-signing-key.priv --wait 10 ccl-terminate.json

```
Note the first command will fail if the Transaction Processor is not running in debug mode because
it registers an enclave without proof data (a.k.a. simulation mode) that is not allowed in non debug mode.


**Displaying PDO Sawtooth Global State Entries and Related Sawtooth Settings**

To display an existing PDO registry entry from Sawtooth global state use following format
```
sawtooth/bin/pdo-cli show\
            [--wait <seconds-to-wait>]\
            [--url <connect-url>]\
            [-v | --verbose]\
            type\
            value

```
Types and values
- If type is `address`, value is a Sawtooth address
- If type is `enclave`, value is a signer public key (used as enclave id)
- If type is `contract`, value is a contract id
- If type is `ccl`, value is a contract id. In this case CCL\_Information and the latest CCL\_State are displayed
- If type is `ccl-history`, value is a contract id. In this case CCL\_Information and all CCL\_State entries are displayed for this contract
- If type is `ccl-state`, value is a <contract\_id>:<state\_hash>. In this case only a CCL\_State entry defined by the contract id and state hash is displayed
- if type is `setting`, value can be a Sawtooth configuration setting key or one of abbreviated PDO setting names - basenames, measurements, or report-public-key

Example of displaying an enclave entry
```
sawtooth/bin/pdo-cli show enclave A138A74B48A7C467161F5C37D5F69A621A02A2DA7ABFFEC0B2B10893E31E30425A49A7E5538FFB72F556C33B3D6D5FFEB023D3E505B5D0F7EB8CDBA4E4043B19
```


**Listing PDO Sawtooth Registries and Related Sawtooth Settings**

_Note: Currently, paging is not implemenrted so this option displays only the first page reported by Sawtooth REST API_

To list entries in the PDO registry from Sawtooth global state use following format
```
sawtooth/bin/pdo-cli list\
            [--wait <seconds-to-wait>]\
            [--url <connect-url>]\
            [-v | --verbose]\
            [-d | --details]
            type

```
'type' is one of enclave, contract, ccl-info, ccl-state, settings

Example of a brief list of contract registry.
```
bin/pdo-cli list contract
```

Example of listing CCL information registry entries with details.
```
bin/pdo-cli list -d ccl-info
```


**Deleting PDO Sawtooth Registries**

It should be noted that delete operations succeeds only if the Transaction Processor runs in the debug mode,
with command line option --debug-on. Otherwise, the Transaction Processor rejects delete requests.

To delete specific or all PDO registries from Sawtooth global state use following format
```
bin/pdo-cli delete\
            [--wait <seconds-to-wait>]\
            [--url <connect-url>]\
            [-v | --verbose]\
            type

```
'type' is one of enclave, contract, ccl-info, ccl-state, pdo-all

Example of deleting all PDO registries.
```
bin/pdo-cli delete pdo-all
```

**Setting and Displaying Global Sawtooth Settings**

This sections describes pdo-cli commands for interacting with Sawtooth settings transaction processor.
All examples in this section assume that they are executd from the top PDO folder.

Use set-setting to set a seeting. Use "pdo-cli set-settings --help" to display available options.
Example belows shows how set pdo.test.registry.measurements with wait delay up to 10 seconds.

```
sawtooth/bin/pdo-cli set-setting pdo.test.registry.measurements c99f21955e38dbb03d2ca838d3af6e43ef438926ed02db4cc729380c8c7a174e
```

Below is an example how to list all global Sawtooth settings. 
Use "pdo-cli list --help" to print all command line options.

```
sawtooth/bin/pdo-cli list settings

```

Below is an example how to show a specific setting pdo.test.registry.measurements
Use "pdo-cli show --help" to print all command line options.
```
sawtooth/bin/pdo-cli show setting pdo.test.registry.measurements

```
