<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# NOTE
The contents of the `ethereum_preview` directory are not supported and are intended only to provide a preview of what Private Data Objects might look like using the Ethereum block chain.

# Introduction

This document provides information on how to use a demo for smart contracts on Ethereum using PDO. These smart contracts resemble the functionality of the Sawtooth Transaction Processor.

There are three PDO smart contracts:

* Contract enclave registry
* Contract (instance) registry
* CCL (Coordination and Commit Log) registry

All three registries are a separate contract, but are found in the same file, transaction_processor_contract.sol. At this time, only the enclave registry and contract registry are implemented. This document describes how to set up and run a python script that demos the functionality of these contracts, such as registering an enclave in the enclave registry and registering a contract in the contract registry.

# Setup

Follow the steps below to successfully run the demo transaction_processor_client.py file from the command line.
##Install Dependencies
### Web3.py
The transaction_processor_client.py file uses the web3.py library to interact with Ethereum. To install web3, follow the insructions in the web3 repository:
* https://github.com/ethereum/web3.py

To ensure alignment with the rest of PDO, delete the python virtual environment from the web3 directory and make a new one with the following command

```python
>> python3 -m venv venv
```

### Solidity Compiler
You will also need to install a solidity compiler in order to compile the enclave registry and contract registry contracts which are written in solidity. This compiler is called solc. Install it as follows:

```python
>> npm install -g solc
```
## Connect to a Testnet
Rather than use the main Ethereum network, connect to a testnet to use fake ether during development. There are three public testnets:
* Ropsten, the public cross-client Ethereum testnet
* Rinkeby,  the public Geth proof of authority testnet
* Kovan, the public Parity proof of authority testnet

Ropsten is the most popular testnet option and most closely resembles the Ethereum mainnet. This script was written for use on Ropsten, but modifications could be made to use it on other testnets.

The quickest way to connect to a testnet is through a hosted node rather than through your own local node which would require downloading the testnet blocks. Infura is a simple hosted node that supports all three public testnets.

Create an account on Infura:
* https://infura.io/

Once you have created an account, create a new project. Name it as you'd like and set the endpoint to be your preferred testnet. Copy the URL that appears below the selected endpoint and replace the following commented code in the transaction_processor_client.py file with that URL.

```python
w3 = Web3(HTTPProvider('[HTTP PROVIDER]'))
```

Note that if you use a testnet other than Ropsten, you will have to change the chain ID used in the script. Other modifications may also be needed.


## Set Up a Wallet
To pay for transactions in ether, you will need a wallet. One wallet option is Metamask, which easily manages ether on Chrome, Firefox, Opera, and Brave browsers. To use MetaMask, simply download the extension and create an account.

Once you have created an account, make sure to set the desired network to your selected testnet for development. This will ensure the ether used is fake. If you need fake ether, you can find some here
* https://faucet.metamask.io/

Next, copy your wallet address and private key and replace the following comented code in transaction_processor_client.py with each respective value. Remember to place them in single quotes.

```python
wallet_privateKey = '[WALLET PRIVATE KEY]'
wallet_address = w3.toChecksumAddress('[WALLET ADDRESS]')
```




## Deploy Contracts

### Automated Deployment
Contract deployment is handled in the python file using the solc solidity compiler, which also provides the bytecode (for EVM execution) and the contract ABI needed for calling the contract function. The contract is deployed through the web3.eth.contract object which then provides the deployed contract address and an instance of the contract for interaction in the demo.

To use the automated deployment, the contracts' code will need to be saved in the same directory as the transaction_processor_contract.sol file. Please make two new files in that directory and name them:
* enclave_registry_source_code.py
* contract_registry_source_code.py

The former should contain the enclave registry contract and the latter should contain BOTH the enclave registry and the contract registry contracts.


The files should be in the following format, note that the pair of triple quotation marks are part of the syntax.
```python
code = '''[CONTRACT SOLIDITY CODE]'''
```


Please see appendices A and B for an example.

### Deployment from Remix
An alternate way to deploy the contracts for testing purposes is from Remix, a Solidity IDE. Follow the link below to reach Remix and copy the contents of transaction_processor_contract.sol into a new project there.

* https://remix.ethereum.org

Next, make sure the environment is set to Injected Web3 and compile the solidity file.

To instantiate a deployed contract in python, Web3 provides the following function:

```python
w3.eth.contract(address, abi)
```

Using this contract instance, we can make calls to a deployed contract's functions. Notice that one of the arguments is the contract ABI. Thus, you will need to copy each contract's ABI, which can be found in Remix under contract details. Create two new local files in the same directory as the transaction_processor_client.py file. Name the files as follows:

* enclave_abi.py
* contract_registry_abi.py


The files should be in the following format, note that the pair of triple quotation marks are part of the syntax.
```python
abi = """[COPIED ABI]"""
```

Replace [COPIED ABI] with each contract's ABI copied from Remix. The python script will appropriately import this file and pass the value of 'abi' into the Web3 contract contsructor function. For more details, see Appendices C and D.

Replace the following commented code in transaction_processor_client.py with the address of the deployed enclave registry contract and the address of the deployed contract registry contract in single quotes.

```python
enclave_registry_contract_address = w3.toChecksumAddress('''DEPLOYED CONTRACT ADDRESS''')
contract_registry_contract_address = w3.toChecksumAddress('''DEPLOYED CONTRACT ADDRESS''')
```

Note that this method requires removing the code for automated deployment.

# Run script

Start a python virtual environment in the same directory as the transaction_processor_client.py file with the following command

```python
>> . venv/bin/activate

```

Finally, simply run the file
```python
>>(venv) python transaction_processor_client.py
```

# Appendix
## Appendix A
The following is sample content for the file enclave_registry_source_code.py, which should be created in the same directory as transaction_processor_client.py. Please note that the actual source code for the enclave registry contract may not be up to date with this version. Refer to the most current contract version in the transaction_processor_contract.sol file.

```python
code = '''pragma solidity ^0.4.0;

contract EnclaveRegistry {
    // Define info to be stored for each enclave
    struct EnclaveInfo {
         bytes32 verifying_key;
         string encryption_key;
         string owner_id;
         string last_registration_block_context;
    }
    address public msgSender;
    address public ecrecoverReturnVal;


    // This declares a state variable that
    // stores an `EnclaveInfo` struct for each enclave verifying key.
    mapping(bytes32 => EnclaveInfo) public enclaves;

    // Stores the ID's (veriyfing_key) of all registered enclaves
    bytes32[] public keySet;

    // Registers a new enclave
    function register(bytes32 verifying_key, string encryption_key,
      string owner_id, string last_registration_block_context) public
    {

        // assigns reference
        EnclaveInfo storage info = enclaves[verifying_key];

        //check if enclave is already registered
        require (info.verifying_key == 0, "Enclave is already registered.");


        //set values of EnclaveInfo object
        info.verifying_key = verifying_key;
        info.encryption_key = encryption_key;
        info.owner_id = owner_id;
        info.last_registration_block_context = last_registration_block_context;


        //update enclave registry
        enclaves[verifying_key] = info;

        //updates keySet
        keySet.push(verifying_key);
    }

    // Returns enclave info by its ID (verifying_key)
    function getEnclave(bytes32 enclave_id)
      view public returns (bytes32 verifying_key, string encryption_key,
      string owner_id, string last_registration_block_context)
    {
        EnclaveInfo storage info = enclaves[enclave_id];
        verifying_key = info.verifying_key;
        //ensure enclave corresponding to id has been initialized
        require (verifying_key != 0, "Enclave not found");
        encryption_key = info.encryption_key;
        owner_id = info.owner_id;
        last_registration_block_context = info.last_registration_block_context;
    }

    // Returns ID's of all registered enclaves
    function getEnclaveIDs()
        view public returns (bytes32[])
    {
        return keySet;
    }

    // Deletes specified enclave
    function deleteEnclaveByID(bytes32 enclave_id) public {
        EnclaveInfo storage info = enclaves[enclave_id];
        //ensure enclave corresponding to id exists
        require (info.verifying_key.length != 0, "No enclave with ID");
        delete enclaves[enclave_id];
        removeFromArray(keySet, enclave_id);

    }

    // Private helper function to keep arrays updated when values are deleted
    function removeFromArray(bytes32[] storage array, bytes32 key)
        private returns(bytes32[]) {

        bool found = false;
        for (uint i  = 0; i < array.length; i++)
        {
            if (array[i] == key)
            {
                found = true;
                break;
            }
        }
        if (found == false) return;

        for (i; i < array.length - 1; i++)
        {
            array[i] = array[i+1];
        }
        array.length--;
        return array;
    }

    function enclaveRegistered(bytes32 verifying_key)
        public view returns(bool) {
        // assigns reference
        EnclaveInfo storage info = enclaves[verifying_key];

        //check if enclave is already registered
        return (info.verifying_key != 0);
    }

    // Verify a signature -- still under development (not working)
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        public returns(bool) {
        ecrecoverReturnVal = ecrecover(hash, v, r, s);
        msgSender = msg.sender;
        return ecrecover(hash, v, r, s) == msg.sender;
    }

    function getSender()
        public view returns(address) {
        return msgSender;
    }

    function getResult()
        public view returns(address) {
        return ecrecoverReturnVal;
    }
}'''

```
## Appendix B
The following is sample content for the file contract_registry_source_code.py, which should be created in the same directory as transaction_processor_client.py. Please note that the actual source code for the enclave registry contract may not be up to date with this version. Refer to the most current contract version in the transaction_processor_contract.sol file.

```python
code = '''pragma solidity ^0.4.0;
/*
 * Implements the transaction processor for Ethereum.
 * Contains a contract for contract registry and a
 * contract for enclave registry.
 */


contract ContractRegistry {

    //Defines info for each provisioning service stored in a contract's enclave
    struct PSInfo {
        bytes32 ps_public_key;
        string encrypted_contract_state;
        int index;
    }

    //Defines info for each enclave stored in a contract's enclave list
    struct ContractEnclaveInfo {
        bytes32 verifying_key; //sometimes refered to as enclave_id
        string contract_state_encryption_key;
        string enclave_signature;
        bytes32[] ps_list_keys;
        mapping(bytes32 => PSInfo) ps_list;
        bool initialized; // once true, enclave info is immutable
    }

    //Define info to be stored for each contract
    struct ContractInfo {
        bytes32 contract_id;
        string code_hash;
        bytes32[] ps_public_keys_list;
        bytes32[] enclave_list_keys;
        mapping(bytes32 => ContractEnclaveInfo) enclave_list;
        address creator;
    }

    // contracts contains all registered contracts
    mapping(bytes32 => ContractInfo) public contracts;

    //keySet stores all registered contracts' ID's
    bytes32[] public contract_ids;

    event contractRegistered(bytes32 contract_id);

    // Registers a new contract
    function register(bytes32 contract_id, string code_hash,
        bytes32[] ps_public_keys_list) public {
        ContractInfo storage contract_info =  contracts[contract_id];

        //check if contract_id already exists
        require(contract_info.contract_id == 0, 'Contract already exists');
        require(contract_id != 0, 'Invalid contract ID argument');
        require(bytes(code_hash).length != 0, 'Invalid code hash argument');
        require(ps_public_keys_list.length > 0, 'Provisioning service keys must be nonempty');

        //set values of ContractInfo
        contract_info.contract_id = contract_id;
        contract_info.code_hash = code_hash;
        contract_info.ps_public_keys_list = ps_public_keys_list;
        contract_info.creator = msg.sender;

        //update contract registry
        contracts[contract_id] = contract_info;

        //add contract_id to contract_ids
        contract_ids.push(contract_id);

        emit contractRegistered(contract_id);
    }


    // Initiates addition of an enclave to a contract's enclave list
    function addEnclaveInit(bytes32 contract_id, bytes32 verifying_key,
        string contract_state_encryption_key, string enclave_signature,
        address enclave_contract_addr)
        public {

        ContractInfo storage contract_info = contracts[contract_id];
        //make sure contract is registered
        require(contract_info.contract_id != 0, 'Contract not found');

        //make sure enclave is being added by the contract creator
        if(msg.sender != contract_info.creator) { revert(); }

        mapping(bytes32 => ContractEnclaveInfo) enclave_list = contract_info.enclave_list;
        ContractEnclaveInfo storage contract_enclave_info = enclave_list[verifying_key];


        EnclaveRegistry enclave_registry = EnclaveRegistry(enclave_contract_addr);
        bool registered = enclave_registry.enclaveRegistered(verifying_key);
        require(registered, 'Enclave not registered');


        //check if enclave is already in enclave_list
        require(contract_enclave_info.verifying_key == 0, 'Enclave already in list');

        //set values of EnclaveInfo
        contract_enclave_info.verifying_key = verifying_key;
        contract_enclave_info.contract_state_encryption_key = contract_state_encryption_key;
        contract_enclave_info.enclave_signature = enclave_signature;
        contract_enclave_info.initialized = false;

        //update enclave_list
        contract_info.enclave_list[verifying_key] = contract_enclave_info;
    }

    // Returns contract associated with given ID
    function getContract(bytes32 id)
        public view returns(bytes32 contract_id, string code_hash,
        bytes32[] ps_public_keys_list, bytes32[] enclave_list_keys) {

        ContractInfo storage contract_info = contracts[id];

        //make sure contract is registered
        require(contract_info.contract_id != 0, 'Contract not found');

        contract_id = contract_info.contract_id;
        code_hash = contract_info.code_hash;
        ps_public_keys_list = contract_info.ps_public_keys_list;
        enclave_list_keys = contract_info.enclave_list_keys;
    }

    // Returns ID's of all enclaves in a contract's enclave list
    function getEnclaveIDs(bytes32 id)
        public view returns(bytes32[] enclaves) {

        ContractInfo storage contract_info = contracts[id];

        //make sure contract is registered
        require(contract_info.contract_id != 0, 'Contract not found');

        enclaves = contract_info.enclave_list_keys;
    }

    // Returns enclave info of a specified enclave in a specified contract's
    // enclave list. Note that enclave_id is the enclave's verifying_key.
    // Enclave must be registered in the enclave registry.
    function getEnclave(bytes32 contract_id, bytes32 enclave_id)
        public view returns(bytes32 verifying_key, string contract_state_encryption_key,
        bytes32[] ps_list_keys) {

        ContractInfo storage contract_info = contracts[contract_id];
        //make sure contract is registered
        require(contract_info.contract_id != 0, 'Contract not found');

        ContractEnclaveInfo storage enclave_info = contract_info.enclave_list[enclave_id];
        require(enclave_info.verifying_key != 0, 'Enclave not found');

        verifying_key = enclave_info.verifying_key;
        contract_state_encryption_key = enclave_info.contract_state_encryption_key;
        ps_list_keys = enclave_info.ps_list_keys;
    }

    // Adds a provisioning service to a specified enclave in a specified
    // contract's enclave list. Provisioning service must be in the contract's
    // list of provisioning services
    function addProvisioningServiceToEnclave(bytes32 contract_id, bytes32 enclave_id,
        bytes32 ps_public_key, string encrypted_contract_state, int index)
        public {

        ContractInfo storage contract_info = contracts[contract_id];
        require(contract_info.contract_id != 0, 'Contract not found');
        //make sure ps is being added by the contract creator
        require(msg.sender == contract_info.creator, 'Sender not authorized to add provisioning service');

        ContractEnclaveInfo storage enclave_info = contract_info.enclave_list[enclave_id];
        require(enclave_info.verifying_key != 0, 'Enclave not found');
        require(!enclave_info.initialized, 'Enclave already initialized. Cannot add provisioning services.');

        PSInfo storage ps_info = enclave_info.ps_list[ps_public_key];
        require(ps_info.ps_public_key == 0, 'Provisioning service already registered');

        //check that this provisioning service is in contract's list of pservices
        bool ps_permission = false;
        bytes32[] storage ps_list = contract_info.ps_public_keys_list;
        for (uint i = 0; i < ps_list.length; i++)
        {
            if (ps_list[i] == ps_public_key)
            {
                ps_permission = true;
                break;
            }
        }
        require(ps_permission == true, 'Provisioning service is unavailable for this contract');
        //create provisioning service info object from arguments
        ps_info.ps_public_key = ps_public_key;
        ps_info.encrypted_contract_state = encrypted_contract_state;
        ps_info.index = index;

        //update enclave info
        enclave_info.ps_list[ps_public_key] = ps_info;
        enclave_info.ps_list_keys.push(ps_public_key);

        //update contract info
        contract_info.enclave_list[enclave_id] = enclave_info;

        //update contract registry
        contracts[contract_id] = contract_info;
    }

    // Completes the addition of an enclave to a contract's enclave list.
    // Ensures no future changes to this enclave's info.
    function addEnclaveCompletion(bytes32 contract_id, bytes32 enclave_id)
        public {

        ContractInfo storage contract_info = contracts[contract_id];
        require(contract_info.contract_id != 0, 'Contract not found');
        //make sure enclave is being added by the contract creator
        require(msg.sender == contract_info.creator, 'Sender not authorized to add enclave to contract');

        ContractEnclaveInfo storage enclave_info = contract_info.enclave_list[enclave_id];
        require(enclave_info.verifying_key != 0, 'Enclave not found');
        require(!enclave_info.initialized, 'Enclave initialization already complete');

        //checks - some seem redundant, could be shortened/fine-tuned
        require(bytes(enclave_info.contract_state_encryption_key).length != 0, 'Contract state encryption key not initialized');
        require(bytes(enclave_info.enclave_signature).length != 0, 'Enclave signature not initialized');
        require(enclave_info.ps_list_keys.length > 0, 'Provisioning service list not initialized');

        //ensure all ps are initilized
        for (uint i = 0; i < enclave_info.ps_list_keys.length; i++) {
            bytes32 key = enclave_info.ps_list_keys[i];
            PSInfo storage ps_info = enclave_info.ps_list[key];
            require(ps_info.ps_public_key != 0);
            require(bytes(ps_info.encrypted_contract_state).length != 0);
        }

        //set initialized to true
        contracts[contract_id].enclave_list[enclave_id].initialized = true;

        //add enclave verifying_key to enclave_list_keys
        bytes32[] storage enclave_list_keys = contract_info.enclave_list_keys;
        enclave_list_keys.push(enclave_id);
    }

    // Returns specified provisioning service of a specified enclave of a
    // specified contract's enclave list
    function getProvisioningService(bytes32 contract_id, bytes32 enclave_id,
        bytes32 ps_id)
        public view returns (bytes32 ps_public_key, string encrypted_contract_state,
        int index) {

        ContractInfo storage contract_info = contracts[contract_id];
        require(contract_info.contract_id != 0, 'Contract not found');

        ContractEnclaveInfo storage enclave_info = contract_info.enclave_list[enclave_id];
        require(enclave_info.verifying_key != 0, 'Enclave not found');
        require(enclave_info.initialized, 'Enclave initialization incomplete');

        PSInfo storage ps_info = enclave_info.ps_list[ps_id];
        require(ps_info.ps_public_key != 0, 'Provisioning service not found');

        ps_public_key = ps_info.ps_public_key;
        encrypted_contract_state = ps_info.encrypted_contract_state;
        index = ps_info.index;
    }

    // Private helper function to keep arrays updated when values are deleted
    function removeFromArray(bytes32[] storage array, bytes32 key)
        private returns(bytes32[]) {

        bool found = false;
        for (uint i  = 0; i < array.length; i++)
        {
            if (array[i] == key)
            {
                found = true;
                break;
            }
        }
        if (found == false) return;

        for (i; i < array.length - 1; i++)
        {
            array[i] = array[i+1];
        }
        array.length--;
        return array;
    }

    // Returns ID's of all registered contracts
    function getContractIDs()
        public view returns (bytes32[])
    {
        return contract_ids;
    }

}


contract EnclaveRegistry {
    // Define info to be stored for each enclave
    struct EnclaveInfo {
         bytes32 verifying_key;
         string encryption_key;
         string owner_id;
         string last_registration_block_context;
    }
    address public msgSender;
    address public ecrecoverReturnVal;


    // This declares a state variable that
    // stores an `EnclaveInfo` struct for each enclave verifying key.
    mapping(bytes32 => EnclaveInfo) public enclaves;

    // Stores the ID's (veriyfing_key) of all registered enclaves
    bytes32[] public keySet;

    // Registers a new enclave
    function register(bytes32 verifying_key, string encryption_key,
      string owner_id, string last_registration_block_context) public
    {

        // assigns reference
        EnclaveInfo storage info = enclaves[verifying_key];

        //check if enclave is already registered
        require (info.verifying_key == 0, "Enclave is already registered.");


        //set values of EnclaveInfo object
        info.verifying_key = verifying_key;
        info.encryption_key = encryption_key;
        info.owner_id = owner_id;
        info.last_registration_block_context = last_registration_block_context;


        //update enclave registry
        enclaves[verifying_key] = info;

        //updates keySet
        keySet.push(verifying_key);
    }

    // Returns enclave info by its ID (verifying_key)
    function getEnclave(bytes32 enclave_id)
      view public returns (bytes32 verifying_key, string encryption_key,
      string owner_id, string last_registration_block_context)
    {
        EnclaveInfo storage info = enclaves[enclave_id];
        verifying_key = info.verifying_key;
        //ensure enclave corresponding to id has been initialized
        require (verifying_key != 0, "Enclave not found");
        encryption_key = info.encryption_key;
        owner_id = info.owner_id;
        last_registration_block_context = info.last_registration_block_context;
    }

    // Returns ID's of all registered enclaves
    function getEnclaveIDs()
        view public returns (bytes32[])
    {
        return keySet;
    }

    // Deletes specified enclave
    function deleteEnclaveByID(bytes32 enclave_id) public {
        EnclaveInfo storage info = enclaves[enclave_id];
        //ensure enclave corresponding to id exists
        require (info.verifying_key.length != 0, "No enclave with ID");
        delete enclaves[enclave_id];
        removeFromArray(keySet, enclave_id);

    }

    // Private helper function to keep arrays updated when values are deleted
    function removeFromArray(bytes32[] storage array, bytes32 key)
        private returns(bytes32[]) {

        bool found = false;
        for (uint i  = 0; i < array.length; i++)
        {
            if (array[i] == key)
            {
                found = true;
                break;
            }
        }
        if (found == false) return;

        for (i; i < array.length - 1; i++)
        {
            array[i] = array[i+1];
        }
        array.length--;
        return array;
    }

    function enclaveRegistered(bytes32 verifying_key)
        public view returns(bool) {
        // assigns reference
        EnclaveInfo storage info = enclaves[verifying_key];

        //check if enclave is already registered
        return (info.verifying_key != 0);
    }

    // Verify a signature -- still under development (not working)
    function verify(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        public returns(bool) {
        ecrecoverReturnVal = ecrecover(hash, v, r, s);
        msgSender = msg.sender;
        return ecrecover(hash, v, r, s) == msg.sender;
    }

    function getSender()
        public view returns(address) {
        return msgSender;
    }

    function getResult()
        public view returns(address) {
        return ecrecoverReturnVal;
    }
}
'''

```
## Apendix C
The following is sample content for the file enclave_abi.py, which should be created in the same directory as transaction_processor_client.py. Please note that the actual ABI for the enclave registry contract may not be up to date with this version. Refer to the most current contract version and obtain the ABI from Remix as expained in the "Deploy Contracts" section of this doc.
```python
abi = """[
	{
		"constant": false,
		"inputs": [
			{
				"name": "enclave_id",
				"type": "bytes32"
			}
		],
		"name": "deleteEnclaveByID",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "verifying_key",
				"type": "bytes32"
			},
			{
				"name": "encryption_key",
				"type": "string"
			},
			{
				"name": "owner_id",
				"type": "string"
			},
			{
				"name": "last_registration_block_context",
				"type": "string"
			}
		],
		"name": "register",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "hash",
				"type": "bytes32"
			},
			{
				"name": "v",
				"type": "uint8"
			},
			{
				"name": "r",
				"type": "bytes32"
			},
			{
				"name": "s",
				"type": "bytes32"
			}
		],
		"name": "verify",
		"outputs": [
			{
				"name": "",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "ecrecoverReturnVal",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"name": "enclaves",
		"outputs": [
			{
				"name": "verifying_key",
				"type": "bytes32"
			},
			{
				"name": "encryption_key",
				"type": "string"
			},
			{
				"name": "owner_id",
				"type": "string"
			},
			{
				"name": "last_registration_block_context",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "enclave_id",
				"type": "bytes32"
			}
		],
		"name": "getEnclave",
		"outputs": [
			{
				"name": "verifying_key",
				"type": "bytes32"
			},
			{
				"name": "encryption_key",
				"type": "string"
			},
			{
				"name": "owner_id",
				"type": "string"
			},
			{
				"name": "last_registration_block_context",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getEnclaveIDs",
		"outputs": [
			{
				"name": "",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getResult",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getSender",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "keySet",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "msgSender",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]"""
```
# Appendix E

The following is sample content for the file contract_registry_abi.py, which should be created in the same directory as transaction_processor_client.py. Please note that the actual ABI for the contract registry contract may not be up to date with this version. Refer to the most current contract version and obtain the ABI from Remix as expained in the "Deploy Contracts" section of this doc.
```python
abi = """[
	{
		"constant": false,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "verifying_key",
				"type": "bytes32"
			},
			{
				"name": "contract_state_encryption_key",
				"type": "string"
			},
			{
				"name": "enclave_signature",
				"type": "string"
			},
			{
				"name": "enclave_contract_addr",
				"type": "address"
			}
		],
		"name": "addEnclaveInit",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "id",
				"type": "bytes32"
			}
		],
		"name": "getEnclaveIDs",
		"outputs": [
			{
				"name": "enclaves",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "enclave_id",
				"type": "bytes32"
			},
			{
				"name": "ps_id",
				"type": "bytes32"
			}
		],
		"name": "getProvisioningService",
		"outputs": [
			{
				"name": "ps_public_key",
				"type": "bytes32"
			},
			{
				"name": "encrypted_contract_state",
				"type": "string"
			},
			{
				"name": "index",
				"type": "int256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "keySet",
		"outputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "enclave_id",
				"type": "bytes32"
			}
		],
		"name": "deleteContractEnclave",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "enclave_id",
				"type": "bytes32"
			},
			{
				"name": "ps_public_key",
				"type": "bytes32"
			},
			{
				"name": "encrypted_contract_state",
				"type": "string"
			},
			{
				"name": "index",
				"type": "int256"
			}
		],
		"name": "addProvisioningServiceToEnclave",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "enclave_id",
				"type": "bytes32"
			}
		],
		"name": "addEnclaveCompletion",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "enclave_id",
				"type": "bytes32"
			}
		],
		"name": "getEnclave",
		"outputs": [
			{
				"name": "verifying_key",
				"type": "bytes32"
			},
			{
				"name": "contract_state_encryption_key",
				"type": "string"
			},
			{
				"name": "ps_list_keys",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			}
		],
		"name": "deleteContract",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "id",
				"type": "bytes32"
			}
		],
		"name": "getContract",
		"outputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "code_hash",
				"type": "string"
			},
			{
				"name": "ps_public_keys_list",
				"type": "bytes32[]"
			},
			{
				"name": "enclave_list_keys",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "getContractIDs",
		"outputs": [
			{
				"name": "",
				"type": "bytes32[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "bytes32"
			}
		],
		"name": "contracts",
		"outputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "code_hash",
				"type": "string"
			},
			{
				"name": "creator",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "contract_id",
				"type": "bytes32"
			},
			{
				"name": "code_hash",
				"type": "string"
			},
			{
				"name": "ps_public_keys_list",
				"type": "bytes32[]"
			}
		],
		"name": "register",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "contract_id",
				"type": "bytes32"
			}
		],
		"name": "contractRegistered",
		"type": "event"
	}
]"""
```
