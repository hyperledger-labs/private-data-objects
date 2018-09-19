# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import web3
#import enclave_abi
#import contract_registry_abi
import enclave_registry_source_code
import contract_registry_source_code
import time

from web3 import Web3, HTTPProvider
from solc import compile_source
from eth_account.messages import defunct_hash_message

# web3.py instance
w3 = Web3(HTTPProvider('[HTTP PROVIDER]'))

# Chain ID specific to network, use 3 for Ropsten
chain_id = 3

w3.eth.enable_unaudited_features()

# Wallet info
wallet_privateKey = '[WALLET PRIVATE KEY]'
wallet_address = w3.toChecksumAddress('[WALLET ADDRESS]')

# code for instantiating an already-deployed contract
#enclave_registry_contract_address = w3.toChecksumAddress('''DEPLOYED CONTRACT ADDRESS''')
#contract_registry_contract_address = w3.toChecksumAddress('''DEPLOYED CONTRACT ADDRESS''')
#enclave_registry_contract = w3.eth.contract(address = w3.toChecksumAddress(enclave_registry_contract_address), abi = enclave_abi.abi)
#contract_registry_contract = w3.eth.contract(address = w3.toChecksumAddress(contract_registry_contract_address), abi = contract_registry_abi.abi)

#------------------------------------------------------------------------------
# This script first deploys the enclave registry contract.
# Next, it creates two enclaves and registers them in the enclave registry.
# These enclaves are then grabbed from the enclave registry contract and
# printed to illustrate their successful registry.
# Then, the script deploys the contract registry contract.
# Next, a contract is registered in the contract registry. This process
# requires adding a registered enclave to the contract and specifying which
# provisioning services are associated with the contract.
# The successfully registered contract and its corresponding enclaves are
# printed out.
# Finally, all registered enclaves and the contract are deleted.
#------------------------------------------------------------------------------
def main():
    # deploy and instantiate enclave registry contract
    enclave_registry_contract_dict = deploy_contract(enclave_registry_source_code.code, 'EnclaveRegistry')
    enclave_registry_contract_address = enclave_registry_contract_dict['address']
    enclave_registry_contract = enclave_registry_contract_dict['contract']

    # use as needed
    #send_ether_to_contract(0.5, enclave_registry_contract_address)
    #send_ether_to_contract(1, contract_registry_contract_address)

    #register two enclaves, client should replace fields with real data
    enclave_one = {
        'verifying_key': '0x12', #bytes32
        'encryption_key': 'encryptionKey', #string
        'owner_id': 'ownerID', #string
        'last_registration_block_context': 'LRBC', #string
    }
    print('\n \n REGISTERING ENCLAVE WITH ID: 0x12')
    register_enclave(enclave_one, enclave_registry_contract)

    #client should replace fields with real data
    enclave_two = {
        'verifying_key': '0x13',
        'encryption_key': 'encryptionKey',
        'owner_id': 'ownerID',
        'last_registration_block_context': 'LRBC'
    }
    print('\n \n REGISTERING ENCLAVE WITH ID: 0x13')
    register_enclave(enclave_two, enclave_registry_contract)
    print_enclaves(enclave_registry_contract)

    # deploy and instantiate contract registry contract
    contract_registry_contract_dict = deploy_contract(contract_registry_source_code.code, 'ContractRegistry')
    contract_registry_contract_address = contract_registry_contract_dict['address']
    contract_registry_contract = contract_registry_contract_dict['contract']

    #register a contract, client should replace fields with real data
    contract_one = {
        'contract_id': '0x10', #bytes32
        'code_hash': 'hash', #string
        'ps_public_keys_list': ["0x15", "0x16", "0x17"] #bytes32[]
    }


    print('\n \n REGISTERING CONTRACT WITH ID: 0x10')
    register_contract(contract_one, contract_registry_contract)

    #add an enclave to the registered contract, client should replace fields
    # with real data
    contract_enclave = {
        'contract_id': '0x10', #bytes32
        'verifying_key': '0x12', #bytes 32, same as 'enclave_id'
        'contract_state_encryption_key': 'encryptionKey', #string
        'enclave_signature': 'signature', #string
        'enclave_contract_addr': enclave_registry_contract_address #address
    }

    print('\n \n INITIALIZING ADDITION OF ENCLAVE 0x12 TO CONTRACT 0x10')
    add_enclave_init(contract_enclave, contract_registry_contract)

    #add a provisioning service to the enclave , client should replace fields
    # with real data
    provisioning_service = {
        'contract_id': '0x10', #bytes32
        'enclave_id': '0x12', #bytes32, same as 'verifying_key'
        'ps_public_key': '0x15', #bytes32
        'encrypted_contract_state': 'state', #string
        'index': 1 #int
    }
    print('\n \n ADDING PROVISIONING SERVICE 0x15 TO ENCLAVE 0x12')
    add_provisioning_service_to_enclave(provisioning_service, contract_registry_contract)

    #completes addition of an enclave to the registered contract
    print('\n \n COMPLETING ADDITION OF ENCLAVE 0x12 TO CONTRACT 0x10')
    add_enclave_completion(contract_enclave, contract_registry_contract)

    print_contracts(contract_registry_contract)

    #hashes a message, signs it, and verifies in contract. Prints results
    signature_demo(enclave_registry_contract)

#--------------------------------------------------------------------------
# Compiles contract source code and deploys it, returns contract address and
# an instance of the contract
#--------------------------------------------------------------------------
def deploy_contract(contract_source_code, contract_name):
    compiled_sol = compile_source(contract_source_code)
    interface_key = '<stdin>:' + contract_name
    contract_interface = compiled_sol[interface_key]
    acct = w3.eth.account.privateKeyToAccount(wallet_privateKey)
    nonce = w3.eth.getTransactionCount(wallet_address)
    contract = w3.eth.contract(abi=contract_interface['abi'], bytecode=contract_interface['bin'])
    tx_dict = contract.constructor().buildTransaction({
        'from': acct.address,
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': 1000000000,
        'nonce': nonce
    })

    print('\n \n DEPLOYING CONTRACT: {}'.format(contract_name))
    tx = complete_transaction(tx_dict)
    if (tx['status'] == 'failed'):
        print('\n Contract deployment failed. Error: {}. Exiting script.'.format(tx['error']))
        exit()

    address = tx['txn_receipt']['contractAddress']
    contract_instance = w3.eth.contract(address=address, abi=contract_interface['abi'])
    return {'contract': contract_instance, 'address': address}

#--------------------------------------------------------------------------
# Working signature implementation using keccak256 hash and ECDSA signature
#--------------------------------------------------------------------------
def signature_demo(enclave_registry_contract):
    print('\n \n SIGNATURE DEMO: ')

    msg = 'sometext'
    print('\n \t Message to hash: {}'.format(msg))
    hash = defunct_hash_message(text=msg) #uses keccak and ethereum prefix
    print('\n \t Hashed message: {}'.format(hash))
    signed_msg = w3.eth.account.signHash(hash, private_key=wallet_privateKey)
    print('\n \t Signature: {}'.format(signed_msg.signature))

    #split into components
    v = signed_msg.v
    r = to_32byte_hex(signed_msg.r)
    s = to_32byte_hex(signed_msg.s)

    print('\n \t Sending message to contract. Verifying message sender is signer.')
    #build transaction
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = enclave_registry_contract.functions.verify(hash, v, r, s).buildTransaction({
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

    #shows that sender and result are the same addresses
    sender = enclave_registry_contract.functions.getSender().call()
    result = enclave_registry_contract.functions.getResult().call()
    print('\n \t Sender: {}'.format(sender))
    print('\n \t Signer: {}'.format(result))
    print('\n \t Signature demo result: {}'.format(sender==result))

def to_32byte_hex(val):
    return w3.toBytes(val).rjust(32, b'\0')

#------------------------------------------------------------------------------
# Given a contract address and ether amount, sends specified amount to
# that contract
#------------------------------------------------------------------------------
def send_ether_to_contract(amount_in_ether, contract_address):
    print('\n SENDING ETHER TO CONTRACT')
    amount_in_wei = w3.toWei(amount_in_ether,'ether');
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = {
            'to': w3.toChecksumAddress(contract_address),
            'value': amount_in_wei,
            'gas': 3000000,
            'gasPrice': w3.toWei('40', 'gwei'),
            'nonce': nonce,
            'chainId': chain_id
    }
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Registers an enclave in the enclave registry
#------------------------------------------------------------------------------
def register_enclave(info, enclave_registry_contract):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = enclave_registry_contract.functions.register(info['verifying_key'], info['encryption_key'],
    info['owner_id'], info['last_registration_block_context']).buildTransaction({
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Deletes an enclave from the enclave registry. Note that the 'enclave_id'
# refers to the enclave's verifying key
#------------------------------------------------------------------------------
def delete_enclave(enclave_id, enclave_registry_contract):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = enclave_registry_contract.functions.deleteEnclaveByID(enclave_id).buildTransaction({
        'chainId': chain_id,
        'gas': 300000,
        'gasPrice': w3.toWei('40', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Prints list of all registered enclaves in the enclave registry
#------------------------------------------------------------------------------
def print_enclaves(enclave_registry_contract):
    enclave_keys = enclave_registry_contract.functions.getEnclaveIDs().call()
    print('\n \n PRINTING ENCLAVE LIST: ')
    count = 1
    for key in enclave_keys:
        enclave = enclave_registry_contract.functions.getEnclave(key).call()
        print('\n \n Enclave: {}'.format(count))
        print('\n \t verifying key: {}'.format(enclave[0]))
        print('\n \t encryption key: {}'.format(enclave[1]))
        print('\n \t owner ID: {}'.format(enclave[2]))
        print('\n \t last registration block context: {}'.format(enclave[3]))
        count = count + 1
    delineate()

#------------------------------------------------------------------------------
# Prints list of all registered contracts in the contract registry as well
# each contract's list of enclaves. Displays the information from each enclave
#------------------------------------------------------------------------------
def print_contracts(contract_registry_contract):
    contract_keys = contract_registry_contract.functions.getContractIDs().call()
    print('\n \n PRINTING CONTRACT LIST: ')
    count = 1
    for key in contract_keys:
        contract = contract_registry_contract.functions.getContract(key).call()
        print('\n \n Contract: {}'.format(count))
        print('\n \t contract ID: {}'.format(contract[0]))
        print('\n \t contract code hash: {}'.format(contract[1]))
        print('\n \t provisioning services public keys: {}'.format(contract[2]))
        #print list of enclaves
        enclave_keys = contract_registry_contract.functions.getEnclaveIDs(key).call()
        print('\n \t enclaves authorized to execute this contract: ')
        count_two = 1
        for enclave_key in enclave_keys:
            enclave = contract_registry_contract.functions.getEnclave(key, enclave_key).call()
            print('\n \t \t authorized enclave: {}'.format(count_two))
            print('\n \t \t verifying key: {}'.format(enclave[0]))
            print('\n \t \t contract state encryption key: {}'.format(enclave[1]))
            print('\n \t \t provisioning services public keys: {}'.format(enclave[2]))

    delineate()

#------------------------------------------------------------------------------
# Registers a contract in the contract registry. Note that this function does
# not add a list of enclaves to the contract-- this must be done through
# separate functions
#------------------------------------------------------------------------------
def register_contract(info, contract_registry_contract):
    nonce = w3.eth.getTransactionCount(w3.toChecksumAddress(wallet_address))

    tx_dict = contract_registry_contract.functions.register(info['contract_id'], info['code_hash'],
    info['ps_public_keys_list']).buildTransaction({
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Begin process of adding an enclave to a registered contract. Note that this
# function must be followed by at least one call to
# add_provisioning_service_to_enclave and one call to add_enclave_completion
# for successful addition.
#------------------------------------------------------------------------------
def add_enclave_init(info, contract_registry_contract):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = contract_registry_contract.functions.addEnclaveInit(info['contract_id'],
    info['verifying_key'], info['contract_state_encryption_key'],
    info['enclave_signature'], info['enclave_contract_addr']).buildTransaction({
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Adds a provisioning service to an enclave in the registered contract's list
# of enclaves. This function will only succeed if called between
# add_enclave_init and add_enclave_completion (provisioning services cannot be
# added to an enclave after the enclave has been successfully added to the
# registered contract)
#------------------------------------------------------------------------------
def add_provisioning_service_to_enclave(info, contract_registry_contract):
    nonce = w3.eth.getTransactionCount(wallet_address)

    tx_dict = contract_registry_contract.functions.addProvisioningServiceToEnclave(info['contract_id'],
    info['enclave_id'], info['ps_public_key'], info['encrypted_contract_state'],
    info['index']).buildTransaction({
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': w3.toWei('100', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Completes the addition of an enclave to a registered contract. Must follow
# call to add_enclave_init and at least one call to
# add_provisioning_service_to_enclave
#------------------------------------------------------------------------------
def add_enclave_completion(info, contract_registry_contract):
    nonce = w3.eth.getTransactionCount(wallet_address)

    tx_dict = contract_registry_contract.functions.addEnclaveCompletion(info['contract_id'],
    info['verifying_key']).buildTransaction({
        'chainId': chain_id,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Deletes a contract from the contract registry
#------------------------------------------------------------------------------
def delete_contract(contract_id, contract_registry_contract):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = contract_registry_contract.functions.deleteContract(contract_id).buildTransaction({
        'chainId': chain_id,
        'gas': 300000,
        'gasPrice': w3.toWei('40', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Performs redundant transaction procedures given method-specific argument.
# While waiting for transaction to be mined on the ledger, prints "None". Once
# the transaction is successfully mined, prints the transaction receipt.
#------------------------------------------------------------------------------
def complete_transaction(tx_dict):
    signed_tx = w3.eth.account.signTransaction(tx_dict, private_key=wallet_privateKey)
    result = w3.eth.sendRawTransaction(signed_tx.rawTransaction)

    tx_receipt = w3.eth.getTransactionReceipt(result)
    count = 0
    print('\n Transaction receipt: ')
    while tx_receipt is None and (count < 30):
        time.sleep(10)
        tx_receipt = w3.eth.getTransactionReceipt(result)
        print(tx_receipt)
        count += count
    delineate()
    if tx_receipt is None:
        return {'status': 'failed', 'error': 'timeout'}

    return {'status': 'added', 'txn_receipt': tx_receipt}


def delineate():
    print('\n \n *************************************************************************************')


main()
