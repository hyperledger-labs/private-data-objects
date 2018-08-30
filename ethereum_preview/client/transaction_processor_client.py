import web3
import enclave_abi
import contract_registry_abi
import time

from web3 import Web3, HTTPProvider


# web3.py instance
w3 = Web3(HTTPProvider('''HTTP PROVIDER'''))

w3.eth.enable_unaudited_features()

# Wallet info
wallet_privateKey = '''WALLET PRIVATE KEY'''
wallet_address = w3.toChecksumAddress('''WALLET ADDRESS''')

enclave_registry_contract_address = w3.toChecksumAddress('''DEPLOYED CONTRACT ADDRESS''')
contract_registry_contract_address = w3.toChecksumAddress('''DEPLOYED CONTRACT ADDRESS''')

enclave_registry_contract = w3.eth.contract(address = w3.toChecksumAddress(enclave_registry_contract_address), abi = enclave_abi.abi)
contract_registry_contract = w3.eth.contract(address = w3.toChecksumAddress(contract_registry_contract_address), abi = contract_registry_abi.abi)

#------------------------------------------------------------------------------
# This script first sends ether to the two contracts.
# Next, it creates two enclaves and registers them in the enclave registry.
# These enclaves are then grabbed from the enclave registry contract and
# printed to illustrate their successful registry.
# Next, a contract is registered in the contract registry. This process
# requires adding a registered enclave to the contract and specifying which
# provisioning services are associated with the contract.
# The successfully registered contract and its corresponding enclaves are
# printed out.
# Finally, all registered enclaves and the contract are deleted.
#------------------------------------------------------------------------------
def main():


    send_ether_to_contract(0.5, enclave_registry_contract_address)

    send_ether_to_contract(1, contract_registry_contract_address)

    #register two enclaves, client should replace fields with real data
    enclave_one = {
        'verifying_key': '0x12', #bytes32
        'encryption_key': 'encryptionKey', #string
        'owner_id': 'ownerID', #string
        'last_registration_block_context': 'LRBC', #string
    }
    print('\n Registering enclave: 0x12')
    register_enclave(enclave_one)

    #client shoule replace fields with real data
    enclave_two = {
        'verifying_key': '0x13',
        'encryption_key': 'encryptionKey',
        'owner_id': 'ownerID',
        'last_registration_block_context': 'LRBC'
    }
    print('\n Registering enclave: 0x13')
    register_enclave(enclave_two)
    print_enclaves()

    #register a contract, client should replace fields with real data
    contract_one = {
        'contract_id': '0x10', #bytes32
        'code_hash': 'hash', #string
        'ps_public_keys_list': ["0x15", "0x16", "0x17"] #bytes32[]
    }


    print('\n Registering contract with ID: 0x10')
    register_contract(contract_one)

    #add an enclave to the registered contract, client should replace fields
    # with real data
    contract_enclave = {
        'contract_id': '0x10', #bytes32
        'verifying_key': '0x12', #bytes 32, same as 'enclave_id'
        'contract_state_encryption_key': 'encryptionKey', #string
        'enclave_signature': 'signature', #string
        'enclave_contract_addr': enclave_registry_contract_address #address
    }

    print('\n Initializing addition of enclave 0x12 to contract 0x10')
    add_enclave_init(contract_enclave)

    #add a provisioning service to the enclave , client should replace fields
    # with real data
    provisioning_service = {
        'contract_id': '0x10', #bytes32
        'enclave_id': '0x12', #bytes32, same as 'verifying_key'
        'ps_public_key': '0x15', #bytes32
        'encrypted_contract_state': 'state', #string
        'index': 1 #int
    }
    print('\n Adding provisioning service 0x15 to enclave 0x12')
    add_provisioning_service_to_enclave(provisioning_service)

    #completes addition of an enclave to the registered contract
    print('\n Completing addition of enclave 0x12 to contract 0x10')
    add_enclave_completion(contract_enclave)

    print_contracts()

    print('\n Deleting contract with ID: 0x10')
    delete_contract('0x10')

    #show empty contract list
    print_contracts()

    print('\n Deleting enclave with ID: 0x12')
    delete_enclave('0x12')

    print('\n Deleting enclave with ID: 0x13')
    delete_enclave('0x13')

    #show empty enclave list
    print_enclaves()

#------------------------------------------------------------------------------
# Given a contract address and ether amount, sends specified amount to
# that contract
#------------------------------------------------------------------------------
def send_ether_to_contract(amount_in_ether, contract_address):
    print('\n Sending ether to contract')
    amount_in_wei = w3.toWei(amount_in_ether,'ether');
    nonce = w3.eth.getTransactionCount(wallet_address)

    tx_dict = {
            'to': w3.toChecksumAddress(contract_address),
            'value': amount_in_wei,
            'gas': 3000000,
            'gasPrice': w3.toWei('40', 'gwei'),
            'nonce': nonce,
            'chainId': 3
    }
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Registers an enclave in the enclave registry
#------------------------------------------------------------------------------
def register_enclave(info):
    nonce = w3.eth.getTransactionCount(wallet_address)

    tx_dict = enclave_registry_contract.functions.register(info['verifying_key'], info['encryption_key'],
    info['owner_id'], info['last_registration_block_context']).buildTransaction({
        'chainId': 3,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Deletes an enclave from the enclave registry. Note that the 'enclave_id'
# refers to the enclave's verifying key
#------------------------------------------------------------------------------
def delete_enclave(enclave_id):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = enclave_registry_contract.functions.deleteEnclaveByID(enclave_id).buildTransaction({
        'chainId': 3,
        'gas': 300000,
        'gasPrice': w3.toWei('40', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Prints list of all registered enclaves in the enclave registry
#------------------------------------------------------------------------------
def print_enclaves():
    enclave_keys = enclave_registry_contract.functions.getEnclaveIDs().call()
    print('\n Printing Enclave List: ')
    for key in enclave_keys:
        print('Enclave: {}'.format(enclave_registry_contract.functions.getEnclave(key).call()))


#------------------------------------------------------------------------------
# Prints list of all registered contracts in the contract registry as well
# each contract's list of enclaves. Displays the information from each enclave
#------------------------------------------------------------------------------
def print_contracts():
    contract_keys = contract_registry_contract.functions.getContractIDs().call()
    print('\n Printing Contract List: ')
    for key in contract_keys:
        print('Contract: {}'.format(contract_registry_contract.functions.getContract(key).call()))
        #print list of enclaves
        enclave_keys = contract_registry_contract.functions.getEnclaveIDs(key).call()
        print('\n Printing Contract Enclave List: ')
        for enclave_key in enclave_keys:
            print('Enclave: {}'.format(contract_registry_contract.functions.getEnclave(key, enclave_key).call()))

#------------------------------------------------------------------------------
# Registers a contract in the contract registry. Note that this function does
# not add a list of enclaves to the contract-- this must be done through
# separate functions
#------------------------------------------------------------------------------
def register_contract(info):
    nonce = w3.eth.getTransactionCount(w3.toChecksumAddress(wallet_address))

    tx_dict = contract_registry_contract.functions.register(info['contract_id'], info['code_hash'],
    info['ps_public_keys_list']).buildTransaction({
        'chainId': 3,
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
def add_enclave_init(info):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = contract_registry_contract.functions.addEnclaveInit(info['contract_id'],
    info['verifying_key'], info['contract_state_encryption_key'],
    info['enclave_signature'], info['enclave_contract_addr']).buildTransaction({
        'chainId': 3,
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
def add_provisioning_service_to_enclave(info):
    nonce = w3.eth.getTransactionCount(wallet_address)

    tx_dict = contract_registry_contract.functions.addProvisioningServiceToEnclave(info['contract_id'],
    info['enclave_id'], info['ps_public_key'], info['encrypted_contract_state'],
    info['index']).buildTransaction({
        #'from': wallet_address,
        'chainId': 3,
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
def add_enclave_completion(info):
    nonce = w3.eth.getTransactionCount(wallet_address)

    tx_dict = contract_registry_contract.functions.addEnclaveCompletion(info['contract_id'],
    info['verifying_key']).buildTransaction({
        #'from': wallet_address,
        'chainId': 3,
        'gas': 3000000,
        'gasPrice': w3.toWei('50', 'gwei'),
        'nonce': nonce
    })
    complete_transaction(tx_dict)

#------------------------------------------------------------------------------
# Deletes a contract from the contract registry
#------------------------------------------------------------------------------
def delete_contract(contract_id):
    nonce = w3.eth.getTransactionCount(wallet_address)
    tx_dict = contract_registry_contract.functions.deleteContract(contract_id).buildTransaction({
        'chainId': 3,
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
    while tx_receipt is None and (count < 30):
        time.sleep(10)
        tx_receipt = w3.eth.getTransactionReceipt(result)
        print(tx_receipt)
        count += count

    if tx_receipt is None:
        return {'status': 'failed', 'error': 'timeout'}

    return {'status': 'added', 'txn_receipt': tx_receipt}

main()
