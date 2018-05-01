<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Provisioning Service Unit Tests

### PASSING TESTS

**Test Case:	1.1**
**Scenario:**	Unpack the request from the user and make sure all required fields are present, all parameters get varified, and a secret
is correctly retrieved or created and returned to the client
**Data:	Minfo containing:**
	Minfo[‘enclave_txn_id’]: [valid ID]
	Minfo[‘contract_txn_id’]: [valid ID]
	Minfo[‘opk’]: [valid contract owner public key]
	Minfo[‘signature’]: [valid signature]
**Expected Result:**	Should pass with no exceptions and return a PSPK and Secret to the client


### FAILING TESTS:

**Test Case:	2.1.1**
**Scenario:**	Unpack the request from the user and make sure all required fields are present, but at least one field will be empty
**Data:	Minfo containing:**
	*Minfo[‘enclave_txn_id’]: NONE*
	Minfo[‘contract_txn_id’]: [valid ID]
	Minfo[‘opk’]: [valid contract owner public key]
	Minfo[‘signature’]: [valid signature]
**Expected Result:**	Should throw an exception saying the Enclavetxnid is missing (Is this how that error works?)

**Test Case:	2.1.2**
**Scenario:**	Unpack the request from the user and make sure all required fields are present, but at least one field will be empty
**Data:	Minfo containing:**
	Minfo[‘enclave_txn_id’]: [valid ID]
	*Minfo[‘contract_txn_id’]: NONE*
	Minfo[‘opk’]: [valid contract owner public key]
	Minfo[‘signature’]: [valid signature]
**Expected Result:**	Should throw an exception saying the contracttxnid is missing (Is this how that error works?)

**Test Case:	2.1.3**
**Scenario:**	Unpack the request from the user and make sure all required fields are present, but at least one field will be empty
**Data:	Minfo containing:**
	Minfo[‘enclave_txn_id’]: [valid ID]
	Minfo[‘contract_txn_id’]: [valid ID]
	*Minfo[‘opk’]: NONE*
  Minfo[‘signature’]: [valid signature]
**Expected Result:**	Should throw an exception saying the opk is missing (Is this how that error works?)

**Test Case:	2.1.4**
**Scenario:**	Unpack the request from the user and make sure all required fields are present, but at least one field will be empty
**Data:	Minfo containing:**
	Minfo[‘enclave_txn_id’]: [valid ID]
	Minfo[‘contract_txn_id’]: [valid ID]
	Minfo[‘opk’]: [valid contract owner public key]
	*Minfo[‘signature’]: NONE*
**Expected Result:**	Should throw an exception saying the signature is missing (Is this how that error works?)

**Test Case:	2.2.1**
**Scenario:**	Request signature is not signed by the contract owner (OPK is incorrect)
**Data:**
	Enclavetxnid: [valid ID]
	Contracttxnid: [valid ID]
	*Opk: [invalid contract owner public key]*
	Signature: [valid signature]
**Expected Result:**	Signature and request are not verified and an exception is raised.

**Test Case:	2.2.2**
**Scenario:**	Request signature is not signed by the contract owner (OPK is incorrect and in wrong format)
**Data:**
	Enclavetxnid: [valid ID]
	Contracttxnid: [valid ID]
	*Opk: [invalid contract owner public key that is too large or small]*
	Signature: [valid signature]
**Expected Result:**	Signature and request are not verified and an exception is raised.

**Test Case:	2.2.3**
**Scenario:**	Retrieving the contract registration transaction from the ledger for a contract that exists, but contract owner’s public key does not match the signer of the request (OPK).
**Data:**
	Contracttxnid: [valid ID]
	‘Update’’UpdateType’: [valid]
	‘Status’ (integer): 2
	*Opk: [incorrect opk]*
**Expected Result:**	Exception should be thrown saying the operation is not allowed for the request signer

**Test Case:	2.3.1**
**Scenario:**	Retrieving the Enclave Encryption Key from the ledger for an enclave that does not exist
**Data:**
	*Enclavetxnid: [invalid ID]*
	‘TransactionType’: [valid]
	‘Update’’UpdateType’: [valid]
	‘Status’ (integer): 2
**Expected Result:**	Exception should be thrown saying enclave transaction does not exist.

**Test Case:	2.3.2**
**Scenario:**	Retrieving the contract registration transaction from the ledger for a contract that does not exist
**Data:**
	*Contracttxnid: [invalid ID]*
	‘Update’’UpdateType’: [valid]
	‘Status’ (integer): 2
	Opk: [valid opk]
**Expected Result:** Exception should be thrown saying the contract transaction doesn’t exist

