<!--- -*- mode: markdown; fill-column: 80 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# PDO Enclave Registry Transaction Family Specification  #

Version 0.1

## Overview ##

The PDO Contract Enclave registry maintains a list of PDO enclaves available for the smart contract execution.

## State ##

This section describes what enclave information is saved in the Sawtooth Global State.

The PDO enclave info is defined as follows:
```cpp
message PdoContractEnclaveInfo {
    // Encoded public key corresponding to private key used the PDO contract
    // enclave to sign contract updates.
    // It is also serves an id to generate address for this entry
    string verifying_key = 1;

    // RSA key used to encrypt messages to the enclave
    string encryption_key = 2;

    // Public key of the signer who submitted "register" transaction
    // for the contract enclave
    // "Revoke" and "update" transaction signuatures must be verified
    // using this key
    string owner_id = 3;

    // Block identifier copied from the most recent registration
    // of this enclave used to ensure that the enclave
    // has been re-registered recently enough
    string last_registration_block_context = 4;

    // This is "register" transaction signature hash. It can be used
    // to get all registration transaction details from the ledger.
    string registration_transaction_id = 5;
}
```
## Transaction Payload ##

PDO enclave registry transaction family payloads are defined by the following protocol buffers codes:

```cpp
message PdoContractEnclaveTransaction {
    // The action that the transaction processor will take.
    // Currently this is only “register”, but could include other actions
    // in the futures such as “revoke”, "update", or "refresh"
    string verb = 1;

    // Encoded public key corresponding to private key used the PDO contract
    // enclave to sign contract updates.
    // It is also serves an id to generate address for this entry
    string verifying_key = 2;

    // Transaction details specific to the action. Currently only details
    // for "register" action are defined - PdoContractEnclaveRegister
    bytes transaction_details = 3;
}
```
```cpp
message PdoContractEnclaveRegister {
    // Reserved for future use; currently ignored
    string organizational_info = 1;

    // RSA key used to encrypt messages to the enclave
    string encryption_key = 2;

    // Information that can be used internally to verify the validity of
    // the registration information stored as an opaque buffer.
    string proof_data = 3;

    // EPID pseudonym that identifies the host on which
    // the enclave resides, knowing that two enclaves reside on the
    // same host enables provisioning policies that distribute across hosts
    string enclave_persistent_id = 4;

    // This is the identity of a block in the chain.
    // This prevents old registrations from being included.
    // No known threats from the old registrations at this point
    string registration_block_context = 5;
}
```
```cpp
message PdoContractEnclaveUpdate {
    // This is the identity of a block in the chain.
    string registration_block_context = 1;
}
```

## Transaction Header ##

## Inputs and Outputs ##

The inputs for validator registry family transactions must include:
*	the PDO enclave registry address of ``verifying_key``
*	the address of Sawtooth setting sawtooth.pdo.report_public_key_pem
*	the address of Sawtooth setting sawtooth.pdo.valid_enclave_measurement
*	the address of Sawtooth setting sawtooth.pdo.valid_enclave_basenames

The outputs for validator registry family transactions must include:
*	the PDO enclave registry address of ``verifying_key``

## Dependencies ##

None

## Family ##

*	family_name: “pdo_contract_enclave_registry”
*	family_version: “1.0”

## Encoding ##

The encoding field must be set to “application/protobuf”.

## Execution ##

Untrusted python code that is a part of the transaction processor will verify the attestation verification report for the signup information. It is important to note that the IAS report public key, the basenames and measurements will need to be on the blockchain and it will need to be set on configuration. When an SGX Enclave is running in simulation mode, its registration transaction payload contains an empty proof_data field. The rest of the simulator logic and real SGX logic stays the same. SGX simulation is supported by PDO Sawtooth Transaction Processor only in debug mode and not allowed in non-debug mode."

The report data, included in the enclave's attestation, is the sha256 hash of the serialization of the following fields:
* ``verifying_key``
* ``encryption_key``
* transaction public key hash
