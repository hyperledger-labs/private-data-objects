<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# PDO Coordination and Commit Log (CCL) Transaction Family Specification  #

Version 0.1

## Overview ##

The PDO CCL transaction family ensures proper serialization of contract state
updates and facilitates coordination between contract instances.

## State ##

The CCL is a graph where each node represents the state of a contract at a
particular point in time and the edges represent dependencies between those
states. Each node will be captured in the global state (and these nodes will be
immutable once created). In addition, each contract will have an entry that
reflects the current state of the contract. These will provide an entry point
into the graph of state updates for the contract. The contract entries will
change on every update.

### Contract State Reference ###

The contract state reference message is a simple reference to a particular
instance of state for a contract. This reference is used to capture dependencies
and to point to the current state of a contract.

```cpp
message CCL_ContractStateReference
{
  // The identifier of the contract registration transaction
  string contract_id = 1;

  // The hash of the current state
  string state_hash = 2;
}
```

### Contract State Update ###

The contract state update message captures information about a specific state
update; that is, the message represents a node in the CCL graph. The information
in the message comes directly from the transaction that committed the update.

```cpp
message CCL_ContractStateUpdate
{
  // The hash of the contract registration transaction identifier
  string contract_id = 1;

  // The hash of the current state
  string current_state_hash = 2;

  // The hash of the previous state
  string previous_state_hash = 3;

  // The hash of the message that caused the update
  string message_hash = 4;

  // OPTIONAL: The actual encrypted state of the contract
  string encrypted_state = 5;

  // Dependencies are references to a specific instance
  // of state from another contract
  repeated CCL_ContractStateReference dependency_list = 6;
}
```

### Contract State ###

The contract state message is the one that is actually stored in the Sawtooth
Global Store. In order to simplify access to the transaction in which the update
was committed (necessary for the client to specify transaction dependencies
efficiently) we add the identifier to the transaction.

```cpp
message CCL_ContractState
{
    // The identifier of the transaction in which this state update was
    // committed
    string transaction_id = 1;

    // The details of the state update
    CCL_ContractStateUpdate state_update = 2;
}
```

### Contract Information ###

The contract information message captures the current state of the contract. It
contains the contract identifier and a link to the current state of the
contract.

```cpp
message CCL_ContractInformation
{
  // The hash of the contract registration transaction identifier
  string contract_id = 1;

  // A reference to the most recently committed state of the contract
  CCL_ContractStateReference current_state = 2;

  // A flag to indicate that the contract is active
  bool is_active = 3;
}
```

## Addressing ##

Messages of type ``CCL_ContractState`` and ``CCL_ContractInformation``
will be stored in the global state. Addresses for ``CCL_ContractState`` will be
constructed by appending the following:

* The first six characters of the sha512 hash of the contract state namespace
  ('ccl_contract_state_registry')
* The first 32 bytes of the sha512 hash of the ``contract_id``from the ``CCL_ContractStateUpdate``
* The first 32 bytes of the sha512 hash of the state hash from the ``CCL_ContractStateUpdate``
This mechanism enables to utilize Sawtooth wild card support for “getters” that allows to submit incomplete address and retrieve all entries that have address starting from the wild card.

Addresses for ``CCL_ContractInformation`` will be constructed by appending the
following:

* The first six characters of the sha512 hash of the contract state namespace
 ('ccl_contract_information_registry')
* The sha512 hash of the contract id field

## Transaction Payload ##

The PDO CCL defines a single message format for transactions since every update
represents a state transformation. The transaction payload is defined by the
``CCL_TransactionPayload`` protocol buffer message:

```cpp
message CCL_TransactionPayload {
    // The action that the transaction processor will take.
    string verb = 1;

    // ECDSA public key of the enclave, base64 encoded
    string contract_enclave_id = 2;

    // Signature from the contract enclave, base64 encoded
    string contract_enclave_signature = 3;

    // ECDSA public key for the channel
    string channel_id = 4;

    // This is all the details of the state update
    CCL_ContractStateUpdate state_update = 5;

    // PDO signature to be verified with contract creator key
    string pdo_signature = 6;
}
```

Three verbs are defined: ``initialize``, ``update`` and ``terminate``. Each verb
imposes unique restrictions on the state update:

Verb            | Restrictions
--------------- | ---------------
``initialize``  | the previous state hash must be ``NULL`` and the dependency list must be empty
``update``      | both previous and current state has must be defined
``terminate``   | the current state hash must be ``NULL``

The ``contract_enclave_id`` field contains the public key of the SGX contract
enclave that performed the state update. The enclave must be registered in the
contract enclave registry and must be provisioned for this contract.

The ``contract_enclave_signature`` is the proof that the specified enclave
generated the update. The signature is computed over the serialized state update
and the channel identity.

The ``channel_id`` is the ECDSA public key for the channel used to communicate
between the client and the contract enclave. This identity must match the
identity that submitted the transaction. If the public key is available in the
transaction (as opposed to the address), then this field is redundant and could
be removed.

The ``pdo_signature`` field contains a proof that the contract creator wants to perform
the requested operation. The field is important during the CCL initialize request, while
it is not used for CCL updates. The signature is performed with the creator's
private key over the sha256 hash of the serialization of the following fields:
* ``enclave_id``
* ``enclave_signature`` converted in binary format
* ``channel_id``
* ``contract_id``
* ``creator_public_key``
* ``contract_code_hash`` converted in binary format
* ``message_hash`` converted in binary format
* ``current_state_hash`` converted in binary format
* ``previous_state_hash`` converted in binary format
* ``contract_id_1``
* ``state_hash_1``
* ``contract_id_2``
* ``state_hash_2``
* ... for all the specified ``contract_id``-``state_hash`` dependencies

## Transaction Header ##

Transaction signer public key must be the same as the ``channel_id``
field in the ``state_update``.

Transaction dependencies field must be set to ensure that the contract
state dependencies in the ``state_udpate`` are met. The client is
expected to compute that list by pulling the transaction identifier from the
corresponding state update in the Sawtooth Global State.

## Inputs and Outputs ##

The input set for all updates includes the ``CCL_ContractInformation`` message
referenced by the ``contract_id`` field. The input set also includes at least the
``CCL_ContractState`` message for the previous state of the contract and also
all references in the ``dependency_list``.

The input set also includes the contract enclave in the contract enclave
registry. This is necessary to verify that the contract enclave in the state
update is in fact a valid contract enclave.

Finally, the input set includes the contract registration from the contract
registry. The contract registry contains a hash of the contract code and a list
of provisioned enclaves that must be checked.

The output set includes the referenced ``CCL_ContractInformation`` message for
the contract and a new message for the state update.

## Dependencies ##

Transaction validation requires that the contract enclave registry and contract
registry are available.

## Family ##

* family_name: "ccl_contract"
* family_version: "1.0"

## Encoding ##

The encoding field must be set to "application/protobuf".

## Execution ##

### Common Checks ###

In addition to basic integrity checks, all CCL transactions must meet the
following criteria to be considered valid:

  * Verify that signer public key is the same as the ``channel_id`` field in the ``state_update``
  * The transaction must contain a valid signature from the contract
    enclave. The signature applies to the serialization of the following fields:
      * ``channel_id``
      * ``contract_id``
      * ``pdo_contract_creator_pem_key``
      * ``contract_code_hash`` retrieved from the contract registry
      * ``message_hash``
      * ``current_state_hash``
      * ``previous_state_hash``
      * ``dependency_list`` (if any is required)
  * The ``initialize`` transaction must contain a valid signature from the contract creator.
    The signature applies to the serialization of the following fieldsL
      * ``contract_enclave_id``
      * ``contract_enclave_signature``
      * (the fields in the signature above)
  * All dependencies must be committed; all ``CCL_ContractStateReference``
    messages in the ``dependency_list`` must exist in the CCL.
  * The contract must be registered in the contract registry; ``contract_id``
    refers to a valid contract in the contract registry
  * The contract enclave must be provisioned for this contract;
    ``contract_enclave_id`` must be in the list of provisioned enclaves in the
    contract registry

### Transaction Verb: ``initialize`` ###

The ``initialize`` transaction creates the initial state of the contract. In
addition to the general conditions for CCL transactions, the ``initialize``
transaction must meet the following criteria to be considered valid:

  * The contract must not be initialized already; there should be no
  ``CCL_ContractInformation`` entry for the contract
  * Only the creator of the contract may initialize the contract
  * ``previous_state_hash`` must be ``NULL``
  * ``dependency_list`` must be ``NULL``

A valid ``initialize`` transaction first creates a ``CCL_ContractState`` message
where it places the identity of the transaction and the body of the
``CCL_ContractStateUpdate`` from the transaction. Next, it creates a
``CCL_ContractInformation`` message. The ``current_state`` field references the
``CCL_ContractState`` message that was created and sets the ``is_active`` flag
to ``True``.

### Transaction Verb: ``update`` ###

The ``update`` transaction updates the state of a contract. In addition to the
general conditions for CCL transactions, the ``update`` transaction must meet
the following criteria to be considered valid:

  * The contract has been initialized; the ``CCL_ContractInformation`` must
    exist for the contract
  * The contract is active; ``is_active`` in the ``CCL_ContractInformation``
    message must be ``True``
  * The transaction must extend the current state; the ``previous_state_hash``
    field must be the same as the ``current_state`` field in the
    ``CCL_ContractInformation`` message for the contract

A valid ``update`` transaction first creates a ``CCL_ContractState`` message
where it places the identity of the transaction and the body of the
``CCL_ContractStateUpdate`` from the transaction. Next, it updates the
``CCL_ContractInformation`` message for the contract to reference the newly
constructed state message.

### Transaction Verb: ``terminate`` ###

The ``terminate`` transaction changes the state of a contract to inactive. In
addition to the general conditions for CCL transactions, the ``terminate``
transaction must meet the following criteria to be considered valid:

  * The contract has been initialized; the ``CCL_ContractInformation`` must
    exist for the contract
  * The contract is active; ``is_active`` in the ``CCL_ContractInformation``
    message must be ``True``
  * The transaction must extend the current state; the ``previous_state_hash``
    field must be the same as the ``current_state`` field in the
    ``CCL_ContractInformation`` message for the contract
  * The ``current_state_hash`` must be ``NULL``

A valid ``terminate`` transaction changes the ``is_active`` field in the current
``CCL_ContractInformation`` message for the contract to ``False``.
