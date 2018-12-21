<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Contract Enclave Service #

The contract enclave service is an HTTP server that passes messages between a client and a contract
enclave. In addition, the enclave service registers the enclave with the ledger on initialization.

See the [build documentation](BUILD.md) for information about installation of the contract enclave
service. This document assumes that the enclave service will be run from a virtual environment
rooted at the path pointed to by the environment variable ``PDO_HOME``.

## Configuration ##

The contract enclave service is configured through an Toml configuration file generally placed in
the ``$PDO_HOME/etc/eservice.toml``.

## Command Line Parameters ##

* config -- name of the configuration file, default is ``eservice.toml``
* config-dir -- one or more directories to search for the configuration file, default is
``[".", "./etc", "$PDO_HOME/etc"]``.
* identity -- *REQUIRED*, a string used to identify log and data files for the enclave service
* logfile -- name of the file for logging, use ``__screen__`` for logging to standard output
* loglevel -- level of logging to use, can be one of ``DEBUG``, ``INFO``, ``WARN``, ``ERROR``
* http -- the port where the HTTP server will listen
* enclave-data -- the name of the file used to store enclave data
* enclave-save -- the path to the file if not specified in the ``enclave-data`` parameter, this is
  only used if new enclave data must be created
* enclave-path -- a list of directories to search for the enclave data file

## Operations ##

The enclave service supports three POST operations for interacting with the enclave:
``EnclaveDataRequest``, ``VerifySecretRequest``, and ``UpdateContractRequest``. In addition, the
enclave service supports a simple GET operation the shutdown the service.

Operations are submitted as JSON encoded strings. All operations contain an ``operation`` field that
specifies the operation to perform. Generally, binary data (both input and output) should be encoded
in base64.

The JSON schema is fully documented in [eservice.json](eservice.json),
[basetypes.json](basetypes.json), and [contract.json](contract.json). Below we show simplified
descriptions of each of the eservice operations.

### Enclave Data Request ###

The ``EnclaveDataRequest`` operation returns information about the enclave including the ECDSA
verifying key and the RSA encryption key.

#### Input ####

```JSON
{
    "operation" : "EnclaveDataRequest"
}
```

#### Output ####

```JSON
{
    "verifying_key" : "base64 encoded ECDSA verifying key for the enclave",
    "encryption_key" : "base64 encoded RSA encryption key for the enclave"
}
```

### Verify Secret Request ###

The verify secret request is used to create a contract state encryption key from a list of secrets
created by provision services.

#### Input ####

```JSON
{
    "operation" : "VerifySecretRequest",
    "contract_id" : "contract identifier",
    "creator_id" : "contract creator's PEM encoded verifying key",
    "serets" : [
        {
            "pspk" : "provisioning service's PEM encoded verifying key",
            "encrypted_secret" : "encrypted secret and signature",
        },
        {}
    ]
}
```

#### Output ####

```JSON
{
    "encrypted_state_encryption_key" : "base64 encoded, encrypted AES key",
    "signature" : "base64 encoded, enclave signature"
}
```

### Update Contract Request ###

The update contract request invokes a method on a contract. To preserve confidentiality, the request
is encrypted so that only the enclave can decrypt it. Typically, a client will create an AES session
key and encrypts it with the enclave's RSA key. The client uses the AES session key to encrypt the
request. The contract enclave decrypts the session key and uses it to decrypt the request. When it
is finished, the result is encrypted with the session key and returned to the client.

The format of the contract request is documented in [contract.json](contract.json).

#### Input ####

```JSON
{
    "operation" : "UpdateContractRequest",
    "encrypted_session_key" : "base64 encoded, session key encrypted with enclave's RSA key",
    "encrypted_request" : "base64 encoded, contract request encrypted with session AES key"
}
```

#### Output ####

```JSON
{
    "result" : "base64 encoded, contract response encrypted with AES session key"
}
```
