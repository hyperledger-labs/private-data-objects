<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Storage Service #

The storage service is an HTTP server that manages the client interface to the block storage associated with a [contract enclave service](eservice.md).

See the [build documentation](BUILD.md) for information about installation of the contract enclave and storage services. This document assumes that the storage service will be run from a virtual environment rooted at the path pointed to by the environment variable ``PDO_HOME``.

## Configuration ##

The storage service is configured through a Toml configuration file generally place in ``$PDO_HOME_/etc/sservice.toml``.

## Command Line Parameters ##

* config -- one or more configuration files, default is ``sservice.toml``
* config-dir -- one or more directories to search for the configuration file, default is ``[".", "./etc", "$PDO_HOME/etc"]``.
* identity -- *REQUIRED*, a string used to identify log and key files
* logfile -- name of the file for logging, use ``__screen__`` for logging to standard output
* loglevel -- level of logging to use, can be one of ``DEBUG``, ``INFO``, ``WARN``, ``ERROR``
* http -- the port where the HTTP server will listen
* key-dir -- one or more directories to search for the private key used by the storage service to sign storage contracts
* data-dir -- path where data files are stored
* block-store -- name of the file where blocks are stored, defaults to ``${data}/${identity}.mdb``
* gc-interval -- the interval over which the garbage collector runs in seconds, defaults to 10

## Operations ##

The storage service supports several operations for interacting with the block store.

| URL             | Method | Request Body     | Response Body            | Description                                    |
|:----------------|:-------|:-----------------|:-------------------------|------------------------------------------------|
| /block/get/<id> | GET    | None             | application/octet-string | Return the requested block                     |
| /block/gets     | POST   | application/json | multipart/form           | Return requested blocks                        |
| /block/list     | GET    | None             | application/json         | List of all known blocks                       |
| /block/check    | POST   | application/json | application/json         | Size and expiration of requested blocks        |
| /block/store    | POST   | multipart/form   | application/json         | Store multiple blocks, return proof of storage |
| /info           | GET    | None             | application/json         | Request information about the service          |
| /shutdown       | GET    | None             | None                     | Request to shutdown the service                |

Across operations, a block id (the sha256 hash of the block) will be represented as a url-encoded, base64 string. Block data is always binary and identified as ``application/octet-string``.

### Check Blocks ###

The ``check`` operation returns the size and expiration time of any requested block that is currently maintained by the storage service. If a requested block is currently not managed by the storage service, length and expiration will be set to 0. Note that the expiration is the number of seconds in the future (not wall clock time) that the storage service agrees to persist the block.

#### Input ####

```JSON
[
    "base64 encoded block hash", ...
]
```

#### Output ####

```JSON
[
    {
        "block_id" : "base64 encoded block hash",
        "size" : "integer",
        "expiration" : "integer"
    },
    ...
    {}
]
```
### Get Blocks ###

The ``gets`` operation returns data associated with a requested list of block identifiers. The operation will fail if any of the requested blocks are not currently managed by the storage service. The operation returns a ``multipart/form`` encoded response with each section of the response containing the contents of one of the requested blocks.

#### Input ####

```JSON
[
    "base64 encoded block hash", ...
]
```

### Store Blocks ###

The ``store`` operation requests that the storage service manage a set of blocks for at least a requested interval of time. If the storage service agrees to manage the blocks for the requested time, it will sign the hash of the hashes of the stored blocks (computed in the same order as the blocks were requested). The request will be encoded as ``multipart/form``. The first section of the form will contain a ``JSON`` request that includes requested expiration time. Each specified block will be in its own section in the form.

#### Input ####


```JSON
{
    "expiration" : "integer",
}
```

#### Output ####

```JSON
{
    "signature" : "base64 encoded signature"
    "block_ids" : [
        "base64 encoded block hash", ...
    ]
}
```
