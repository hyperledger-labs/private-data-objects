<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Building and Deploying Contracts with Wawaka #

The [Wawaka contract interpreter](../../common/interpreter/wawaka/README.md)
 processes contracts for private data objects based on the
[WebAssembly Micro Runtime](https://github.com/intel/wasm-micro-runtime)
developed by Intel (WAMR). WAMR implements a small WebAssembly VM and a
set of supporting functions that can be executed inside the contract
enclave. As such contracts can be implemented in any programming
language that can be compiled into WASM.

## Contracts Included in the Distribution ##

This project comes bundled with a few example contracts which you can
experiment with. For the most part, the contracts included in the distribution
are used primarily for testing and are not intended for production use.

- [mock-contract](../wawaka/mock-contract)
A very simple contract which allows the contract owner to increment and
retrieve a stored value. Other parties can interact with the contract only
through an anonymous operation for incrementing the value.

- [memory-test](../wawaka/memory-test)
Another simple contract that tests the limits for memory use by contracts.
Tests include multiple persistent key/value operations, large values, and
extensive recursion.

- [kv-test](../wawaka/kv-test)
A contract to demonstrate and test the use of a separate, encrypted key/value
store. The use of a separate key/value store simplifies sharing of data amongst
a group of contracts and for passing large data structures into a contract. This
contract also demonstrates the use of [pdo-shell plugins](../wawaka/kv-test/plugins/kv-test.py)
and [pdo-shell scripts](../wawaka/kv-test/scripts/kv-test.psh)
for accessing methods in the contract more easily.

- [interpreter-test](../wawaka/interpreter-test)
This contract defines methods for testing various functions available
to wawaka contracts through the native function interface including
functions for AES, RSA and ECDSA cryptography, and methods for
interacting with the contract persistent state.

- [interface-test](../wawaka/interface-test)
This contract defines methods for testing parameter passing and
contract execution environment. Methods are defined that return
errors in different forms.

- [attestation-test](../wawaka/attestation-test)
This contract is more complex. It creates a secret that can be passed
between contracts through a secure, secret channel. The contract tests
contract-to-contract attestation (that is, it verifies that the
contract that will be receiving the message is the one expected to
receive the message). You may find methods in the attestation-test
contract to be useful in your own contracts. This contract also
defines [pdo-shell plugins](../wawaka/attestation-test/plugins/attestation-test.py)
and [pdo-shell scripts](../wawaka/attestation-test/scripts/attestation-test.psh)
to simplify interaction with the contract object.

## Writing A Contract ##

### Anatomy of a Contract ###

*TO BE COMPLETED*

```C++
#include "Dispatch.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "Value.h"

// -----------------------------------------------------------------
// NAME: initialize_contract
// -----------------------------------------------------------------
bool initialize_contract(const Environment& env, Response& rsp)
{
    return rsp.success(true);
}

bool get_value(const Message& msg, const Environment& env, Response& rsp)
{
    ww::value::Number v((double)value);
    return rsp.value(v, true);
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(get_value),
    { NULL, NULL }
};
```

#### Required Methods ####

*TO BE COMPLETED*

#### Method Parameters ####

*TO BE COMPLETED*

#### Dispatch Table ####

*TO BE COMPLETED*

### Common Library ###

*TO BE COMPLETED*

Classes for defining methods:
- Environment
- Message
- Response
- StateReference


Classes helpful for writing contracts:
- Attestion
- Cryptography
- KeyValue
- Secret
- Types
- Value

Macros:
- CONTRACT\_METHOD and CONTRACT\_METHOD2
- SCHEMA\_KW and SCHEMA\_KWS

### Build Tools ###

There are many toolchains that could be used to build a WASM code. By
default, Wawaka contracts are compiled with the compilers provided by
[WASI SDK](https://github.com/WebAssembly/wasi-sdk). To use WASI SDK,
download and install the appropriate package file from
https://github.com/WebAssembly/wasi-sdk/releases (we have verified
that release wasi-sdk-12 works with WAMR version WAMR-01-18-2022).

To help you build a contract we have included two CMakefiles that
can be included in your contract's CMakefile.

- [contract-build.cmake](../wawaka/contract-build.cmake)
Macros for setting the appropriate environment variables and
source dependencies. Defines the ```BUILD_CONTRACT``` macro
for building a contract from source files.

- [wawaka-common.cmake](../wawaka/wawaka-common.cmake)
Settings to build the wawaka [common library](#Common Library). The
definitions set up the appropriate include paths and libraries for
linking wawaka contracts with the classes defined in the common
library.

These helper files can be used in your own CMakeLists.txt to build
a contract. For example, the following file would build the memory-test
contract using the wawaka common library.

```
INCLUDE($ENV{PDO_SOURCE_ROOT}/contracts/wawaka/contract-build.cmake)
INCLUDE($ENV{PDO_SOURCE_ROOT}/contracts/wawaka/wawaka_common.cmake)

LIST(APPEND WASM_LIBRARIES ${WW_COMMON_LIB})
LIST(APPEND WASM_INCLUDES ${WW_COMMON_INCLUDES})

BUILD_CONTRACT(memory-test memory-test/memory-test.cpp)
```

## Deploying A Contract ##

If you are using the build tools provided, typing `make install`
should copy the base64 encoded WASM contract into the directory
`${PDO_HOME}/contracts`. This is the default location used by the
`pdo-shell` scripts.
