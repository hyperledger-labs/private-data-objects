<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Private Data Objects Environment Variables

Instructions in this document assume the environment variable
`PDO_SOURCE_ROOT` points to the PDO source directory.

PDO uses a number of environment variables to control build,
installation and operation. While PDO should build and run with only the
default values, four variables are commonly set to reflect specifics of
the installation:

  * [`PDO_INSTALL_ROOT`](#pdo_install_root) -- the path to the directory where PDO is installed
  * [`PDO_LEDGER_TYPE`](#pdo_ledger_type) -- the ledger type to be used (sawtooth or ccf)
  * [`PDO_LEDGER_URL`](#pdo_ledger_url) -- the URL for the ledger
  * [`PDO_LEDGER_KEY_ROOT`](#pdo_ledger_key_root) -- the path to a directory containing ledger keys


In addition, if you run in SGX HW mode you will generally define
`PDO_SGX_KEY_ROOT` as well. See below for information on these variables
and others you could override from defaults.

<!-- -------------------------------------------------- -->
<!-- -------------------------------------------------- -->
## Common Configuration Script

The script
[build/common-config.sh](../build/common-config.sh)
can be used to set values for all of the environment variables that are
used in the build, installation & execution process.

The default usage of this script is to be sourced. For example, local
configuration file may be constructed as:

```bash
   export PDO_INSTALL_ROOT=${PDO_SOURCE_ROOT}/build/_dev
   export PDO_LEDGER_KEY_ROOT=${PDO_INSTALL_ROOT}/opt/pdo/etc/keys/ledger
   export PDO_LEDGER_URL=http://127.0.0.1:8008
```
and before building it you call the configuration script as

```bash
   source ${PDO_SOURCE_ROOT}/build/common-config.sh
```

If passed the parameter `--evalable-export` the script will return a
list of export commands of the variables instead of directly exporting
them to the environment.

Passing parameter `--reset-keys` will unset key variables
`PDO_ENCLAVE_CODE_SIGN_PEM`, `PDO_LEDGER_KEY_SKF`,
`PDO_SPID` and `PDO_SPID_API_KEY` before setting variables.

<!-- -------------------------------------------------- -->
<!-- -------------------------------------------------- -->
## Generic Environment Variables

<!-- -------------------------------------------------- -->
### `PDO_INSTALL_ROOT`
(default: `${PDO_SOURCE_ROOT}/build/_dev`):

`PDO_INSTALL_ROOT` is the root of the directory in which the virtual
enviroment will be built; generally `PDO_HOME` will point to
`PDO_INSTALL_ROOT/opt/pdo`

<!-- -------------------------------------------------- -->
### `PDO_INTERPRETER`
(default: `gipsy`):

`PDO_INTERPRETER` contains the name of the interpreter to use for
processing contracts. `gipsy` is the default and is the Scheme-based,
functional language. `wawaka` is an experimental interpreter that
executes WASM-based contracts. `wawaka-opt` enables optimizations
in Wawaka's WASM interpreter. `wawaka-aot` is a version of Wawaka that
executes ahead-of-time compiled WASM contracts.
For more information on the configuration
and use of `wawaka`, see the interpreter
[README](../common/interpreter/wawaka/README.md).

<!-- -------------------------------------------------- -->
### `PDO_HOME`
(default: `${PDO_INSTALL_ROOT}/opt/pdo`):

`PDO_HOME` is the directory where PDO-specific files are stored for
operation. These files include configuration files, data files, compiled
contracts, contract user keys and service scripts.

<!-- -------------------------------------------------- -->
### `PDO_HOSTNAME`
(default: `${HOSTNAME}`):

`PDO_HOSTNAME` identifies the hostname where service interfaces
will be exported. Defaults to HOSTNAME.

<!-- -------------------------------------------------- -->
### `PDO_DEBUG_BUILD`
(default: 0)

`PDO_DEBUG_BUILD` builds PDO modules for debugging. This includes
compile flags, logging statements in the enclave, etc. Since
`PDO_DEBUG_BUILD` potentially exposes information about what is
happening inside a contract, do not use with confidential contracts.

<!-- -------------------------------------------------- -->
### `TINY_SCHEME_SRC`
(default: `${PDO_SOURCE_ROOT}/tinyscheme-1.41`)

`TINY_SCHEME_SRC` points to the installation of the tinyscheme source in
order to build the library used to debug and test contracts outside of
the contract enclave.

<!-- -------------------------------------------------- -->
### `WASM_SRC`
(default: `${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime`)

`WASM_SRC` points to the installation of the wasm-micro-runtime. This
is used to build the WASM interpreter for the wawaka contract interpreter.
The git submodule points to the latest tagged commit of [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) we have validated:
`WAMR-09-29-2020`.

<!-- -------------------------------------------------- -->
### `WASM_MEM_CONFIG`
(default: `MEDIUM`)

`WASM_MEM_CONFIG` indicates the memory configuration for the
WASM runtime: the runtime's global memory pool size,
the WASM module's heap size, and the size of module's
operand stack.
When the variable is set to `SMALL`, the runtime's global memory
pool size is set to 1MB.
If the variable is set to `MEDIUM`, the runtime's memory pool
size is set to 2MB.
When the variable is set to `LARGE`, the runtime's memory
pool size is set to 4MB.

<!-- -------------------------------------------------- -->
<!-- -------------------------------------------------- -->
## SGX Environment Variables

<!-- -------------------------------------------------- -->
### `SGX_MODE`
(default: `SIM`)

`SGX_MODE` determines the SGX mode of operation. When the variable is
set to `SIM`, then the SGX enclaves will be compiled for simulator
mode. When the variable is set to `HW`, the enclaves will be compiled to
run in a real SGX enclave.

<!-- -------------------------------------------------- -->
### `PDO_SGX_KEY_ROOT`
(default: `${PDO_SOURCE_ROOT}/build/keys/sgx_mode_${SGX_MODE,,}/`):

`PDO_SGX_KEY_ROOT` is the root directory where SGX and IAS related keys
are stored. The default points to a directory which contains values
which are good enough for SGX simulator mode. However, for SGX HW mode
you should provide your own version, at least for `PDO_SPID` and
`PDO_SPID_API_KEY`. See [SGX section](install.md#SGX) of the
[BUILD document](install.md) for more information.

<!-- -------------------------------------------------- -->
### `PDO_ENCLAVE_CODE_SIGN_PEM`
(default: `${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem`):

`PDO_ENCLAVE_CODE_SIGN_PEM` contains the name of the file containing the
key used to sign the enclave. If you wish to use PDO for production,
this key must be white-listed with IAS.  For development, testing, and
other non-production uses, whether in simulator or hardware mode, the
key can generated by the command:

```bash
    openssl genrsa -3 -out ${PDO_ENCLAVE_CODE_SIGN_PEM} 3072.
```

The default path points to a key which is automatically generated during
the build.

<!-- -------------------------------------------------- -->
### `PDO_SPID`
(default: `DEADBEEF00000000DEADBEEF00000000`)

`PDO_SPID` is the ID that accompanies the certificate registered with
the Intel Attestation Service. This should be a 32 character hex
string. If the variable is unset, the configuration script
`common-config.sh` will pull the value from the file
`${PDO_SGX_KEY_ROOT}/sgx_spid.txt`.

The default value will work for SGX simulation mode. See
[SGX section](install.md#SGX) of the [BUILD document](install.md) for
instructions to create the SPID to support SGX hardware mode.

<!-- -------------------------------------------------- -->
### `PDO_SPID_API_KEY`
(default `deadbeef00000000deadbeef00000000`)

`PDO_SPID_API_KEY` is the key used to authenticate IAS client
requests. This should be a 32 character hex string.
If the variable is unset, the configuration script
`common-config.sh` will pull the value from the file
`${PDO_SGX_KEY_ROOT}/sgx_spid_api_key.txt`.

The default value will work for SGX simulation mode. See
[SGX section](install.md#SGX) of the [BUILD document](install.md) for
instructions to create the API key to support SGX hardware mode.

<!-- -------------------------------------------------- -->
<!-- -------------------------------------------------- -->
## Ledger Environment Variables

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_TYPE`
(default: `sawtooth`):

`PDO_LEDGER_TYPE` is the ledger to be used with PDO.
PDO supports sawtooth and ccf (Microsoft) based ledgers.

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_URL`
(default: `http://127.0.0.1:8008/`):

`PDO_LEDGER_URL` is the URL used to submit transactions to the
ledger. This should be the URL for the REST API component.

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_KEY_ROOT`
(default: `${PDO_INSTALL_ROOT}/opt/pdo/etc/keys/ledger`):

`PDO_LEDGER_KEY_ROOT` is the root directory where the system keys are
stored for ledger integration; files in this directory are not
automatically generated.

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_KEY_SKF`
(default: `${PDO_LEDGER_KEY_ROOT/pdo_validator.priv`)

`PDO_LEDGER_KEY_SKF` is used to update settings in the Sawtooth
validator. This is the key used by the Sawtooth ledger and is generally
found in the file `.sawtooth/keys/ledger.priv` in the Sawtooth
installation directory hiearchy.
