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
  * [`PDO_LEDGER_TYPE`](#pdo_ledger_type) -- the ledger type to be used (ccf)
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
   export PDO_LEDGER_URL=http://127.0.0.1:6600
```
and before building it you call the configuration script as

```bash
   source ${PDO_SOURCE_ROOT}/build/common-config.sh
```

If passed the parameter `--evalable-export` the script will return a
list of export commands of the variables instead of directly exporting
them to the environment.

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
(default: `wawaka`):

`PDO_INTERPRETER` contains the name of the interpreter to use for
processing contracts. `wawaka` is the default interpreter that
executes WASM-based contracts. `wawaka-opt` enables optimizations
in Wawaka's WASM interpreter.
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
(default: 1)

`PDO_DEBUG_BUILD` builds PDO modules for debugging. This includes
compile flags, logging statements in the enclave, etc. Since
`PDO_DEBUG_BUILD` potentially exposes information about what is
happening inside a contract, do not use with confidential contracts.

<!-- -------------------------------------------------- -->
### `WASM_SRC`
(default: `${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime`)

`WASM_SRC` points to the installation of the wasm-micro-runtime. This
is used to build the WASM interpreter for the wawaka contract interpreter.
The git submodule points to the latest tagged commit of [WAMR](https://github.com/bytecodealliance/wasm-micro-runtime) we have validated:
`WAMR-1.1.2`.

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
are stored. If SGX_MODE=SIM, the default folder contains mock files that
are good for simulation mode. If SGX_MODE=HW, the default (or custom)
folder must be filled with legitimate SGX & IAS keys.
See [SGX section](install.md#SGX) of the [BUILD document](install.md)
for more information.

<!-- -------------------------------------------------- -->
## Ledger Environment Variables

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_TYPE`
(default: `ccf`):

`PDO_LEDGER_TYPE` is the ledger to be used with PDO.
PDO supports ccf (Microsoft) based ledgers.

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_URL`
(default: `http://127.0.0.1:6600/`):

`PDO_LEDGER_URL` is the URL used to submit transactions to the
ledger. This should be the URL for the REST API component.

<!-- -------------------------------------------------- -->
### `PDO_LEDGER_KEY_ROOT`
(default: `${PDO_INSTALL_ROOT}/opt/pdo/etc/keys/ledger`):

`PDO_LEDGER_KEY_ROOT` is the root directory where the system keys are
stored for ledger integration; files in this directory are not
automatically generated.

<!-- -------------------------------------------------- -->
