<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

**NOTE: THIS IS A RESEARCH PROTOTYPE, IT IS NOT INTENDED FOR PRODUCTION USAGE**

# The Wawaka Contract Interpreter #

The Wawaka contract interpreter processes contracts for private data
objects based on the
[WebAssembly Micro Runtime](https://github.com/intel/wasm-micro-runtime)
developed by Intel (WAMR). WAMR implements a small WebAssembly VM and a
set of supporting functions that can be executed inside the contract
enclave. As such contracts can be implemented in any programming
language that can be compiled into WASM.

## Building Wawaka ##

The Wawaka interpreter is not built by default. To build a contract
enclave with Wawaka enabled, you will need to do the following:

  * Install and configure [emscripten](https://emscripten.org/)
  * Pull the WAMR submodule (if the repo was not cloned with the `--recurse-submodules` flag)
  * Set the `PDO_INTERPRETER` environment variable to `wawaka`

### Install emscripten ###

There are many toolchains that could be used to build a WASM code. We have tested (and our sample
and test contracts use) [emscripten](https://emscripten.org/). Note that we currently require the `fastcomp` compiler which is no longer the default compiler.

```bash
cd ${PDO_SOURCE_ROOT}

git clone https://github.com/emscripten-core/emsdk.git
cd ${PDO_SOURCE_ROOT}/emsdk

./emsdk install latest-fastcomp
./emsdk activate latest-fastcomp

source ./emsdk_env.sh
```

### WAMR setup ###

If wawaka is configured as the contract interpreter, the libraries implementing the WASM interpreter
will be built for use with Intel SGX. The source for the WAMR interpreter is
included as a submodule in the interpreters/ folder, and will
always point to the latest tagged commit that we have validated: `WAMR-03-30-2020`.
If the PDO parent repo was not cloned with the `--recurse-submodules` flag,
you will have to explictly pull the submodule source.

```
cd ${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
git submodule update --init
git checkout WAMR-03-30-2020 # optional
```

The WAMR API is built during the Wawaka build, so no additional
build steps are required to set up WAMR.

### Set the environment variables ###

By default, PDO will be built with the Gipsy Scheme contract interpreter. To use the experimental wawaka interpreter, set the environment variables `WASM_SRC` (default is the submodule directory with the WAMR source), `PDO_INTERPRETER` (the name of the contract interpreter to use), and `WASM_MODE` (the
execution mode of the wawaka WASM runtime).

```bash
export WASM_SRC=${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
export PDO_INTERPRETER=wawaka
export WASM_MODE=INTERP
```

PDO supports two WAMR interpreter modes: classic
interpreter and optimized interpreter (more details at
[WAMR documentation](https://github.com/bytecodealliance/wasm-micro-runtime/blob/master/doc/build_wamr.md#configure-interpreter)).
By default, PDO builds the classic interpreter. To enable the
optimized interpreter, set the `WASM_MODE` environment variable
to `INTERP_OPT`.

### Build PDO ###

Note that any change to the contract interpreter requires PDO to be completely rebuilt.

```bash
cd ${PDO_SOURCE_ROOT}/build
make rebuild
```

### Test the Configuration ###

Sample wawaka contracts are built and installed along with the
interpreter. You can run the simple test contract as follows:

```bash
cd ${PDO_SOURCE_ROOT}/contracts/wawaka
pdo-test-contract --no-ledger --interpreter wawaka --contract mock-contract \
    --expressions ./mock-contract/test-long.exp --loglevel info
```

## Ahead-of-Time Compiled WASM
** Disclaimer: Support for this feature is under active development and will be rolled-out at a later date. AoT mode cannot currently be enabled for testing. **

### Setup

By default, wawaka will be built for interpreted wasm contracts.
If you would like to enable
ahead-of-time (AoT) compiled wasm contracts, set the environment variable `WASM_MODE` (default: `INTERP`):

```bash
export WASM_MODE=AOT
```

With AoT wasm enabled, the `wamrc` compiler (including dependencies)
shipped as part of the WAMR codebase will be built
as part of the PDO build.

### Building and running wawaka Contracts

We provide a new cmake function `BUILD_AOT_CONTRACT` that
automatically invokes `wamrc` on a given wasm bytecode file,
and generates the corresponding `.aot` binary file. 
To build an AoT-compiled wawaka contract, add the following call to the contract's
`CMakeList.txt`:

```
BUILD_AOT_CONTRACT(<contract name> <contract source list>)
```

Running an AoT-compiled wawaka contract requires no additional steps,
as the WAMR runtime transparently detects the input wasm code's format.

## Basics of a Contract ##

Note that compilation into WASM that will run in the contract enclave can be somewhat tricky. Specifically, all symbols whether used or not must be bound. The wawaka interpreter will fail if it attempts to load WASM code with unbound symbols.
