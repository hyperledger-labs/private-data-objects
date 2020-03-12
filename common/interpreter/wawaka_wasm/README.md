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
always point to the latest tagged commit that we have validated: `WAMR-03-05-2020`.
If the PDO parent repo was not cloned with the `--recurse-submodules` flag,
you will have to explictly pull the submodule source.

```
cd ${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
git submodule update --init
git checkout WAMR-03-05-2020 # optional
```

The WAMR API is built during the Wawaka build, so no additional
build steps are required to set up WAMR.

### Set the environment variables ###

By default, PDO will be built with the Gipsy Scheme contract interpreter. To use the experimental wawaka interpreter, set the environment variables `WASM_SRC` (default is the submodule directory with the WAMR source) and `PDO_INTERPRETER` (the name of the contract interpreter to use.

```bash
export WASM_SRC=${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
export PDO_INTERPRETER=wawaka
```

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

## Basics of a Contract ##

Note that compilation into WASM that will run in the contract enclave can be somewhat tricky. Specifically, all symbols whether used or not must be bound. The wawaka interpreter will fail if it attempts to load WASM code with unbound symbols.
