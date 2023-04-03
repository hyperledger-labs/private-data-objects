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

## Build Wawaka ##

The Wawaka interpreter is not built by default. To build a contract
enclave with Wawaka enabled, you will need to do the following:

  * Install and configure the WASM development toolchain
  * Pull the WAMR submodule (if the repo was not cloned with the `--recurse-submodules` flag)
  * Set the `PDO_INTERPRETER` environment variable to `wawaka`

### Install WASM Development Toolchain ###

There are many toolchains that could be used to build a WASM code. By default, Wawaka contracts are
compiled with the compilers provided by [WASI SDK](https://github.com/WebAssembly/wasi-sdk). To use
WASI SDK, download and install the appropriate package file from
https://github.com/WebAssembly/wasi-sdk/releases (we have verified that release wasi-sdk-12 works
with WAMR version WAMR-1.1.2).

```bash
wget -q -P /tmp https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sdk_12.0_amd64.deb
sudo dpkg --install /tmp/wasi-sdk_12.0_amd64.deb
```

These directions assume that the SDK will be installed in the PDO source tree. Typically, the WASI
SDK would be installed in the directory `/opt/wasi-sdk`.

### Set Up WAMR ###

If wawaka is configured as the contract interpreter, the libraries implementing the WASM interpreter
will be built for use with Intel SGX. The source for the WAMR interpreter is
included as a submodule in the interpreters/ folder, and will
always point to the latest tagged commit that we have validated: `WAMR-1.1.2`.
If the PDO parent repo was not cloned with the `--recurse-submodules` flag,
you will have to explictly pull the submodule source.

```
cd ${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
git submodule update --init
git checkout WAMR-1.1.2 # optional
```

The WAMR API is built during the Wawaka build, so no additional
build steps are required to set up WAMR.

#### Select the Interpreter ####

PDO supports two WAMR interpreter modes: classic interpreter and optimized interpreter
(more details at [WAMR documentation]
(https://github.com/bytecodealliance/wasm-micro-runtime/blob/master/doc/build_wamr.md#configure-interpreter)).
By default, PDO builds the classic interpreter. To enable the optimized interpreter, set the
following environment variable:

```bash
export PDO_INTERPRETER=wawaka-opt
```

#### Configure the Interpreter ####

Wawaka has three memory configuration parameters that can
be adjusted depending on the requirements for a WASM contract:
- `RUNTIME_MEM_POOL_SIZE`: The WASM runtime's global memory pool size.
- `STACK_SIZE`: Size of the runtime's operand stack for executing the contract.
- `HEAP_SIZE`: Size of the heap for dynamic allocations by the contract.

To facilitate configuring wawaka's memory, we provide
three pre-defined memory configurations that meet most
contract requirements:
- `SMALL`: 1MB WASM runtime memory pool (64KB stack, 768KB heap)
- `MEDIUM`: 2MB WASM runtime memory pool (256KB stack, 1.5MB heap)
- `LARGE`: 4MB WASM runtime memory pool (512KB stack, 3MB heap)

To use a specific memory configuration, set
the environment variable `WASM_MEM_CONFIG` (the default is the `MEDIUM`
configuration) to build the wawaka interpreter with those memory
settings:

```bash
export WASM_MEM_CONFIG=MEDIUM
```

Here are some tips for choosing the right wawaka memory configuration
for your contract:
- How many global variables does your contract use?
- How deep is your call graph?
- How many dynamic allocations do you expect your contract to make?

As a general rule, a contract's globals and
[linear memory](https://webassembly.org/docs/semantics/#linear-memory)
need to fit into the runtime's memory pool along with
the stack and heap.

### Set Environment Variables ###

To use the wawaka interpreter, set the environment variables `WASM_SRC` (default is the submodule
directory with the WAMR source) and `PDO_INTERPRETER` (the name of the contract interpreter to use).

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

You may also want to run the full wawaka test suite:
```bash
cd ${PDO_SOURCE_ROOT}/build
make test
```

### Benchmarking wawaka

PDO now provides a small benchmarking suite for wawaka. The contracts
are located under `contracts/wawaka/benchmarks` and test different
workloads. To build the benchmarking contracts, and run the provided
benchmarking suite under the current wawaka configuration, run:

```bash
cd ${PDO_SOURCE_ROOT}/build
make benchmark
```

Go to [contracts/wawaka/benchmarks](../../../contracts/wawaka/benchmarks/README.md), for more details.

## Basics of a Contract ##

Note that compilation into WASM that will run in the contract enclave can be somewhat tricky. Specifically, all symbols whether used or not must be bound. The wawaka interpreter will fail if it attempts to load WASM code with unbound symbols.
