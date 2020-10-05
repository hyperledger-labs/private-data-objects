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
git checkout 1.39.20 # last release to support fastcomp backend

./emsdk install latest-fastcomp
./emsdk activate latest-fastcomp

source ./emsdk_env.sh
```

### WAMR setup ###

If wawaka is configured as the contract interpreter, the libraries implementing the WASM interpreter
will be built for use with Intel SGX. The source for the WAMR interpreter is
included as a submodule in the interpreters/ folder, and will
always point to the latest tagged commit that we have validated: `WAMR-09-29-2020`.
If the PDO parent repo was not cloned with the `--recurse-submodules` flag,
you will have to explictly pull the submodule source.

```
cd ${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
git submodule update --init
git checkout WAMR-09-29-2020 # optional
```

The WAMR API is built during the Wawaka build, so no additional
build steps are required to set up WAMR.

### Set the environment variables ###

By default, PDO will be built with the Gipsy Scheme contract interpreter. To use the experimental wawaka interpreter, set the environment variables `WASM_SRC` (default is the submodule directory with the WAMR source), `PDO_INTERPRETER` (the name of the contract interpreter to use).

```bash
export WASM_SRC=${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
export PDO_INTERPRETER=wawaka
```

**Optimized Interpreter**

PDO supports two WAMR interpreter modes: classic
interpreter and optimized interpreter (more details at
[WAMR documentation](https://github.com/bytecodealliance/wasm-micro-runtime/blob/master/doc/build_wamr.md#configure-interpreter)).
By default, PDO builds the classic interpreter. To enable the
optimized interpreter, set the following environment variable:

```bash
export PDO_INTERPRETER=wawaka-opt
```

### Memory configuration ###

Wawaka has three memory configuration parameters that can
be adjusted depending on the requirements for a WASM contract:
- `RUNTIME_MEM_POOL_SIZE`: The WASM runtime's global memory pool size.
- `STACK_SIZE`: Size of the runtime's operand stack for executing
the contract.
- `HEAP_SIZE`: Size of the heap for dynamic allocations
by the contract.

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

You may also need to specify additional _contract-specific_
memory settings at compile time to ensure that wawaka has sufficient
memory to execute your contract. Please refer to
the emscripten [documentation](https://emscripten.org/docs/tools_reference/emcc.html) for setting the appropriate
options for your contract.

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

## AoT-Compiled WASM

Running ahead-of-time compiled WASM modules
can significantly improve the performance of PDO contracts
to near-native speeds. In internal benchmarks, we measured
up to a 29x execution time speedup over interpreted WASM
for some compute-intensive workloads when compiled ahead of
time.

By default, wawaka will be built for interpreted wasm contracts.
To enable ahead-of-time (AoT) compiled WASM contracts, set the
environment variable `PDO_INTERPRETER`:

```bash
export PDO_INTERPRETER=wawaka-aot
```

### AoT compiler setup

To download the LLVM dependencies, run:

```bash
LLVM_VERSION=10.0.0
LLVM_REPO=https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)
LLVM_TAR=clang+llvm-$(LLVM_VERSION)-x86_64-linux-gnu-ubuntu-18.04
LLVM_BIN=$(WASM_SRC)/core/deps/llvm/build/llvm/bin/llvm-lto # proxy for llvm dependency

cd $(WASM_SRC)/core/deps && mkdir -p llvm/build/
wget -q $(LLVM_REPO)/$(LLVM_TAR).tar.xz
tar -xf $(LLVM_TAR).tar.xz -C llvm/build/
cd llvm/build/ && mv $(LLVM_TAR) llvm
```

The following steps then build the `wamrc` AoT compiler that
is shipped with WAMR:

```bash
cd $(WASM_SRC)/wamr-compiler
mkdir -p build
cd build
cmake .. && make
```

### CDI setup

To build the experimental `gen-cdi-report` tool, run:

```bash
cd ${PDO_SOURCE_ROOT}/contracts/cdi
mkdir -p build
cd build
cmake .. && make
```

Next, to generate a set of ECDSA signing keys used when calling
`gen-cdi-report`, run:

```bash
openssl ecparam -name secp256k1 -genkey -noout -out cdi_compiler1_private.pem
openssl ec -in cdi_compiler1_private.pem -pubout -out cdi_compiler1_public.pem
```
They key pair is placed in `${PDO_INSTALL_ROOT}/opt/pdo/keys`.
All `cdi_compiler{i}_public.pem` keys in this directory are
automatically added to the PDO enclave service configuration
(see `${PDO_INSTALL_ROOT}/opt/pdo/etc/template/enclave.toml`).

### Building AoT Contracts

To build an AoT contract for wawaka, run:

```bash
cd ${WASM_SRC}/wamr-compiler/build/
./wamrc -sgx --format=aot -o <contract code file> <contract bytecode file>
```

For more options to run `wamrc`, see the
[documentation](https://github.com/bytecodealliance/wasm-micro-runtime/blob/main/doc/build_wasm_app.md#compile-wasm-to-aot-module).

To generate an integrity proof for a contract to use
the experimental CDI feature, run:

```bash
cd ${PDO_SOURCE_ROOT}/contracts/cdi/build/
./gen-cdi-report -c <contract code file> -k <CDI signing key file> -o <CDI report file>
```

## Basics of a Contract ##

Note that compilation into WASM that will run in the contract enclave can be somewhat tricky. Specifically, all symbols whether used or not must be bound. The wawaka interpreter will fail if it attempts to load WASM code with unbound symbols.
