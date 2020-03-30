# Wawaka Benchmarks

The contracts in this directory are designed for benchmarking the performance
of the [wawaka interpreter](https://github.com/hyperledger-labs/private-data-objects/tree/master/common/interpreter/wawaka_wasm).

- `fibonacci`: recursive workload (and common benchmark for WASM runtimes)
- `sha256`: CPU-intensive operation on variable input sizes (based on [TinyCrypt](https://github.com/intel/tinycrypt))

## Running the benchmarks

The `pdo-test-contract` CLI tool automatically recognizes JSON expressions
that include benchmarking configurations:
- `"benchmark": <true/false>`
- `"iterations" : <number of iterations>`
- `"benchName": <output file name>`
