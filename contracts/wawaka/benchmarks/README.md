# Wawaka Benchmarks

The contracts in this directory are designed for benchmarking the performance
of the [wawaka interpreter](https://github.com/hyperledger-labs/private-data-objects/tree/master/common/interpreter/wawaka_wasm).

- `fibonacci`: recursive workload (and common benchmark for WASM runtimes)

## Running the benchmarks

The `pdo-test-contract` CLI tool automatically recognizes JSON expressions
that include benchmarking configurations:
- `"benchmark": <true/false>`
- `"iterations" : <number of iterations>`
- `"benchName": <output file name>`

The entire benchmark suite for the currently built wawaka configuration can
be run via `make benchmark` from within the top-level `build/` directory,
or each individual benchmark can be run as such:
```bash
pdo-test-contract --no-ledger \
                  --contract contracts/wawaka/benchmarks/<test contract> \
                  --expressions build/benchmarks/wawaka/<test contract>.json \
                  --logfile __screen__ --loglevel info
```

The benchmark results for all iterations are written to the file `benchName-${PDO_INTERPRETER}-bench.txt` under the `contracts/wawaka/benchmarks/data/` directory.
