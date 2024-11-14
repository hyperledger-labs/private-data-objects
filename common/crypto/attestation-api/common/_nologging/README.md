This package provides the `LOG_*` defines inside and outside of the enclave for logging purposes.
Inside the enclave, the package disables logging, i.e., no enclave-edge APIs are produced
and all function calls are empty.
Outside of the enclave, the package uses the standard I/O library.
