The attestation API makes use of the jwt-cpp module.
The module must be patched to work in SGX.
The [patch](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/dcap_1.22_reproducible/external/0001-Add-a-macro-to-disable-time-support-in-jwt-for-SGX.patch) was borrowed directly from the DCAP primitives and integrated in the cmake build process.
