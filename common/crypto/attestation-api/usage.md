The attestation library is available under the [attestation-dev branch](https://github.com/hyperledger-labs/private-data-objects/tree/attestation-dev).

The library is divided in 3 main components:
1. attestation generation, inside the enclave
2. attestation conversion to evidence, outside of the enclave
3. evidence verification, inside or outside of the enclave

![image](https://github.com/user-attachments/assets/d3042b3a-37dd-4966-9c8a-9561e93f6174)

The figure depicts the flows for attestation generation, conversion and verification.
For additional technical details look at the `test/attested_evidence_test.sh` script in the library.
Also, for additional details about the APIs look at the headers in the `include` folder.

**Attestation generation.**
The library exposes the `init_attestation(params)` and `attestation_blob = get_attestation(statement)` APIs.
`params` is a json blob to initialize the internal state of the library for an attestation. The `statement` is a binary string which (in SGX) is hashed to generate the "report data" to be attested.
```jsonc
// params json blob
{
  "attestation_type": "<simulated, epid-linkable, epid-unlinkable, dcap-sgx, dcap-direct-sgx>",
  "hex_spid": "<hex encoded spid>", // only for EPID
  "sig_rl": "<sigrl>" // only for EPID
}
```
`attestation` is a json blob containing the remote attestation. So notice that, for EPID and DCAP, the trusted attestation library has ocalls in untrusted space to get the remote attestation from the Intel Quoting Enclave.
```jsonc
// attestation json blob
{
  "attestation_type": "<see above>",
  "attestation": "<base64-encoded quote>"
}
```

**Attestation conversion.**
The library provides a script for converting the attestation into evidence: `evidence_blob = attestation_to_evidence(attestation_blob)`. Additional sub-scripts perform the conversion based on the attestation type. For the `simulated` type, it simply copies the attestation fields into the evidence field. For EPID, the script contacts the Intel Attestation Service (IAS) for verification -- an API key is required in the collateral folder. For `dcap-sgx`, the script contacts the Intel Trust Authority (ITA) for verification through the provided url -- an API key is required in the collateral folder. For `dcap-direct-sgx`, the script uses the DCAP library to retrieve the collateral from the Intel Provisioning Certification Service (PCS) or the Intel Provisioning Certificate Caching Service (PCCS), depending on the configuration in `/etc/sgx_default_qcnl.conf`. Here, no third-party verification is performed -- the verification fully happens in the last step.
```jsonc
// evidence json blob
{
  "attestation_type": "<see above>",
  "evidence":
  {
    "ias_report": "<>", // only for EPID
    "ias_certificates": "<>", // only for EPID
    "ias_signature": "<>", // only for EPID
    "collateral": "<as received from Intel PCS/PCCS>", // only for DCAP
    "untrusted-time-t": "<current time to be used for certificate verification>" // only EPID/DCAP
}
```

**Attestation verification.**
The attestation library exposes the `verify_evidence(evidence_blob, statement, code_id)` API. In SGX, the code identity refers to the `mrenclave` value. The verification result is simply `true` or `false`, depending on the outcome. The API mainly verifies: the chain of trust of the evidence (i.e., none for the `simulated` type; up to the IAS root CA for EPID; up to the SGX Root CA for the `dcap-direct-sgx` type; up to the ITA root CA for the `dcap-sgx` type. The respective root CA certificates are all retrieved at build time and compiled into the library.

