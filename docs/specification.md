<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# SPECIFICATION

This page provides and index to the documentation for each of the PDO
components.

# CCF & Transaction Processors

General information about how the ccf transaction processors work
can be found [here](../ccf_transaction_processor/README.md).

# Common library

Information about cryptography components of the project implemented in the
common library can be found [here](../common/docs/crypto.md).

# Enclave service

More information about how the enclave service works can be found
[here](../eservice/docs/eservice.md).

### Code Deployment Integrity

*** Disclaimer: This is an experimental feature. Not ready for production use!! ***

The origins of contracts, especially those built by remote
toolchains, may be difficult to trace. Our Code Deployment
Integrity (CDI) framework, enables PDO enclave hosting services
(eservice) to specify various levels of trust relationships
with contract build toolchains,
and establish trust in contracts at run-time based on their policy.

For normal CDI policies, CDI-aware toolchains digitally sign
the emitted contract code to authenticate the toolchain. For
strict CDO policies, toolchains may generate a signed cryptographic
proof binding the input to the emitted contract code.
Only if the eservice can validate the provenance and integrity
of the contract it receives, does it execute the contract.
