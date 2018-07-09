<!--- -*- mode: markdown; fill-column: 80 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

## Enclave-signing key ##
This is a key used by the Enclave Service to sign a contract enaclave.
As for the requirements of the SGX SDK (v2.1), this must be an
3072-bit RSA key with public exponent 3. For testing purposes,
this can be generated with the following command:
``openssl genrsa -3 -out private_rsa_key.pem 3072``

## Requirements for Attestation ##
In the configuration directory (specified at initialization time),
it is necessary to include a configuration file for the SGX Enclave Attestation
and a certificate.

### Certificate ###
This is a PEM file which
* the user generates ([here](https://software.intel.com/en-us/articles/certificate-requirements-for-intel-attestation-services));
* includes the BEGIN/END CERTIFICATE and BEGIN/END PRIVATE KEY fields;
* has the certificate part registered with the Intel Attestation Service.

### Configuration file ###
This file include 4 string fields:
* spid - the service provider ID obtained from Intel after registering the certificate above
 ([here](https://software.intel.com/en-us/form/sgx-onboarding));
* spid_cert_file - the PEM file of the certificate above
* ias_url - the url of the Intel Attestation Service
* http_proxy - a parameter to specify a proxy (if any) or '' otherwise

### (optional) BIOS update ###
If the TCB of the platform performing the attestation is outdated, the
Intel Attestation Service can successfully verify an attestation though answering
with a `GROUP_OUT_OF_DATE` quote status. It is up to the verifier to decide whether to
trust an attestation from a platform whose TCB has been identified as outdated
(but not compromised).
The TCB can be updated through a BIOS update. For example, if you are running PDOs on
Intel NUCs, you can visit the [Intel Download Center](https://downloadcenter.intel.com/)
(and select `Mini PCs`) to find the latest BIOS release.
As long as the latest version is being used, the IAS will answer (to correct attestations)
with an `OK` quote status.
