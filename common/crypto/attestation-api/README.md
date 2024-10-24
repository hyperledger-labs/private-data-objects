# Attestation API

This library implements a single API for generating and verifying hardware-based attestation (e.g., Intel SGX EPID/DCAP attestations).
The library implementation originally started as part of the Fabric Private Chaincode project, and later spun off and extended.

The library works with Intel SGX EPID attestations, verified through Intel Attestation Service (IAS), and DCAP attestations, verified through Intel Trust Authority (ITA).

## Build

Build the docker image to create an environment with all necessaty dependencies.
```bash
cd docker
make
```

### Simulation mode
Start the dev container:
```bash
docker run -v <project root>:/project -e SGX_MODE=SIM -it oaa-dev
```

Simulation mode is the default mode. It does not use actual Intel SGX operations, and tests are conducted on simulated-type attestations.

```bash
source /opt/intel/sgxsdk/environment
mkdir build
cd build
cmake ..
make
```

### Hardware mode
Start the dev container, here is an example:
```bash
docker run --network host -v <project root>:/project -e SGX_MODE=HW -it oaa-dev
```
The container is attached to the host network to download the root certificates.
Also, enabling the HW mode makes the generated artifacts use actual Intel SGX operations -- and tests are conducted on real attestations.

DCAP support with ITA is built by default, but requires the URL to the ITA CA root certificates (in JWK format). If the URL is not specified, the build will succeed but it won't be able to verify DCAP attestations.
```bash
export ITA_ROOT_CACERT_URL=<certificate url>
```

EPID support and DCAP support for direct verificaiton (without ITA) are built by default, and require an internet connection to download the Intel CA root certificates.

```bash
source /opt/intel/sgxsdk/environment
mkdir build
cd build
cmake ..
make
```

#### Collateral (for usage and testing)
Using (or testing) SGX attestation requires some collateral. The folder to such collateral must be provided as:
```bash
export COLLATERAL_FOLDER=<path to the folder>
```

EPID collateral files:
* `spid_type.txt`, a text file containing the SPID type ("epid-linkable" or "epid-unlinkable")
* `spid.txt`, a text file containing the SPID (a 32-byte long hex string)
* `api_key.txt`, a text file containing the API key to use IAS (a 32-byte long hex string)

DCAP collateral files:
* `ita_api_key.txt`, a text file containing the API key to use ITA
* `attestation_type.txt`, a text file containing the attestation type ("dcap-sgx")


#### Testing

To run the tests in HW mode, the collateral (see above) and the SGX devices are necessary.
Assuming a default system configuration, you may want to start the dev docker image as follows:
```bash
docker run --network host --device /dev/sgx_enclave:/dev/sgx_enclave --device /dev/sgx_provision:/dev/sgx_provision -v /var/run/aesmd:/var/run/aesmd -v <project root>:/project -v <local collateral folder>:/collateral -e SGX_MODE=HW -e COLLATERAL_FOLDER=/collateral -it oaa-dev
```

To test everything (simulated attestations in SIM mode, and all supported attestations in HW mode for platforms that support both EPID and DCAP):
```bash
make test
```

To test everything except DCAP with ITA:
```bash
SKIP_TEST_DCAP= make test
```

To test everything except DCAP with direct verification:
```bash
SKIP_TEST_DCAP_DIRECT= make test
```
For SGX platform that do not support DCAP or FLC, both DCAP tests must be disabled.


To test everything except EPID (for SGX platforms that do not support EPID):
```bash
SKIP_TEST_EPID= make test
```

If tests fail, you may want to output some logs with:
```bash
env CTEST_OUTPUT_ON_FAILURE=1 make test
```
