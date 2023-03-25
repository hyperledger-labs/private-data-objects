<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Using Private Data Objects

This document describes what to do with your Hyperledger Private Data Objects
project once you have followed the steps in the
[installation guide](install.md).

The easiest way to test the basic functionality is to follow the
instructions in the [docker guide](../docker/README.md). This document
contains information about running the various services outside the
containers.

## Table of Contents

- [Configure the Installation](#configure)
- [Start the Ledger](#ledger)
- [Validate the Installation](#validating)
- [Run Services](#services)
- [Develop Contracts](../contracts/docs/contracts.md)
- [Work with Objects](../client/docs/USAGE.md)

# <a name="configure">Configure the Installation

The [environment guide](environment.md) describes various environment
variables used mainly to build and install PDO. Configuration of the
various applications that are part of the project generally combine
environment variables (that describe the installation), a configuration
file, and command line switches.

Configuration files are located by default in the directory
`${PDO_HOME}/etc`. The four primary applications each use their own
configuration file:

| Application | Description  | Configuration File  |
|:--|:--|:--|
| `eservice` | contract enclave service | [`eservice.toml`](../build/opt/pdo/templates/eservice.toml) |
| `pservice` | contract provisioning service | [`pservice.toml`](../build/opt/pdo/templates/pservice.toml) |
| `sservice` | state storage service associated with an enclave service | [`sservice.toml`](../build/opt/pdo/templates/sservice.toml) |
| `pdo-shell` | the PDO client shell for creating contracts and invoking methods | [`pcontract.toml`](../build/opt/pdo/templates/pcontract.toml) |

For simplicity in installation, the file `enclave.toml` in the
`${PDO_HOME}/etc` directory contains the configuration for the accessing
the Intel Attestation Service.

In addition, most provided `pdo-shell` scripts use the service
configuration information found in
[`${PDO_HOME}/etc/site.psh`](../build/opt/pdo/templates/site.psh).
That can be included in scripts to load and configure a database of
enclave, provisioning and storage services. This will simplify script
execution. Add or change service references as necessary.

Default versions of the configuration files are constructed during the
build process. The default setup provides configuration files for five
different service instances plus the `pdo-shell` client configuration.

# <a name="ledger">Start the Ledger

Using PDO requires a running instance of a ledger. Documentation for
building, installing and running [Microsoft CCF](../ccf_transaction_processor/README.md)
is available.

# <a name="validating">Validate the Installation

The easiest way to validate that your installation is correct is to run
the test utilities in the `${PDO_SOURCE_ROOT}/build` directory. With the
proper environment variables set and the virtual environment activated
as described in the [installation guide](install.md), run these
commands:

```
cd ${PDO_SOURCE_ROOT}/build
make test
```

A variety of tests are run that exercise different components of the
installation. Note that the test process will start the necessary
eservies, pservices and sservices. It assumes that the ledger is
already running and configured.
