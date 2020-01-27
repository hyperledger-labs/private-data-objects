<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Using Private Data Objects

This document describes what to do with your Hyperledger Private Data Objects
project once you have followed the steps in the
[installation guide](install.md).

## Table of Contents

- [Validate the Installation](#validating)
- [Develop Contracts](#contracts)

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
| `eservice` | contract enclave service | `eservice.toml` |
| `pservice` | contract provisioning service | `pservice.toml` |
| `sservice` | state storage service associated with an enclave service | `sservice.toml` |
| `pdo-shell` | the PDO client shell for creating contracts and invoking methods | `pcontract.toml` |

For simplicity in installation, the file `enclave.toml` in the
`${PDO_HOME}/etc` directory contains the configuration for the accessing
the Intel Attestation Service.

Default versions of the configuration files are constructed during the
build process. The default setup provides configuration files for five
different service instances plus the `pdo-shell` client configuration.

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
installation.

# <a name="contracts">Contracts

A "contract" is, at its core, just some Gipsy Scheme code. This code runs
inside the contract enclave where it is protected from eavesdropping
(confidentiality) and tampering (integrity). The contracts themselves enforce
what they can and can not do - they are just code that runs on data. More
information about contracts is available
[here](../contracts/docs/contract.md).

This project comes bundled with a few example contracts which you can
experiment with. Here is a brief overview of each one:

- [mock-contract](../contracts/test-contracts/mock-contract.scm)
A very simple contract which allows the contract owner to increment and
retrieve a stored value. Other parties can not interact with the contract.

- [integer-key](../contracts/integer-key/integer-key.scm)
Like mock contract, provides an interface for interacting with a stored integer
value. Only the contract owner may retrieve and decrement the value. Anyone may
increment the counter, and the owner can transfer some or all of the value to a
different integer-key contract owned by someone else. Additionally, the owner
can choose to transfer ownership of the contract to someone else. Integer key
also supports escrow - the ability to transfer control of the value to another
entity temporarily (such as when participating in an auction).

- [auction](../contracts/auction/integer-key-auction.scm)
More sophisticated contract that implements a "silent" auction. Participants in
the auction can "bid" integer-key values by placing them in escrow.
Participants may only see the highest bid and their current bid - not even the
owner of the auction can retrieve all of the bids. The owner may choose when to
close bidding and select a winner, after which point the "for sale" value is
exchanged with the highest bid.

- [exchange](../contracts/exchange/docs/exchange.md)
Where the integer-key and auction contracts are primarily for demonstration and testing, the suite
of contracts that make up the asset exchange can be used to implement a multi-asset ledger with
several types of exchanges possible. The exchange contract suite includes plugins for the pdo client
shell to simplify interaction with the contracts and
[example scripts](../contracts/exchange/scripts/README.md)
that can be used to set up asset ledgers.
