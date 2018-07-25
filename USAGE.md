<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# USAGE

This document describes what to do with your Hyperledger Private Data Objects
project once you have followed the steps in [BUILD.md](BUILD.md).

## Table of Contents

- [Validating the Installation](#validating)
- [Contracts](#contracts)

# <a name="validating">Validating the Installation

The easiest way to validate that your installation is correct is to run the
test utilities under eservice/tests. With the proper environment variables set
and the virtual environment activated as described in [BUILD](BUILD.md), run
these commands:

```
cd eservice/tests
python test-secrets.py
python test-contract.py --ledger http://127.0.0.1:8008
python test-request.py --ledger http://127.0.0.1:8008
```

These tests do not require the enclave service or provisioning service to be
running - they test directly against the underlying implementations of those
services. If these tests pass, you know that your system is set up correctly.

# <a name="contracts">Contracts

A "contract" is, at its core, just some Gipsy Scheme code. This code runs
inside the contract enclave where it is protected from eavesdropping
(confidentiality) and tampering (integrity). The contracts themselves enforce
what they can and can not do - they are just code that runs on data. More
information about contracts is available [here](contracts/docs/contract.md).

This project comes bundled with a few example contracts which you can
experiment with. Here is a brief overview of each one:

- [mock-contract](contracts/mock-contract/mock-contract.scm)
A very simple contract which allows the contract owner to increment and
retrieve a stored value. Other parties can not interact with the contract.

- [integer-key](contracts/integer-key/integer-key.scm)
Like mock contract, provides an interface for interacting with a stored integer
value. Only the contract owner may retrieve and decrement the value. Anyone may
increment the counter, and the owner can transfer some or all of the value to a
different integer-key contract owned by someone else. Additionally, the owner
can choose to transfer ownership of the contract to someone else. Integer key
also supports escrow - the ability to transfer control of the value to another
entity temporarily (such as when participating in an auction).

- [auction](contracts/auction/auction.scm)
More sophisticated contract that implements a "silent" auction. Participants in
the auction can "bid" integer-key values by placing them in escrow.
Participants may only see the highest bid and their current bid - not even the
owner of the auction can retrieve all of the bids. The owner may choose when to
close bidding and select a winner, after which point the "for sale" value is
exchanged with the highest bid.

- [exchange](contracts/exchange/docs/exchange.md)
Where the integer-key and auction contracts are primarily for demonstration and testing, the suite
of contracts that make up the asset exchange can be used to implement a multi-asset ledger with
several types of exchanges possible. The exchange contract suite includes plugins for the pdo client
shell to simplify interaction with the contracts and [example scripts](contracts/exchange/scripts/README.md)
that can be used to set up asset ledgers.
