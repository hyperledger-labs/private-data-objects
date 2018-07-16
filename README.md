<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
Hyperledger Private Data Objects
-------------

Private Data Objects (PDO) enables sharing of data and coordinating action
amongst mutually distrusting parties. Interaction is mediated through a “smart
contract” that defines data access and update policies that are carried with
the object regardless of where it resides or how often it changes hands. The
smart contracts policies are enforced through execution in a Trusted Execution
Environment (TEE).

PDO uses a distributed ledger to ensure that there is a single, authoritative
instance of the object, and to provide a means of guaranteeing atomicity of
updates across interacting objects. The long-term goal for PDO is to perform
contract execution and storage off the blockchain, with only a hash of
blockchain state stored on the distributed ledger

PDO provides benefits for both application developers seeking to define and
implement privacy-preserving distributed ledgers, and for service providers
seeking to provide blockchain services.

For the application developer, smart contracts implemented with PDO ensure that
contract state is completely hidden from all participants, including contract
validators, and allows contracts to be stored off-chain. Policies and data are
bound up together in the PDO smart contract; polices travel with the data no
matter how the smart contract object is shared or with whom. The PDO smart
contact provides an enforceable agreement for multi-party data sharing and
analytics.

For service providers, PDO provides scalable performance; separation of
contract execution from ordering allows the performance of contract execution
to scale with available hardware. Because PDO contract execution occurs off
the blockchain, redundancy is limited to the applications requirements rather
than the entire blockchain, providing fewer potential targets for compromise.

Documentation
-------------

Instructions for installing/building Hyperledger Private Data Objects can be
found in the [BUILD](BUILD.md) documentation.

The [USAGE](USAGE.md) document describes what you can do with a functional PDO
installation.

For more information about how Private Data Objects work, see the
[SPECIFICATION](SPECIFICATION.md) document.

A presentation about Private Data Objects is available
[HERE](https://docs.google.com/presentation/d/16V0kK9M_z86WwI-PfdltY5plXnkOdFuK84sWFaExH_k).

Project Status
-------------

Hyperledger Private Data Objects operates as a Hyperledger Labs project. This
code is provided solely to demonstrate basic PDO mechanisms and to facilitate
collaboration to refine PDO architecture and define minimum viable product
requirements.

Initial Committers
-------------

* Andrea Miele (andmiele1 - andrea.miele@intel.com)
* Abdulkareem Adesokan (aaadesok - abdulkareem.adesokan@intel.com)
* Bruno Vavala (bvavala - bruno.vavala@intel.com)
* Byron Marohn (byron-marohn - byron.marohn@intel.com)
* Mic Bowman (cmickeyb - cmickeyb@gmail.com)
* Eugene Yarmosh (EugeneYYY - yevgeniy.y.yarmosh@intel.com)
* Holly Harmon (harmonh - holly.harmon@intel.com)
* Tom Barnes (TomBarnes - thomas.j.barnes@intel.com)

Sponsor
-------------

Dan Middleton (dan.middleton@intel.com)

License
-------------

Hyperledger Private Data Objects software is released under the Apache License
Version 2.0 software license. See the [license file](LICENSE) for more details.

Hyperledger Private Data Objects documentation is licensed under the Creative
Commons Attribution 4.0 International License. You may obtain a copy of the
license at: http://creativecommons.org/licenses/by/4.0/.
