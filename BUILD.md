<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# BUILD

In order to build, install, and run Hyperledger Private Data Objects, a number
of additional components must be installed and configured. The following
instructions will guide you through the installation and build process for
Hyperledger Private Data Objects.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installing Sawtooth Distributed Ledger](#sawtooth)
- [Quickstart: Installing PDO Using Scripts](#quickstart)
- [Building and installing PDO manually](#manual-install)
    - [Setting up a Python Virtual Environment](#virtualenv)
    - [Compiling the Common C++ Libraries](#common)
    - [Compiling the Python shared libraries](#python)
    - [Building the Enclave Service](#eservice)
    - [Building the Provisioning Service](#pservice)
    - [Building the Client](#client)
- [Using Private Data Objects](#using)

# <a name="prerequisites"></a>Prerequisites
Follow the instructions [here](PREREQUISITES.md) to install and configure
components on which PDO depends.

# <a name="sawtooth"></a>Installing Sawtooth Distributed Ledger
Hyperledger Private Data Objects uses the Hyperledger Sawtooth distributed
ledger to store data object instances and state, and to guarantee update
atomicity.

Application logic is implemented in Sawtooth through the use of Transaction
Processors; transaction processors enable the distributed ledger to handle
application requests. This repository contains the code required to build
Transaction Processors that handle PDO requests.

Follow the setup document [here](sawtooth/docs/SETUP.md) to install both
Sawtooth and the custom Sawtooth Transaction Processors.

Note that the Sawtooth components do not depend on any other components of the
PDO project, and can be set up on an entirely separate machine from the one
running Private Data Objects. It is recommended that Sawtooth be run on Ubuntu
16.04 as it is the only operating system version on which Sawtooth is actively
supported.

# <a name="quickstart"></a>Quickstart: Installing PDO Using Scripts
The following section of this document describes manual compilation and
installation instructions for Private Data Objects components. Following those
steps is a good way to learn about the components of the project as you become
an advanced user.

This section describes how to get started with PDO quickly using provided
scripts to compile and install PDO.

First, make sure environment variables are set as described in the
[prerequisites](#prerequisites) section.

The quickstart build will set up a python virtual environment to install things
into. Set `CONTRACTHOME` to point to the target install directory for PDO
components. You will need this environment variable set in every shell session
where you interact with PDO.
```
export CONTRACTHOME=`pwd`/__tools__/build/_dev/opt/pdo
```

Change to the quickstart build directory:
```
cd __tools__/build
```

Edit `opt/pdo/etc/template/eservice.toml` and
`opt/pdo/etc/template/pservice.toml` to have the correct ledger URL for your
sawtooth installation.

Build the virtual environment and install PDO components into it:
```
make
```

Activate the new virtual environment for the current shell session. You will
need to do this in each new shell session (in addition to exporting environment
variables).
```
source _dev/bin/activate
```

Run the test suite to check that the installation is working correctly. Replace
the URL with the URL for the rest-api of your Sawtooth installation.
```
cd ..
LEDGER_URL=http://127.0.0.1:8008 ./run-tests.sh
```

# <a name="manual-install"></a>Building and installing PDO manually
## <a name="virtualenv"></a>Setting up a Python Virtual Environment
The directories containing python code (`python`, `eservice`, `pservice`, and
`client`) all create installable Python modules. You can install these to the
root system's python if you want; however, the recommended approach is to
create a new python "virtual environment" where they can be installed without
affecting the root system.

Create a python virtual environment in the folder `venv` by running:
```
python3 -m venv venv
```

Now activate that virtual environment for your current shell session. You will
need to do this every time you start a new shell session:
```
source venv/bin/activate
```

Now that the virtual environment is active, install the python libraries that
Private Data Objects depends upon. NOTE: On Ubuntu 17.10 (and probably others)
secp256k1 may not install correctly with pip. If this happens to you, try first
installing your distribution's libsecp256k1-dev package via something like
`sudo apt-get install libsecp256k1-dev` and then re-run the pip installation.
```
pip install --upgrade pip
pip install --upgrade setuptools
pip install --upgrade toml
pip install --upgrade requests
pip install --upgrade colorlog
pip install --upgrade twisted
pip install --upgrade pyyaml
pip install --upgrade google
pip install --upgrade protobuf
pip install --upgrade secp256k1
pip install --upgrade cryptography
pip install --upgrade pyparsing
```

If you are using this recommended virtual environment setup, you will also need
to export the environment variable `CONTRACTHOME`. This is used by PDO to find
configuration files and encryption keys. Set this variable in your current
shell session with:
```
export CONTRACTHOME=`pwd`/venv/opt/pdo
```

## <a name="common"></a>Compiling the Common C++ Libraries
The `common` directory contains cryptography, encoding, and other miscellaneous
routines used by many other components. Follow the build instructions
[here](common/BUILD.md) to compile the common libraries.

## <a name="python"></a>Compiling the Python shared libraries
The `python` directory contains shared python libraries/imports used by many
other components. Much of the higher-level user logic of Private Data Objects
is implemented in Python. The python directory includes a python SWIG wrapper
of the common libraries, so common must be compiled prior to compiling the
`python` directory.

Instructions for compiling and installing the python directory are available
[here](python/BUILD.md).

## <a name="eservice"></a>Building the Enclave Service
The Enclave Service (eservice for short) consists of two components:
- A Software Guard Extensions "enclave" which runs the actual contract code
- A python service wrapper (the eservice) which passes messages to and from the enclave

More information about the eservice is available
[here](eservice/docs/eservice.md), and instructions for how to build it are
[here](eservice/docs/BUILD.md).

## <a name="pservice"></a>Building the Provisioning Service
The Provisioning Service (pservice for short) is a simple key/value store used
to generate "secrets" which provision specific enclaves for use with specific
contracts.

Instructions for how to build the provisioning service are available
[here](pservice/docs/BUILD.md).

## <a name="client"></a>Building the Client
The client directory contains several utilities for creating and executing
contracts.

Instructions for how to build the client utilities service are available
[here](client/docs/BUILD.md).

# <a name="using"></a>Using Private Data Objects
See the main [USAGE](USAGE.md) document for information on how to test and
use your Private Data Objects installation.
