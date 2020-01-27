<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Table of Contents

- [Building the Client Utilities](#building)
    - [Preliminaries](#preliminaries)
    - [Build & Install the Modules](#install)
        - [Install additional python libraries](#python)
        - [Quick way to build (& install)](#quick)
        - [Details of what makefile does](#details)
- [Using the Client Utilities](#usage)

# <a name="building">Building the Client Utilities

This document describes how to build the client utilities - tools that can be
used to interact with contracts. These currently include a tool to create a
contract (CreateCLI), update a contract (UpdateCLI), and run an auction
(AuctionTestCLI).

## <a name="preliminaries">Preliminaries

The client utilities depend on the common python libraries/imports, which
depend on the PDO common C++ library. Build these components first using the
build instructions [here](../../common/BUILD.md) and
[here](../../python/BUILD.md).

It is highly recommended that you build a Python virtual environment
where you can install the common Python modules. The rest of these
instructions assume that you have set up a virtual environment for
Python3 and have activated it.

The environment variable ``PDO_HOME`` should be set to the directory where
you expect to configure and run the client utilities. Generally the variable is
set to the path to your virtual environment root plus ``opt/pdo``.

For example:
```bash
prompt> export PDO_HOME=$VIRTUAL_ENV/opt/pdo
```

For production deployment, ``PDO_HOME`` should be set to ``/opt/pdo``.

## <a name="install">Build & Install the Modules

### <a name="python">Install additional python libraries
You may have to install some additional python packages with pip before this
will run, including:
```
prompt> pip install colorlog
prompt> pip install requests
prompt> pip install toml
prompt> pip install twisted
```

### <a name="quick">Quick way to build (& install):

Make sure the environment variables are defined (see the
[environment guide](../../docs/environment.md)), then run:
```bash
prompt> make build_all && make install
```

### <a name="details">Details of what makefile does

The client utilities modules must be built next:

```bash
prompt> python setup.up build_ext
```

Next, build the installable egg file:

```bash
prompt> python setup.py bdist_egg
```

If you want to remove files created during the build process, just use
``make clean``.

Assuming that you have activated a virtual environment, the modules can
be installed with ``easy_install``.

```bash
prompt> easy_install dist/pdo_client-0.0.1.dev1-py3.6-linux-x86_64.egg
```

Note that the name of the egg file will depend on the version of Python
you are using.

# <a name="usage">Using the Client Utilities

See the main [USAGE](../../USAGE.md) document about how to use the client to
interact with Private Data Objects contracts.
