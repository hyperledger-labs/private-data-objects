<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Building the Common Python Libraries #

This directory contains source for shared Python libraries that support
the private data objects project.

* pdo.common -- wrapper for the common library
  * pdo.common.crypto -- cryptographic classes and array conversion
* pdo.test -- classes and functions to simplify test development
  * pdo.test.enclave -- enclave specific classes
    * pdo.test.helpers.contract -- contract update requests and responses
    * pdo.test.helpers.keys -- enclave and service keys
    * pdo.test.helpers.secrets -- provisioning secrets and contract
    state encryption keys

## Preliminaries ##

The common Python library depends on the C++ common library. First build
the C++ library using the build instructions [here](../common/BUILD.md).

It is highly recommended that you build a Python virtual environment
where you can install the common Python modules. The rest of these
instructions assume that you have set up a virtual environment for
Python3 and have activated it.

## Build the Modules ##

Quick way to build (& install):
```bash
make && make install
```

Details of what makefile does ...
The extension modules must be built first:

```bash
python setup.py build_ext
```

Next, build the installable egg file:

```bash
python setup.py bdist_egg
```

If you want to remove files created during the build process, use the
``clean --all`` setup command:

```bash
python setup.py clean --all
```

Assuming that you have activated a virtual environment, the modules can
be installed with ``easy_install``.

```bash
easy_install dist/pdo_common_library-0.1.0-py3.6-linux-x86_64.egg
```
## Test the Module ##

If everything is set up correctly, you should be able to run the common
crypto wrapper test:

```
cd ../common/tests
python test_cryptoWrapper.py
```
