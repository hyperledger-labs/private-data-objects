<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Table of Contents

- [Building the Contract Enclave Service and Supporting Libraries](#building)
    - [Preliminaries](#preliminaries)
    - [Build & Install the Modules](#install)
        - [Install additional python libraries](#python)
        - [Quick way to build (& install)](#quick)
        - [Details of what makefile does](#details)
    - [Test the Module](#test)
- [Test the Enclave Service](#service-test)

# <a name="building">Building the Contract Enclave Service and Supporting Libraries

This directory contains source for the contract enclave, a Python
wrapper for managing it, and a service that translates HTTP requests
into invocations of the contract enclave.


## <a name="preliminaries">Preliminaries

This service depends on the common python libraries/imports, which depend on
the PDO common C++ library. Build these components first using the build
instructions [here](../../common/BUILD.md) and [here](../../python/BUILD.md).

It is highly recommended that you build a Python virtual environment
where you can install the common Python modules. The rest of these
instructions assume that you have set up a virtual environment for
Python3 and have activated it.

The environment variable ``PDO_HOME`` should be set to the directory
where you expect to configure and run the enclave service. Generally the
variable is set to the path to your virtual environment root plus
``opt/pdo``.

For example:
```bash
prompt> export PDO_HOME=$VIRTUAL_ENV/opt/pdo
```

For production deployment, ``PDO_HOME`` should be set to ``/opt/pdo``.

Note: EService has to be compiled in SGX hardware-mode before compiling and running
[PService](../../pservice/docs/BUILD.md) in hardware-mode. Any changes to the EService
will require the PService to be recompiled.

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

First, the contract enclave must be built:
```bash
prompt> mkdir build
prompt> cd build
prompt> cmake .. -G "Unix Makefiles"
prompt> make
```

The contract enclave extension modules must be built next:

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
prompt> easy_install dist/pdo_eservice-0.0.1.dev1-py3.6-linux-x86_64.egg
```

Note that the name of the egg file will depend on the version of Python
you are using.

## <a name="test">Test the Module

If everything is set up correctly, you should be able to run the secret
and request tests in the ``tests`` directory. These invoke the contract
enclave wrapper scripts directly.

```bash
prompt> cd ./tests
prompt> python test-secrets.py
prompt> python test-request.py
```

# <a name="service-test">Test the Enclave Service

The enclave service can started with the ``eservice`` script. The
enclave service will search the current directory for a subdirectory
called ``etc`` in which you can place the configuration file
``eservice.toml``.  If the configuration file does not exist in the
current directory tree, the script will attempt to load it from the
installed home directory (i.e. the value of the ``PDO_HOME``
environment variable).

An example configuration file, ``sample_config.toml`` will be installed in
``$PDO_HOME/etc``. That file should provide a starting point for creating your ``eservice.toml``
file.

Similarly, the enclave service requires a ``log`` and ``data``
directory. Again, by default, these can be located in the current
directory hierarchy or placed in the installed tree. Additionally, the
configuration file can override any defaults.

The simplest method is to use the default configuration in the installed
directory.

Assuming correct configuration, the enclave service can be started this
way:

```bash
prompt> eservice --identity test-service
```

The ``identity`` parameter is a string used to identify logs and data files associated with the
service. For example, the logs for the above command will be called ``logs/test-service.log``.

Logging can be sent to the screen by adding a parameter for the ``logfile``:

```bash
prompt> eservice --identity test-service --logfile __screen__
```

Once the enclave service is running, you can run the enclave test script. The test script requires a
URL for connecting to the enclave service. The default configuration uses ``http://localhost:7100``.

```bash
prompt> cd ./tests
prompt> python test-eservice.py --url http://localhost:7100
```
