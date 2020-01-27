<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Table of Contents

- [Building the Provisioning Service](#building)
    - [Preliminaries](#preliminaries)
    - [Build & Install the Modules](#install)
        - [Install additional python libraries](#python)
        - [Quick way to build (& install)](#quick)
        - [Details of what makefile does](#details)
- [Test the Provisioning Service](#service-test)

# <a name="building">Building the Provisioning Service

This document describes how to build the provisioning service - a persistent
secret store which is used to provision enclaves so that they may operate on
contracts. It consists of a python JSON RPC utility which handles requests
submitted over HTTP.

## <a name="preliminaries">Preliminaries

This service depends on the common python libraries/imports, which depend on
the PDO common C++ library. Build these components first using the build
instructions [here](../../common/BUILD.md) and [here](../../python/BUILD.md).

It is highly recommended that you build a Python virtual environment
where you can install the common Python modules. The rest of these
instructions assume that you have set up a virtual environment for
Python3 and have activated it.

The environment variable ``PDO_HOME`` should be set to the directory where
you expect to configure and run the provisioning service. Generally the
variable is set to the path to your virtual environment root plus ``opt/pdo``.

For example:
```bash
prompt> export PDO_HOME=$VIRTUAL_ENV/opt/pdo
```

For production deployment, ``PDO_HOME`` should be set to ``/opt/pdo``.

Note: To build and run PService in SGX hardware-mode, the [EService](../../eservice/docs/BUILD.md)
has to be compiled first in hardware-mode.
Any changes to the EService will require the PService to be recompiled.

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

The provisioning service modules must be built next:

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
prompt> easy_install dist/pdo_pservice-0.0.1.dev1-py3.6-linux-x86_64.egg
```

Note that the name of the egg file will depend on the version of Python
you are using.

# <a name="service-test">Test the Provisioning Service

The provisioning service can started with the ``pservice`` script. The
provisioning service will search the current directory for a subdirectory
called ``etc`` in which you can place the configuration file ``pservice.toml``.
If the configuration file does not exist in the current directory tree, the
script will attempt to load it from the installed home directory (i.e. the
value of the ``PDO_HOME`` environment variable).

An example configuration file, ``sample_config.toml`` will be installed in
``$PDO_HOME/etc``. That file should provide a starting point for creating
your ``pservice.toml`` file.

Similarly, the provisioning service requires a ``log`` and ``data`` directory.
Again, by default, these can be located in the current directory hierarchy or
placed in the installed tree. Additionally, the configuration file can override
any defaults.

The simplest method is to use the default configuration in the installed
directory.

Assuming correct configuration, the provisioning service can be started this
way:

```bash
prompt> pservice --identity test-service
```

The ``identity`` parameter is a string used to identify logs and data files
associated with the service. For example, the logs for the above command will
be called ``logs/test-service.log``.

Logging can be sent to the screen by adding a parameter for the ``logfile``:

```bash
prompt> pservice --identity test-service --logfile __screen__
```

Once the provisioning service is running, you can run the provisioning service
unit tests. Information about what these tests do is available
[here](../test/Unit_Tests.md).  The test script requires a URL for connecting
to the provisioning service. The default configuration uses
``http://localhost:7800``.

```bash
prompt> cd pservice/test
prompt> python UnitTests.py --url http://localhost:7800
```
