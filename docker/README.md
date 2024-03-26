<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Docker Tools and Usages #

This directory contains scripts useful for building and running
containers with various PDO services and components. For the most
part, this directory could be copied to any host (even without PDO
otherwise installed) to build, configure, and execute PDO code.

<!--- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --->
## Basic Layout ##

There are three subdirectories that are employed in building, configuring and running a  container.

* `xfer` -- this directory is used to pass configuration information
  and keys between the container and the host; for example, to push a
  previously built configuration into the container, put the files in
  the appropriate subdirectory in xfer.
* `tools` -- this directory contains a number of scripts that will be
  installed in the container to simplify building, configuring and
  running the services in the container.
* `repository` -- this directory is created during the build process
  and contains the PDO source code that will be copied into the
  container; the build variables `PDO_REPO` and `PDO_BRANCH` control
  what is put into the directory.

<!--- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --->
## Makefile Targets ##

The `Makefile` contains several targets that should simplify building
images and running containers.

Four configuration variables should be set as necessary:

* `PDO_REPO` -- the URL or file path of the PDO source git repository;
  this defaults to the repository stored on the local file system at
  `${PDO_SOURCE_ROOT}`.
* `PDO_BRANCH` -- the branch to use in from the source repository;
  this defaults to the branch where the source is currently stored.
* `PDO_USER_UID` -- the UID for the user that is created in the
  container to run the services; this defaults to the current users
  UID. Note that the `xfer` directory must be writable by the account
  associated with the UID.
* `PDO_GROUP_UID` -- the GID for the group assigned to the user
  created in the container; the default is the GID for the current
  user.

### Automated Test ###

The `Makefile` in the directory is set up so that `make test` should
build and execute the automated tests with the CCF ledger, PDO
services, and PDO client all executing in separate containers. This
action is performed using the `docker-compose` configuration files in
the source directory and the `run_client_tests.sh`,
`run_services_test.sh` and `run_ccf_tests.sh` scripts in the `tools`
directory.

The automated tests pre-configure all network services to run on
`localhost` interface.

### Build and Rebuild Targets ###

There are targets for the initial build of each image. In addition, if
changes are made to artifacts that are not part of the docker build
specification, a rebuild target can be used to force recompilation of
the PDO artifacts.

```bash
    make build_services_base
    make rebuild_ccf
```

Similar targets will start the three primary containers: `run_ccf`,
`run_services` and `run_client`. The first two will run the containers
as services in detached mode. The last for the client will run an
interactive shell in the client container. See below for information
on how to use the client container.

### Build for SGX ###

For the contract enclave to run in SGX hardware mode, the services
image must be built using the following target:
```bash
    make sgx_build_services
```
This will create the `pdo_service_sgx` image. Inside the image,
the `SGX_MODE=HW` environment variable further indicates that the
service were built to run in SGX.

<!--- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --->
## Pattern: Local Development in a Container ##

### PDO Services ###

To set up an environment where interactive development can take place
on the local repository, use the `pdo_services_base` image and mount
the local source into the container. In this mode, you can edit source
files interactively on the host platform and compile/test inside the
container without installing any dependencies on the host.

Note: to use the ledger, you need to copy the CCF network certificate
into the directory `${PDO_SOURCE_ROOT}/xfer/ccf/keys`.

```bash
	docker run \
        -v ${PDO_SOURCE_ROOT}/docker/xfer/:/project/pdo/xfer \
        -v ${PDO_SOURCE_ROOT}/docker/tools/:/project/pdo/tools \
        -v ${PDO_SOURCE_ROOT}/:/project/pdo/src \
        --network host -it \
        --env PDO_HOSTNAME=${PDO_HOSTNAME} --env PDO_LEDGER_URL=${PDO_LEDGER_URL} \
        --name ${USER}_services_container pdo_services_base
```

The `start_development.sh` script contains all of the necessary
commands to set up the environment for development and testing. This
includes setting all of the necessary environment variables, adding
`PDO_HOSTNAME` to the no proxy configuration, and copying the CCF
network certificates into `PDO_LEDGER_KEY_ROOT`.

```bash
    source /project/pdo/tools/start_development.sh
```

### CCF ###

To develop CCF (which is built using the `pdo_ccf_base` image) use
the following:
```bash
	docker run \
        -v ${PDO_SOURCE_ROOT}/docker/xfer/:/project/pdo/xfer \
        -v ${PDO_SOURCE_ROOT}/docker/tools/:/project/pdo/tools \
        -v ${PDO_SOURCE_ROOT}/:/project/pdo/src \
        --network host -it \
        --env PDO_HOSTNAME=${PDO_HOSTNAME} --env PDO_LEDGER_URL=${PDO_LEDGER_URL} \
        --name ${USER}_ccf_container pdo_ccf_base
```

The `start_development.sh` script can be used in the `ccf_container`
in the same way it is used in the `services_container` above.

Note: be sure to run `make clean` in the host (out of container) build
tree.

<!--- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx --->
## Pattern: Service Deployment ##

The containers can be used to deploy network services from the
`pdo_ccf` and `pdo_services` images. Set the environment variables
`PDO_HOSTNAME` to the interface where the service will listen and
`PDO_LEDGER_URL` as the endpoint for CCF.

The scripts used to start CCF, PDO services and clients take a number
of options that can be passed after the docker image name. While each
script may have unique parameters (try running with `--help`), there
are several that are common to all of the start up scripts:

* `--interface` : the default hostname for providing or accessing services
* `--ledger` : the URL for the ledger
* `--mode <build|copy|skip>` : the mode for handling
  configuration; `build` creates a new set of configuration files
  using the hostname in the interface parameter, `copy` copies the
  configuration files from the transfer directory, and `skip` does
  nothing

For example, the following command will start the PDO services using
`localhost` interface for exporting services:

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name ${USER}_services_container pdo_services \
        --interface localhost --ledger http://127.0.0.1:6600
```

The examples below are run in the foreground. To run these examples
in the background add the `--detach` switch to the `docker run` commands.

As mentioned above, the docker images are built with a `UID:GID`
dervied from account used to build the images. If you would prefer to
use a different identity, the `--user` switch to the `docker run`
command will override the builtin identities. This can be especially
useful if the images are stored in a repository.

** NOTE: ** We need a better way to process registrations for SGX HW mode. In
theory, the best way to do this may be to create a canonical base
services image; populate an instance of it with CCF private keys, run
the registration. That way the canonical base service image would have
a standard version of the enclave library that would not have to deal
with reproducible builds.

### CCF Deployment ###

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name ${USER}_ccf_container pdo_ccf
```

This will configure the CCF service using the default configuration
based on `PDO_HOSTNAME` as the interface for exposing the ledger.

** NOTE: ** The CCF container ignores the existing value of
`PDO_LEDGER_URL`. Rather the container defines the service endpoint
that is captured by the setting of PDO_LEDGER_URL.

You may also run the CCF with a pre-built configuration. Create the
directories `$(SCRIPT_DIR)/xfer/ccf/etc` and
`$(SCRIPT_DIR)/xfer/ccf/keys`. Copy the CCF configuration files
(`cchost.toml` and `constitution.js`) into the `etc` directory. You
can use the PDO tool `pdo-configure-ccf` to create an initial set of
configuration files that can be customized.

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name ${USER}_ccf_container pdo_ccf --mode copy
```

The CCF container will create the `networkcert.pem` key file and
place it in the `$(SCRIPTDIR)/xfer/ccf/keys`.

** NOTE: ** We do not support starting a CCF instance to join an
existing CCF network. This is future work.

### PDO Services Deployment ###

Before starting the services container, be sure to copy the CCF ledger
keys into `${PDO_SOURCE_ROOT}/docker/xfer/ccf/keys`. Those keys
should be available from that directory on the host where the CCF
ledger is running.

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name ${USER}_services_container pdo_services
```

This will configure and create the standard set of five `eservices`,
five `pservices` and five `sservices`. It will take `PDO_HOSTNAME` and
`PDO_LEDGER_URL` that existed when the `pdo_services` image was built.
These can be overridden by adding parameters to the `docker-run`
command:

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name ${USER}_services_container pdo_services --ledger <URL> --interface <HOST>
```

You may also run the services with a pre-built configuration. Create
the directories `$(SCRIPT_DIR)/xfer/services/etc` and
`$(SCRIPT_DIR)/xfer/services/keys`. Copy the service configuration
files in to the `etc` directory and the service keys into the `keys`
directory. An initial version of the configuration files can be built
with the PDO tool `pdo-configure-services`.

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name ${USER}_services_container pdo_services --mode copy
```

#### PDO Services Deployment Using SGX ####

There are a few _additional_ considerations when using the services with SGX.

Before starting the container, make sure that the SGX collateral is available 
as described [here](../docs/install).

Also, recall that the attestation policy on the ledger has to be set once by the 
first eservice of a ledger consortium member. Hence, the first service container 
that is deputed to perform such registration must be instructed to do so.
```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        -v <host aesmd socket>:/var/run/aesmd --device=<host SGX device>:/dev/sgx/enclave \
        --name ${USER}_services_container pdo_services_sgx --register
```
This updated command allows to trigger the registration step right before
starting the services. The policy registration must happen before enclaves are 
registered (or any enclave registration will fail).

Finally, the _same_ SGX collateral must be made available to all service containers.
At enclave registration time, this will allow the eservice to generate the right 
quote (and attestation verification report) that meets the attestation policy 
originally registered with the PDO Transaction Processor.

### PDO Client Deployment ###

The client image creates an interactive environment for connecting
with PDO services. By default the entry point creates an interactive
shell.

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host -p \
        --name ${USER}_pdo_client pdo_client
```

The script `/project/tools/start_client.sh` is intended to simplify
initialization of a functioning client environment. Among other things
it will create the client configuration files and keys for users, and
it will copy the ledger keys from the `xfer` directory tree. The
script provides the standard options for interface (the default
services host), the ledger, and the mode for building or copying
client configuration files. An initial set of configuration files can
be created with the PDO tool `pdo-configure-client`.

For example:
```bash
    user@has:/project/pdo# source /project/pdo/tools/start_client.sh --ledger http://127.0.0.1:6600/
```
