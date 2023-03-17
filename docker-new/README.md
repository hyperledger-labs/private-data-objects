# Docker Usages #

The `Makefile` contains several targets that should simplify building
images and running containers. This file contains some additional
information for running the various containers.

## Automated Test ##

The automated tests pre-configure all network services to run on localhost interface.

```bash
    rm -f ./xfer/networkcert.pem ./xfer/site.psh ./xfer/status
	docker-compose -f test-configuration.yaml build \
        --build-arg PDO_REPO_URL=$(PDO_REPO_URL) \
        --build-arg PDO_REPO_BRANCH=$(PDO_REPO_BRANCH)
	docker-compose --no-recreate -f test-configuration.yaml up
```

The `Makefile` in the directory is set up so that `make test` should
build and execute the automated tests with the CCF ledger, PDO
services, and PDO client all executing in separate containers.

## Local Development ##

To set up an environment where interactive development can take place
on the local repository, use the `pdo-services-base` image and mount
the local source into the container. In this mode, you can edit source
files interactively on the host platform and compile/test inside the
container without installing any dependencies on the host.

Note: to use the ledger, you need to copy the CCF network certificate
into the directory `${SCRIPTDIR}/xfer`.

```bash
	docker run \
        -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer \
        -v $(SCRIPT_DIR)/tools/:/project/pdo/tools \
        -v $(PDO_SOURCE_ROOT)/:/project/pdo/src \
        --network host -p -it \
        --env PDO_HOSTNAME=${PDO_HOSTNAME} --env PDO_LEDGER_URL=${PDO_LEDGER_URL}
        --name ${USERNAME}/services-container pdo-services-base
```

The `start_development.sh` script contains all of the necessary
commands to set up the environment for development and testing. This
includes setting all of the necessary environment variables, adding
`$PDO_HOSTNAME` to the no proxy configuration, and copying the CCF
network certificates into `$PDO_LEDGER_KEY_ROOT`.

```bash
    source /project/pdo/tools/start_development.sh
```

## Service Deployment ##

The containers can be used to deploy network services from the
`pdo-ccf` and `pdo-services` images. Set the environment variables
`PDO_HOSTNAME` to the interface where the service will listen and
`PDO_LEDGER_URL` as the endpoint for CCF.

** NOTE: We need a better way to process registrations for SGX HW mode. In
theory, the best way to do this may be to create a canonical base
services image; populate an instance of it with CCF private keys, run
the registration. That way the canonical base service image would have
a standard version of the enclave library that would not have to deal
with reproducible builds.**

### CCF Deployment ###

```bash
    rm -f xfer/ccf_keys/networkcert.pem
    docker run -v $(SCRIPTDIR)/xfer/:/project/pdo/xfer --network host \
        --name ccf-container pdo-ccf
```

### PDO Services Deployment ###

```bash
    rm -f $(SCRIPT_DIR)/xfer/sites.psh
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host \
        --name services-container pdo-services
```

### PDO Client Deployment ###

The client image is primarily intended for automated services
tests. As such, starting it will run tests in
`${PDO_SOURCE_ROOT}/build/tests/service-tests.sh`. You can, however,
override the entrypoint and start a shell that would allow you to
perform other client operations.

```bash
    docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host -p \
        --name pdo-client pdo-client
```
