PDO_REPO_URL = https://github.com/hyperledger-labs/private-data-objects.git
PDO_REPO_BRANCH =  main

-include make.loc

# Turns out that this does not work very well if the path
# contains spaces in the name; in fact lots of things break
# very badly; set this explicitly
# SCRIPT_DIR = $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
SCRIPT_DIR ?= ${PDO_SOURCE_ROOT}/docker-new

DOCKER_USERNAME = $(LOGNAME)
DOCKER_BUILDARGS += --build-arg PDO_REPO_URL=$(PDO_REPO_URL)
DOCKER_BUILDARGS += --build-arg PDO_REPO_BRANCH=$(PDO_REPO_BRANCH)
DOCKER_BUILDARGS += --build-arg PDO_HOSTNAME=$(PDO_HOSTNAME)
DOCKER_BUILDARGS += --build-arg PDO_LEDGER_URL=$(PDO_LEDGER_URL)
DOCKER_ARGS = --progress=plain ${DOCKER_BUILDARGS}

IMAGES=base client services-base services ccf

# for the most part this is just used to force rebuild when the
# PDO repository has changed
TIMESTAMP := $(shell /bin/date "+%Y%m%d%H%M%S")

all : $(addprefix build_,$(IMAGES))

rebuild_% :
	@ docker build ${DOCKER_ARGS} --build-arg REBUILD=$(TIMESTAMP) --tag pdo-$* --file $(SCRIPT_DIR)/pdo-$*.dockerfile .

build_% :
	@ docker build ${DOCKER_ARGS} --tag pdo-$* --file $(SCRIPT_DIR)/pdo-$*.dockerfile .

clean_% :
	@ docker rmi -f pdo-$*

run_ccf : build_ccf
	@ rm -f xfer/ccf_keys/*
	- docker rm -f ccf-container
	@ docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host --name ccf-container -P -d pdo-ccf

run_services : build_base build_services-base build_services
	@ rm -f $(SCRIPT_DIR)/xfer/site.psh
	- docker rm -f services-container
	@ docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host --name services-container -P -d pdo-services

run_client : build_base build_client
	- docker rm -f client-container
	@ docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host --name client-container pdo-client

build_test :
	PDO_REPO_URL=$(PDO_REPO_URL) PDO_REPO_BRANCH=$(PDO_REPO_BRANCH) \
		docker-compose -f test-configuration.yaml build

test : build_test
	- rm -f $(SCRIPT_DIR)/xfer/ccf_keys/* $(SCRIPT_DIR)/xfer/site.psh $(SCRIPT_DIR)/xfer/status
	docker-compose -f test-configuration.yaml up --no-recreate

_IMAGES_=$(shell docker images -a --filter=dangling=true -q)
_CONTAINERS_=$(shell docker ps --filter=status=exited --filter=status=created -q)
clean : $(addprefix clean_,$(IMAGES))
	@ rm -f $(SCRIPT_DIR)/xfer/ccf_keys/* $(SCRIPT_DIR)/xfer/site.psh $(SCRIPT_DIR)/xfer/status
	@ if [ ! -z "$(_CONTAINERS_)" ]; then docker rm -f $(_CONTAINERS_); fi
	@ if [ ! -z "$(_IMAGES_)" ]; then docker rmi -f $(_IMAGES_); fi

.PHONY: clean
.PHONY: build_test test
.PHONY: run_ccf run_client run_services
