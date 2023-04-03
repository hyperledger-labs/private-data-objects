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

TEST_FILES =  -f base.yaml
TEST_FILES += -f client_base.yaml
TEST_FILES += -f services_base.yaml
TEST_FILES += -f ccf_base.yaml
TEST_FILES += -f test.yaml

# for the most part this is just used to force rebuild when the
# PDO repository has changed
TIMESTAMP := $(shell /bin/date "+%Y%m%d%H%M%S")

all : $(addprefix build_,$(IMAGES))

rebuild_% :
	@ docker build ${DOCKER_ARGS} --build-arg REBUILD=$(TIMESTAMP) --tag pdo_$* --file $(SCRIPT_DIR)/pdo_$*.dockerfile .

build_% :
	@ docker build ${DOCKER_ARGS} --tag pdo_$* --file $(SCRIPT_DIR)/pdo_$*.dockerfile .

clean_% :
	@ docker rmi -f pdo_$*

run_ccf : build_ccf
	- docker rm -f ccf_container
	@ docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host --name ccf_container -P -d pdo_ccf

run_services : build_base build_services_base build_services
	- docker rm -f services_container
	@ docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer --network host --name services_container -P -d pdo_services

run_client : build_base build_client
	- docker rm -f client_container
	@ docker run -v $(SCRIPT_DIR)/xfer/:/project/pdo/xfer -it --network host --name client_container pdo_client

build_test :
	PDO_REPO_URL=$(PDO_REPO_URL) PDO_REPO_BRANCH=$(PDO_REPO_BRANCH) \
		docker-compose $(TEST_FILES) build

test : clean_config build_test
	docker-compose $(TEST_FILES) up

_IMAGES_=$(shell docker images -a --filter=dangling=true -q)
_CONTAINERS_=$(shell docker ps --filter=status=exited --filter=status=created -q)
clean_images : $(addprefix clean_,$(IMAGES))
	@ if [ ! -z "$(_CONTAINERS_)" ]; then docker rm -f $(_CONTAINERS_); fi
	@ if [ ! -z "$(_IMAGES_)" ]; then docker rmi -f $(_IMAGES_); fi

clean_config :
	@ rm -f $(SCRIPT_DIR)/xfer/ccf/keys/*.pem $(SCRIPT_DIR)/xfer/ccf/etc/*.toml
	@ rm -f $(SCRIPT_DIR)/xfer/services/keys/*.pem $(SCRIPT_DIR)/xfer/services/etc/*.toml
	@ rm -f $(SCRIPT_DIR)/xfer/site.psh $(SCRIPT_DIR)/xfer/status

clean : clean_images clean_config

.PHONY: clean clean_images clean_config
.PHONY: build_test test
.PHONY: run_ccf run_client run_services
