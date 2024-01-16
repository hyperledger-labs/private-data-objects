# ------------------------------------------------------------------------------
# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

# PDO_REPO --
#   The URL or path to the git repository, the default uses the current repository
#   though it might be reasonable to build a particular branch from the primary
#   PDO repository at https://github.com/hyperledger-labs/private-data-objects.git
# PDO_BRANCH --
#   The branch that will be used for the containers, the default is the current
#   branch, a reasonable alternative would be to use the 'main' branch from the
#   public PDO repository
PDO_REPO ?= ${PDO_SOURCE_ROOT}
PDO_BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)

PDO_VERSION ?= $(shell cd repository; bin/get_version) 

# PDO_USER_UID, PDO_GROUP_UID --
#   The UID/GID for the user accounts that will be created in the container; this is
#   important especially when the containers are being used for development; note
#   that the user/group identifiers need to have write access to the xfer directory
PDO_USER_UID ?= $(shell id -u)
PDO_GROUP_UID ?= $(shell id -g)

# Include local customizations if they are available
-include make.loc

# Turns out that setting the script directory from the Makefile's name
# does not work very well if the path contains spaces in the name; in
# fact lots of things break very badly; set this explicitly
DOCKER_DIR ?= ${PDO_SOURCE_ROOT}/docker

DOCKER_USERNAME = $(LOGNAME)
DOCKER_BUILDARGS += --build-arg UID=$(PDO_USER_UID)
DOCKER_BUILDARGS += --build-arg GID=$(PDO_GROUP_UID)
DOCKER_ARGS = $(DOCKER_BUILDARGS)

IMAGES=base client services_base services ccf_base ccf

# for the most part this is just used to force rebuild when the
# PDO repository has changed
TIMESTAMP := $(shell /bin/date "+%Y%m%d%H%M%S")

all : $(addprefix build_,$(IMAGES))

rebuild_% : repository
	docker build $(DOCKER_ARGS) \
		--build-arg REBUILD=$(TIMESTAMP) \
		--build-arg PDO_VERSION=$(PDO_VERSION) \
		--tag pdo_$*:$(PDO_VERSION) \
		--file $(DOCKER_DIR)/pdo_$*.dockerfile .

build_% : repository
	docker build $(DOCKER_ARGS) \
		--build-arg PDO_VERSION=$(PDO_VERSION) \
		--tag pdo_$*:$(PDO_VERSION) \
		--file $(DOCKER_DIR)/pdo_$*.dockerfile .

# docker build dependencies
build_client: build_base
build_services: build_services_base
build_services_base: build_base
build_ccf: build_ccf_base


clean_% :
	@ docker rmi -f pdo_$*:$(PDO_VERSION)

run_ccf : build_ccf stop_ccf
	@ docker run -v $(DOCKER_DIR)/xfer/:/project/pdo/xfer -e PDO_HOSTNAME=${PDO_HOSTNAME} --network host --name ccf_container -P -d pdo_ccf:$(PDO_VERSION)

run_services : build_base build_services_base build_services stop_services
	@ docker run -v $(DOCKER_DIR)/xfer/:/project/pdo/xfer -e PDO_HOSTNAME=${PDO_HOSTNAME} --network host --name services_container -P -d pdo_services:$(PDO_VERSION)

run_client : build_base build_client
	@docker run -v $(DOCKER_DIR)/xfer/:/project/pdo/xfer -e PDO_HOSTNAME=${PDO_HOSTNAME} -it --network host --name client_container pdo_client:$(PDO_VERSION) -c "stty cols $$(tput cols) rows $$(tput lines) && bash"

stop_all : stop_ccf stop_services stop_client

stop_ccf :
	- docker rm -f ccf_container

stop_services :
	- docker rm -f services_container

stop_client :
	- docker rm -f client_container

# -----------------------------------------------------------------
# We need a repository with the source for the branch we are going
# to build. In theory this could just be a copy of the local source
# tree but it might contain other artifacts. So instead we clone
# the repository with just a single branch in it. The storage and
# performance requirements are relatively low.
# -----------------------------------------------------------------
repository :
	@ git clone --single-branch --branch $(PDO_BRANCH) --recurse-submodules $(PDO_REPO) repository

clean_repository :
	@ rm -rf repository

# -----------------------------------------------------------------
# Testing uses docker-compose to build a set of images that will be configured
# to run with localhost as the interface. in order to get a clean shutdown we
# don't use a docker-compose specification for the base, ccf_base and services_base
# containers. since we are rebuilding the repository, we force recompilation of these
# images from the rebuilt repository. the corresponding images are built using docker
# build instead of being included in the docker-compose.
# -----------------------------------------------------------------
TEST_FILES = -f client_base.yaml
TEST_FILES += -f services_base.yaml
TEST_FILES += -f ccf_base.yaml
TEST_FILES += -f test.yaml

build_test : repository build_services build_ccf build_client

test : clean_config clean_repository build_test stop_all
	PDO_VERSION=$(PDO_VERSION) docker-compose $(TEST_FILES) up --abort-on-container-exit
	PDO_VERSION=$(PDO_VERSION) docker-compose $(TEST_FILES) down


# -----------------------------------------------------------------
# Cleaning is a bit interesting because the containers don't go away
# unless they are told to very nicely. Until they go away they hold onto
# referenced images. Clean make sure that everything is cleaned up
# across the board.
# -----------------------------------------------------------------
_IMAGES_=$(shell docker images -a --filter=dangling=true -q)
_CONTAINERS_=$(shell docker ps --filter=status=exited --filter=status=created -q)
clean_images : $(addprefix clean_,$(IMAGES))
	@ if [ ! -z "$(_CONTAINERS_)" ]; then docker rm -f $(_CONTAINERS_); fi
	@ if [ ! -z "$(_IMAGES_)" ]; then docker rmi -f $(_IMAGES_); fi

clean_config :
	@ rm -f $(DOCKER_DIR)/xfer/ccf/keys/*.pem $(DOCKER_DIR)/xfer/ccf/etc/*.toml
	@ rm -f $(DOCKER_DIR)/xfer/services/keys/*.pem $(DOCKER_DIR)/xfer/services/etc/*.toml
	@ rm -f $(DOCKER_DIR)/xfer/services/etc/site.psh

clean : clean_images clean_config clean_repository

.PHONY: clean clean_images clean_config clean_repository
.PHONY: build_test test
.PHONY: run_ccf run_client run_services
