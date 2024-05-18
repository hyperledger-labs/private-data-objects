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

# Include local customizations if they are available
-include make.loc

# PDO_SOURCE_ROOT
# The root directory of this checked out source tree.
# Usually, below default should do the "right thing" but if your path
# contains spaces _you will_ have to explicitly pass, e.g. via make.loc,
# the desired PDO_SOURCE_ROOT when invoking make.
PDO_SOURCE_ROOT ?= $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../)

# PDO_DEBUG_BUILD
# The flag that determines the build type (debug or not).
PDO_DEBUG_BUILD ?= 0

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

PDO_VERSION ?= $$( if [ -d repository ]; then cd repository; bin/get_version; else echo "latest"; fi )

# PDO_USER_UID, PDO_GROUP_UID --
#   The UID/GID for the user accounts that will be created in the container; this is
#   important especially when the containers are being used for development; note
#   that the user/group identifiers need to have write access to the xfer directory
PDO_USER_UID ?= $(shell id -u)
PDO_GROUP_UID ?= $(shell id -g)

DOCKER_COMMAND ?= docker
DOCKER_COMPOSE_COMMAND ?= docker-compose
# to work with upstream docker and docker compose plugin, redefine above
# as `DOCKER_COMPOSE_COMMAND=docker compose` in your `make.loc`

DOCKER_DIR = ${PDO_SOURCE_ROOT}/docker
DOCKER_USERNAME = $(LOGNAME)
DOCKER_BUILDARGS += --build-arg UID=$(PDO_USER_UID)
DOCKER_BUILDARGS += --build-arg GID=$(PDO_GROUP_UID)
DOCKER_ARGS = $(DOCKER_BUILDARGS)

IAS_CERTIFICATES=$(DOCKER_DIR)/repository/common/crypto/verify_ias_report/ias-certificates.txt

IMAGES=base client services_base services services_sgx ccf_base ccf

# for the most part this is just used to force rebuild when the
# PDO repository has changed
TIMESTAMP := $(shell /bin/date "+%Y%m%d%H%M%S")

all : $(addprefix build_,$(IMAGES))

rebuild_% : repository
	$(DOCKER_COMMAND) build $(DOCKER_ARGS) \
		--build-arg REBUILD=$(TIMESTAMP) \
		--build-arg PDO_VERSION=$(PDO_VERSION) \
		--tag pdo_$*:$(PDO_VERSION) \
		--file '$(DOCKER_DIR)'/pdo_$*.dockerfile .

build_% : repository
	$(DOCKER_COMMAND) build $(DOCKER_ARGS) \
		--build-arg PDO_VERSION=$(PDO_VERSION) \
		--tag pdo_$*:$(PDO_VERSION) \
		--file '$(DOCKER_DIR)'/pdo_$*.dockerfile .

# overwrite above build rules for SGX-dependent images
rebuild_services_sgx : repository
	$(DOCKER_COMMAND) build $(DOCKER_ARGS) \
		--build-arg REBUILD=$(TIMESTAMP) \
		--build-arg PDO_VERSION=$(PDO_VERSION) \
		--build-arg PDO_DEBUG_BUILD=$(PDO_DEBUG_BUILD) \
		--build-arg SGX_MODE=HW \
		--tag pdo_services_sgx:$(PDO_VERSION) \
		--file $(DOCKER_DIR)/pdo_services.dockerfile .

build_services_sgx : $(IAS_CERTIFICATES) repository build_services_base
	$(DOCKER_COMMAND) build $(DOCKER_ARGS) \
		--build-arg PDO_VERSION=$(PDO_VERSION) \
		--build-arg PDO_DEBUG_BUILD=$(PDO_DEBUG_BUILD) \
		--build-arg SGX_MODE=HW \
		--tag pdo_services_sgx:$(PDO_VERSION) \
		--file $(DOCKER_DIR)/pdo_services.dockerfile .

# docker build dependencies
build_client: build_base
build_services: build_services_base
build_services_base: build_base
build_ccf: build_ccf_base

clean_% :
	$(DOCKER_COMMAND) rmi -f pdo_$*:$(PDO_VERSION)

DOCKER_RUN_ARGS = -v $(DOCKER_DIR)/xfer/:/project/pdo/xfer
DOCKER_RUN_ARGS += --network host

run_ccf : build_ccf stop_ccf
	$(DOCKER_COMMAND) run $(DOCKER_RUN_ARGS) --name ccf_container -P -d pdo_ccf:$(PDO_VERSION)

run_services : build_base build_services_base build_services stop_services
	$(DOCKER_COMMAND) run $(DOCKER_RUN_ARGS) --name services_container -P -d pdo_services:$(PDO_VERSION)

run_client : build_base build_client stop_client
	$(DOCKER_COMMAND) run $(DOCKER_RUN_ARGS) -it --name client_container pdo_client:$(PDO_VERSION) \
		-c "stty cols $$(tput cols) rows $$(tput lines) && bash"

stop_all : stop_ccf stop_services stop_client

stop_ccf :
	- $(DOCKER_COMMAND) rm -f ccf_container

stop_services :
	- $(DOCKER_COMMAND) rm -f services_container

stop_client :
	- $(DOCKER_COMMAND) rm -f client_container

$(IAS_CERTIFICATES) : repository
	# the script prepares the certificates from the source repo
	# and moves only the necessary artifacts to the destination repo (absolute path required)
	$(DOCKER_DIR)/tools/prepare_ias_certificates.sh "$(PDO_SOURCE_ROOT)" $(DOCKER_DIR)/$<

# -----------------------------------------------------------------
# We need a repository with the source for the branch we are going
# to build. In theory this could just be a copy of the local source
# tree but it might contain other artifacts. So instead we clone
# the repository with just a single branch in it. The storage and
# performance requirements are relatively low.
# -----------------------------------------------------------------
repository :
	# clone the repo
	git clone --single-branch --branch $(PDO_BRANCH) --recurse-submodules '$(PDO_REPO)' repository

	# Prepare enclave signing key (if any, this goes in the repo itself).
	# This is effective only in HW mode builds.
	# PDO_SGX_KEY_ROOT is an optional parameter (either set in environment or empty)
	$(DOCKER_DIR)/tools/copy_enclave_signing_key.sh "$(PDO_SOURCE_ROOT)" repository "${PDO_SGX_KEY_ROOT}"

clean_repository :
	rm -rf repository

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

TEST_SGX_FILES = ${TEST_FILES}
TEST_SGX_FILES += -f test-sgx.yaml

SGX_DEVICE_PATH=$(shell if [ -e "/dev/isgx" ]; \
				then echo "/dev/isgx"; \
				elif [ -e "/dev/sgx/enclave" ]; \
					then echo "/dev/sgx/enclave"; \
				else echo "ERROR: NO SGX DEVICE FOUND"; \
				fi)

DOCKER_COMPOSE_SGX := env SGX_DEVICE_PATH=${SGX_DEVICE_PATH} $(DOCKER_COMPOSE_COMMAND)

build_test : repository build_services build_ccf build_client

test : clean_config clean_repository build_test stop_all
	PDO_VERSION=$(PDO_VERSION) $(DOCKER_COMPOSE_COMMAND) $(TEST_FILES) up --abort-on-container-exit
	PDO_VERSION=$(PDO_VERSION) $(DOCKER_COMPOSE_COMMAND) $(TEST_FILES) down

sgx_build_test : repository build_services_sgx build_ccf build_client

sgx_keys :
	# Prepare sgx keys.
	# PDO_SGX_KEY_ROOT is an optional parameter (either set in environment or empty)
	$(DOCKER_DIR)/tools/copy_sgx_keys.sh "$(PDO_SOURCE_ROOT)" "$(DOCKER_DIR)" "${PDO_SGX_KEY_ROOT}"

sgx_test : clean_config clean_repository sgx_build_test stop_all sgx_keys
	PDO_VERSION=$(PDO_VERSION) $(DOCKER_COMPOSE_SGX) $(TEST_SGX_FILES) up --abort-on-container-exit
	PDO_VERSION=$(PDO_VERSION) $(DOCKER_COMPOSE_SGX) $(TEST_SGX_FILES) down

# -----------------------------------------------------------------
# Cleaning is a bit interesting because the containers don't go away
# unless they are told to very nicely. Until they go away they hold onto
# referenced images. Clean make sure that everything is cleaned up
# across the board.
# -----------------------------------------------------------------
_IMAGES_=$(shell $(DOCKER_COMMAND) images -a --filter=dangling=true -q)
_CONTAINERS_=$(shell $(DOCKER_COMMAND) ps --filter=status=exited --filter=status=created -q)
clean_images : $(addprefix clean_,$(IMAGES))
	if [ ! -z "$(_CONTAINERS_)" ]; then $(DOCKER_COMMAND) rm -f $(_CONTAINERS_); fi
	if [ ! -z "$(_IMAGES_)" ]; then $(DOCKER_COMMAND) rmi -f $(_IMAGES_); fi

clean_config :
	rm -f '$(DOCKER_DIR)'/xfer/ccf/keys/*.pem '$(DOCKER_DIR)'/xfer/ccf/etc/*.toml
	rm -f '$(DOCKER_DIR)'/xfer/services/keys/*.pem '$(DOCKER_DIR)'/xfer/services/etc/*.toml
	rm -f '$(DOCKER_DIR)'/xfer/services/keys/sgx/*.pem '$(DOCKER_DIR)'/xfer/services/keys/sgx/*.txt
	# clean the artifacts of the prepare_ias_certificates target
	rm -f $(IAS_CERTIFICATES)

clean : clean_images clean_config clean_repository

.PHONY: clean clean_images clean_config clean_repository
.PHONY: build_test test
.PHONY: sgx_build_test sgx_test sgx_keys
.PHONY: run_ccf run_client run_services

# -----------------------------------------------------------------
# Include additional targets to simplify development inside containers
# -----------------------------------------------------------------
include make.dev
