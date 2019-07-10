# Copyright 2017 Intel Corporation
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

DOCKER_BUILD_OPTS=
DOCKER_COMPOSE_COMMAND=docker-compose
DOCKER_COMPOSE_FILES=
DOCKER_COMPOSE_OPTS=

# optionally allow local overriding defaults
-include make.loc

DOCKER_COMPOSE_FILES += sawtooth-pdo.yaml sawtooth-pdo.local-code.yaml
ifeq ($(SGX_MODE),HW)
   DOCKER_COMPOSE_FILES += sawtooth-pdo.sgx.yaml
   SGX_DEVICE_PATH=$(shell if [ -e "/dev/isgx" ]; then echo "/dev/isgx"; elif [ -e "/dev/sgx" ]; then echo "/dev/sgx"; else echo "ERROR: NO SGX DEVICE FOUND"; fi)
   DOCKER_COMPOSE_COMMAND := env SGX_DEVICE_PATH=${SGX_DEVICE_PATH} ${DOCKER_COMPOSE_COMMAND}
endif
ifdef http_proxy
   DOCKER_BUILD_OPTS += --build-arg http_proxy=${http_proxy}
   DO_PROXY = 1
endif
ifdef https_proxy
   DOCKER_BUILD_OPTS += --build-arg https_proxy=${https_proxy}
   DO_PROXY = 1
endif
ifdef ftp_proxy
   DOCKER_BUILD_OPTS += --build-arg ftp_proxy=${ftp_proxy}
   DO_PROXY = 1
endif
ifdef no_proxy
   DOCKER_BUILD_OPTS += --build-arg no_proxy=${no_proxy}
   DO_PROXY = 1
endif
ifdef DO_PROXY
   DOCKER_COMPOSE_FILES += sawtooth-pdo.proxy.yaml
endif
ifdef PDO_DEBUG_BUILD
   DOCKER_COMPOSE_FILES += sawtooth-pdo.debugging.yaml
endif
DOCKER_COMPOSE_OPTS += $(foreach cf, $(DOCKER_COMPOSE_FILES), -f $(cf))

all:

pdo-dev-image:
	# sparse lmdb files cause docker to run out of disk space. As we include ..
	# as git root for build of pdo-build docker file, we should  not have run tests
	# inside the default build location
	if [ -x ../build/_dev/opt/pdo/data ]; then \
		echo -e "\n\nWARNING: you have a local "bare-metal" build in ../build/_dev. If that includes lmdb-files, below docker-compose might run out of disk space!!\n\n"; \
	fi
	# unconditionally build, count on docker caching to not rebuild if not necessary
	docker build $(DOCKER_BUILD_OPTS) -f Dockerfile.pdo-dev -t pdo-dev .

pdo-composition: pdo-dev-image
	env PDO_REPO_BRANCH=$$(git rev-parse --abbrev-ref HEAD) $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) build

test: pdo-composition test-with-no-build

test-env-setup: pdo-composition test-env-setup-with-no-build

test-env-setup-with-no-build:
	# just to be on safe side, make sure environment is not still up (e.g.,from previous failed attempt)
	-$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) down
	# - start services
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) up -d
	# MAYBE: test , e.g., with 'ps', whether all services are up properly
	# - insitialize the ledger
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) \
	   exec validator sawset proposal create --url http://rest-api:8008 --key /root/.sawtooth/keys/my_key.priv sawtooth.validator.transaction_families='[{"family": "intkey", "version": "1.0"}, {"family":"sawtooth_settings", "version":"1.0"}, {"family": "pdo_contract_enclave_registry", "version": "1.0"}, {"family":  "pdo_contract_instance_registry", "version": "1.0"}, {"family": "ccl_contract", "version": "1.0"}]'
	if [ "$(SGX_MODE)" = "HW" ]; then \
	   $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) \
	      exec pdo-build bash -c 'source /etc/bash.bashrc; export PDO_SGX_KEY_ROOT=/project/pdo/build/opt/pdo/etc/keys/sgx/; unset PDO_SPID PDO_SPID_API_KEY; source /project/pdo/src/private-data-objects/build/common-config.sh; make -C /project/pdo/src/private-data-objects/build force-conf register'; \
	fi

test-with-no-build: test-env-setup-with-no-build
	# 'sawtooth-pdo.debugging.yaml' doesn't start pdo-tp, so we will have to manually start it
	if [ ! -z "$(PDO_DEBUG_BUILD)" ]; then  \
	   $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) \
	      exec -d pdo-tp bash -c "/project/pdo/src/private-data-objects/sawtooth/bin/pdo-tp -v -v --connect tcp://validator:4004 --debug-on"; \
	fi
	# - run automated tests
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) \
	   exec pdo-build bash -i -c /project/pdo/src/private-data-objects/build/__tools__/run-tests.sh
	# - teardown
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) down


# target to run docker-compose with same files on arbitrary docker-compose command passed as ARGS...
# to pass multiple arguments, you will have to pass it as env-variablse, e.g., "env ARGS='arg1 arg2 arg3' make run"
run:
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS) $(ARGS)
