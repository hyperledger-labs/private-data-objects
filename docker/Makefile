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
DOCKER_COMPOSE_FILES_STL=
DOCKER_COMPOSE_FILES_CCF=
DOCKER_COMPOSE_OPTS_STL=
DOCKER_COMPOSE_OPTS_CCF=

# optionally allow local overriding defaults
-include make.loc

DOCKER_COMPOSE_FILES_STL += sawtooth-pdo.yaml sawtooth-pdo.local-code.yaml
DOCKER_COMPOSE_FILES_CCF += ccf-pdo.yaml ccf-pdo.local-code.yaml
DOCKER_COMPOSE_FILES_CCF_ONLY += ccf.yaml ccf.local-code.yaml

ifeq ($(SGX_MODE),HW)
   DOCKER_COMPOSE_FILES_STL += sawtooth-pdo.sgx.yaml
   SGX_DEVICE_PATH=$(shell if [ -e "/dev/isgx" ]; then echo "/dev/isgx"; elif [ -e "/dev/sgx/enclave" ]; then echo "/dev/sgx/enclave"; else echo "ERROR: NO SGX DEVICE FOUND"; fi)
   DOCKER_COMPOSE_COMMAND := env SGX_DEVICE_PATH=${SGX_DEVICE_PATH} ${DOCKER_COMPOSE_COMMAND}
endif
ifdef http_proxy
   DO_PROXY = 1
endif
ifdef https_proxy
   DO_PROXY = 1
endif
ifdef ftp_proxy
   DO_PROXY = 1
endif
ifdef no_proxy
   DO_PROXY = 1
endif
ifdef DO_PROXY
   DOCKER_COMPOSE_FILES_STL += sawtooth-pdo.proxy.yaml
   DOCKER_COMPOSE_FILES_CCF += ccf-pdo.proxy.yaml
   DOCKER_COMPOSE_FILES_CCF_ONLY += ccf.proxy.yaml
endif
ifdef PDO_DEBUG_BUILD
   DOCKER_COMPOSE_FILES_STL += sawtooth-pdo.debugging.yaml
endif

DOCKER_COMPOSE_OPTS_STL += $(foreach cf, $(DOCKER_COMPOSE_FILES_STL), -f $(cf))
DOCKER_COMPOSE_OPTS_CCF += $(foreach cf, $(DOCKER_COMPOSE_FILES_CCF), -f $(cf))
DOCKER_COMPOSE_OPTS_CCF_ONLY += $(foreach cf, $(DOCKER_COMPOSE_FILES_CCF_ONLY), -f $(cf))

all:

pdo-dev-image:
	# unconditionally build, count on docker caching to not rebuild if not necessary
	docker build $(DOCKER_BUILD_OPTS) -f Dockerfile.pdo-dev -t pdo-dev .

pdo-composition: pdo-dev-image
	env PDO_REPO_BRANCH=$$(git rev-parse --abbrev-ref HEAD) $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) build
	# Note:
	# - using `sawtooth-pdo.local-code.yaml` in above will cause the docker context to be `../`.
	#   To make sure that we do not pull in (too much) unnecessary stuff, we explicitly excludes
	#   various files/dirs in `../.dockerignore`.
	#   There are two negative effect for not excluding enough
	#   - if some non-essential file changed (e.g., build artificats on host which are
	#     all not needed in docker), docker caching might not work well and docker will rebuild
	#     layers even though it could have cached (and hence run faster).
	#   - the the build-time layer will become unecessarily big (note: as we do multi-stage, the size of
	#     of the built container image should not be affected). This is in particular an issue with lmdb
	#     files which are created by tests in default location ../build/_dev. These files are
	#     sparse but docker expands to them to their nominal size (several gb) and could cause
	#     running out of disk space during the build...

pdo-composition-ccf: pdo-dev-image
	env PDO_REPO_BRANCH=$$(git rev-parse --abbrev-ref HEAD) $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF) build

ccf-only:
	env PDO_REPO_BRANCH=$$(git rev-parse --abbrev-ref HEAD) $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF_ONLY) build


test-stl: pdo-composition test-with-no-build
test-ccf: pdo-composition-ccf test-with-no-build-ccf
test: test-stl test-ccf

test-env-setup: pdo-composition test-env-setup-with-no-build
test-env-setup-ccf: pdo-composition-ccf test-env-setup-with-no-build-ccf
test-env-setup-ccf-only: ccf-only test-env-setup-with-no-build-ccf-only

test-env-setup-with-no-build:
	# just to be on safe side, make sure environment is not still up (e.g.,from previous failed attempt)
	-$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) down
	# - start services
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) up -d
	# MAYBE: test , e.g., with 'ps', whether all services are up properly
	# - insitialize the ledger
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) \
	   exec -T validator sawset proposal create --url http://rest-api:8008 --key /root/.sawtooth/keys/my_key.priv sawtooth.validator.transaction_families='[{"family": "intkey", "version": "1.0"}, {"family":"sawtooth_settings", "version":"1.0"}, {"family": "pdo_contract_enclave_registry", "version": "1.0"}, {"family":  "pdo_contract_instance_registry", "version": "1.0"}, {"family": "ccl_contract", "version": "1.0"}]'
	if [ "$(SGX_MODE)" = "HW" ]; then \
	   $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) \
	      exec -T pdo-build bash -c 'source /etc/bash.bashrc && export PDO_SGX_KEY_ROOT=/project/pdo/build/opt/pdo/etc/keys/sgx/ && unset PDO_SPID PDO_SPID_API_KEY PDO_HOSTNAME && source /project/pdo/src/private-data-objects/build/common-config.sh && make -C /project/pdo/src/private-data-objects/build force-conf register'; \
	fi

test-env-setup-with-no-build-ccf-only:
	# just to be on safe side, make sure environment is not still up (e.g.,from previous failed attempt)
	-$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF_ONLY) down
	# - start services
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF_ONLY) up -d

test-env-setup-with-no-build-ccf:
	# just to be on safe side, make sure environment is not still up (e.g.,from previous failed attempt)
	-$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF) down
	# - start services
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF) up -d

test-with-no-build: test-env-setup-with-no-build
	# 'sawtooth-pdo.debugging.yaml' doesn't start pdo-tp, so we will have to manually start it
	if [ ! -z "$(PDO_DEBUG_BUILD)" ]; then  \
	   $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) \
	      exec -T -d pdo-tp bash -c "/project/pdo/src/private-data-objects/sawtooth/bin/pdo-tp -v -v --connect tcp://validator:4004 --debug-on"; \
	fi
	# - run automated tests
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) \
	   exec -T pdo-build bash -i -c /project/pdo/src/private-data-objects/build/__tools__/run-tests.sh
	# - teardown
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) down


test-with-no-build-ccf: test-env-setup-with-no-build-ccf
	# - run automated tests
	# the pdo container must add the ip address of the pdo-tp-ccf container to its no proxy list (if behind a proxy)
	if [ ! -z "$(no_proxy)" ]; then \
	   $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF)  exec -T pdo-build bash -i -c "source /set_no_proxy.sh && /project/pdo/build/opt/pdo/etc/keys/ledger/check-for-ccf-keys.sh && /project/pdo/src/private-data-objects/build/__tools__/run-tests.sh"; \
	else \
	   $(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF)  exec -T pdo-build bash -i -c "/project/pdo/build/opt/pdo/etc/keys/ledger/check-for-ccf-keys.sh && /project/pdo/src/private-data-objects/build/__tools__/run-tests.sh"; \
	fi

	# remove ccf keys from local folder
	rm ccf_keys/networkcert.pem

	# - teardown
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF) down

# target to run docker-compose with same files on arbitrary docker-compose command passed as ARGS...
# to pass multiple arguments, you will have to pass it as env-variablse, e.g., "env ARGS='arg1 arg2 arg3' make run"
run-stl:
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_STL) $(ARGS)

run-ccf:
	$(DOCKER_COMPOSE_COMMAND) $(DOCKER_COMPOSE_OPTS_CCF) $(ARGS)
