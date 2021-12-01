# Copyright 2019 Intel Corporation
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

ifndef PDO_INSTALL_ROOT
$(error Incomplete configuration, PDO_INSTALL_ROOT is not defined)
endif

ifndef PDO_INTERPRETER
$(error Incomplete configuration, PDO_INTERPRETER is not defined)
endif

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DSTDIR ?= $(PDO_INSTALL_ROOT)

WAMR_ROOT=$(PDO_SOURCE_ROOT)/interpreters/wasm-micro-runtime
WAMR_TOOLCHAIN=$(WAMR_ROOT)/wamr-sdk/app/wasi_toolchain.cmake

PLUGIN_INSTALL_DIR ?= $(PDO_HOME)/contracts/plugins
PLUGIN_SOURCE=$(wildcard $(SCRIPTDIR)/*/plugins/*.py)

SCRIPT_INSTALL_DIR ?= $(PDO_HOME)/bin
SCRIPT_SOURCE=$(wildcard $(SCRIPTDIR)/*/scripts/*.psh)

DATA_DIR ?= $(PDO_HOME)/data

TEST_LOG_LEVEL ?= warn
TEST_LOG_FILE ?= /dev/null

## This would point you to the WAMR version of the built in libraries
## WAMR_TOOLCHAIN=$(WAMR_ROOT)/wamr-sdk/app/wamr_toolchain.cmake

all : build
	@cd build && make all

clean :
	@echo Remove build directory
	@rm -rf build

debug :
	@echo No debug build defined

# this is the unit test target, these tests can run without eservice running
test : install interface-test interpreter-test memory-test mock-contract-test

# this is the system test target, these tests require an eservice
system-test : install eservice-db attestation-test

ESERVICE_DB=$(DATA_DIR)/eservice-test-db.json
eservice-db:
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		pdo-eservicedb --loglevel $(TEST_LOG_LEVEL) -d $(ESERVICE_DB) reset --create && \
		pdo-eservicedb --loglevel $(TEST_LOG_LEVEL) -d $(ESERVICE_DB) add -u http://localhost:7101 -n es7101 && \
		pdo-eservicedb --loglevel $(TEST_LOG_LEVEL) -d $(ESERVICE_DB) add -u http://localhost:7102 -n es7102 && \
		pdo-eservicedb --loglevel $(TEST_LOG_LEVEL) -d $(ESERVICE_DB) add -u http://localhost:7103 -n es7103 && \
		pdo-eservicedb --loglevel $(TEST_LOG_LEVEL) -d $(ESERVICE_DB) add -u http://localhost:7104 -n es7104 && \
		pdo-eservicedb --loglevel $(TEST_LOG_LEVEL) -d $(ESERVICE_DB) add -u http://localhost:7105 -n es7105

interface-test:
	@echo run test: $@
	@ . $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger \
		--loglevel $(TEST_LOG_LEVEL) --logfile $(TEST_LOG_FILE) \
		--contract $@ \
		--expressions ${SCRIPTDIR}/$@/test-short.json

interpreter-test:
	@echo run test: $@
	@ . $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger \
		--loglevel $(TEST_LOG_LEVEL) --logfile $(TEST_LOG_FILE) \
		--contract $@ \
		--expressions ${SCRIPTDIR}/$@/test-short.json

memory-test:
	@echo run test: $@
	@ . $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger \
		--loglevel $(TEST_LOG_LEVEL) --logfile $(TEST_LOG_FILE) \
		--contract $@ \
		--expressions ${SCRIPTDIR}/$@/test-short.json

mock-contract-test :
	@echo run test: $@
	@ . $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger \
		--loglevel $(TEST_LOG_LEVEL) --logfile $(TEST_LOG_FILE) \
		--contract mock-contract \
		--expressions ${SCRIPTDIR}/mock-contract/test-short.json

attestation-test:
	@echo run test: $@
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		cd attestation-test && \
		scripts/attestation-test.psh --loglevel $(TEST_LOG_LEVEL) --logfile $(TEST_LOG_FILE) \
			-m eservice_dbfile $(ESERVICE_DB) \
			-m test_data $(SCRIPTDIR)/attestation-test/scripts

.PHONY: test interface-test mock-contract-test interpreter-test memory-test
.PHONY: system-test eservice-db attestation-test

install : build
	@echo install contracts
	@cd build && make install
	@mkdir -p $(PLUGIN_INSTALL_DIR); cp $(PLUGIN_SOURCE) $(PLUGIN_INSTALL_DIR)
	@mkdir -p $(SCRIPT_INSTALL_DIR); cp $(SCRIPT_SOURCE) $(SCRIPT_INSTALL_DIR)

build :
	mkdir -p $@
	cd $@ && cmake .. -DCMAKE_TOOLCHAIN_FILE=$(WAMR_TOOLCHAIN)

.PHONY : all clean debug install test
