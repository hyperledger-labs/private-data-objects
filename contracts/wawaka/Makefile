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

WAMR_ROOT=${PDO_SOURCE_ROOT}/interpreters/wasm-micro-runtime
WAMR_TOOLCHAIN=$(WAMR_ROOT)/wamr-sdk/app/wasi_toolchain.cmake

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

test : install interface-test interpreter-test memory-test mock-contract-test

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

.PHONY: test interface-test mock-contract-test interpreter-test memory-test

install : build
	@echo install contracts
	@cd build && make install

build :
	mkdir -p $@
	cd $@ && cmake .. -DCMAKE_TOOLCHAIN_FILE=$(WAMR_TOOLCHAIN)

.PHONY : all clean debug install test
