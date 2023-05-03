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

ifndef PDO_HOME
$(error Incomplete configuration, PDO_HOME is not defined)
endif

ifndef PDO_SOURCE_ROOT
$(error Incomplete configuration, PDO_SOURCE_ROOT is not defined)
endif

WAMR_ROOT=$(PDO_SOURCE_ROOT)/interpreters/wasm-micro-runtime
WAMR_TOOLCHAIN=$(WAMR_ROOT)/wamr-sdk/app/wasi_toolchain.cmake

TEST_LOG_LEVEL ?= warn
TEST_LOG_FILE ?= __screen__
TEST_SERVICE_HOST ?= localhost
TEST_LEDGER ?= http://localhost:6600

## This would point you to the WAMR version of the built in libraries
## WAMR_TOOLCHAIN=$(WAMR_ROOT)/wamr-sdk/app/wamr_toolchain.cmake

all : build
	@ make -C build

clean :
	@echo Remove build directory
	@rm -rf build

debug :
	@echo No debug build defined

test : unit-test

# unit-test does not require an eservice
# we rebuild cmake in case the test configuration has changed
unit-test : install
	@ cmake -S . -B build \
		-DCMAKE_TOOLCHAIN_FILE=$(WAMR_TOOLCHAIN) \
		-DTEST_LOG_LEVEL=$(TEST_LOG_LEVEL) \
		-DTEST_LOG_FILE=$(TEST_LOG_FILE) \
		-DTEST_SERVICE_HOST=$(TEST_SERVICE_HOST)
	@ make -C build test ARGS='-V -R ^unit'

# system-test assumes an eservice is available
# we rebuild cmake in case the test configuration has changed
system-test : install
	@ cmake -S . -B build \
		-DCMAKE_TOOLCHAIN_FILE=$(WAMR_TOOLCHAIN) \
		-DTEST_LOG_LEVEL=$(TEST_LOG_LEVEL) \
		-DTEST_LOG_FILE=$(TEST_LOG_FILE) \
		-DTEST_LEDGER=$(TEST_LEDGER) \
		-DTEST_SERVICE_HOST=$(TEST_SERVICE_HOST)
	@ make -C build test ARGS='-V -R ^system'

install : build
	@ make -C build install

# this is a bit weird because build doesn't actually build the
# packages; build is a directory
build :
	@ cmake -S . -B build \
		-DCMAKE_TOOLCHAIN_FILE=$(WAMR_TOOLCHAIN) \
		-DTEST_LOG_LEVEL=$(TEST_LOG_LEVEL) \
		-DTEST_LOG_FILE=$(TEST_LOG_FILE) \
		-DTEST_LEDGER=$(TEST_LEDGER) \
		-DTEST_SERVICE_HOST=$(TEST_SERVICE_HOST)

.PHONY: test unit-test system-test
.PHONY : all clean debug install test

# Note: build is NOT a phony in this case; we make the directory and
# then build the makefile using cmake. This only needs to be re-done
# if build goes away.
