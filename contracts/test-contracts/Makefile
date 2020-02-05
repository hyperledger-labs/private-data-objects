# Copyright 2018 Intel Corporation
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

PDO_HOME ?= /opt/pdo

SRCDIR?=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOTDIR := $(abspath $(SRCDIR)/../..)
GIPSY_SCHEME := $(ROOTDIR)/contracts/bin/gipsyscheme
INSTALLDIR = $(PDO_HOME)/contracts

CONTRACTS := _mock-contract.scm _mock-contract-bad.scm _key-value-test.scm _memory-test.scm _interface-test.scm
TEST_CONTRACTS := $(addprefix _debug, $(CONTRACTS))

all: $(CONTRACTS)

debug: $(TEST_CONTRACTS)

test:
	@echo No automated tests defined

_mock-contract.scm : mock-contract.bld mock-contract.scm
	$(GIPSY_SCHEME) -1 mock-contract.bld

_debug_mock-contract.scm : mock-contract.bld mock-contract.scm
	$(GIPSY_SCHEME) -1 mock-contract.bld debug

_mock-contract-bad.scm : mock-contract-bad.bld mock-contract-bad.scm
	$(GIPSY_SCHEME) -1 mock-contract-bad.bld

_debug_mock-contract-bad.scm : mock-contract-bad.bld mock-contract-bad.scm
	$(GIPSY_SCHEME) -1 mock-contract-bad.bld debug

_key-value-test.scm : key-value-test.bld key-value-test.scm
	$(GIPSY_SCHEME) -1 key-value-test.bld

_debug_key-value-test.scm : key-value-test.bld key-value-test.scm
	$(GIPSY_SCHEME) -1 key-value-test.bld debug

_memory-test.scm : memory-test.bld memory-test.scm
	$(GIPSY_SCHEME) -1 memory-test.bld

_interface-test.scm : interface-test.bld interface-test.scm
	$(GIPSY_SCHEME) -1 interface-test.bld

_debug_memory-test.scm : memory-test.bld memory-test.scm
	$(GIPSY_SCHEME) -1 memory-test.bld debug

install : $(CONTRACTS)
	@echo copy $(CONTRACTS) to $(INSTALLDIR)
	@mkdir -p $(INSTALLDIR)
	@cp $(CONTRACTS) $(INSTALLDIR)

clean :
	rm -f $(CONTRACTS) $(TEST_CONTRACTS)

.PHONY : all clean debug install test
