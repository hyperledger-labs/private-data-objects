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
EXTENSIONPATH := $(ROOTDIR)/common/build
INSTALLDIR = $(PDO_HOME)/contracts

CONTRACTS := _mock-contract.scm _mock-contract-bad.scm _key-value-test.scm _memory-test.scm
DEBUGCONTRACTS := $(addprefix _debug, $(CONTRACTS))

all: $(CONTRACTS)

debug : $(DEBUGCONTRACTS)

_mock-contract.scm : mock-contract.bld mock-contract.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 mock-contract.bld

_debug_mock-contract.scm : mock-contract.bld mock-contract.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 mock-contract.bld debug

_mock-contract-bad.scm : mock-contract-bad.bld mock-contract-bad.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 mock-contract-bad.bld

_debug_mock-contract-bad.scm : mock-contract-bad.bld mock-contract-bad.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 mock-contract-bad.bld debug

_key-value-test.scm : key-value-test.bld key-value-test.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 key-value-test.bld

_debug_key-value-test.scm : key-value-test.bld key-value-test.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 key-value-test.bld debug

_memory-test.scm : memory-test.bld memory-test.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 memory-test.bld

install : $(CONTRACTS)
	@echo copy $(CONTRACTS) to $(INSTALLDIR)
	@mkdir -p $(INSTALLDIR)
	@cp $(CONTRACTS) $(INSTALLDIR)

clean :
	rm -f $(CONTRACTS) $(DEBUGCONTRACTS)

.PHONY : all debug clean install
