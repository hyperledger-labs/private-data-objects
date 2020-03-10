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

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DSTDIR ?= $(PDO_INSTALL_ROOT)

all : build
	@cd build; make all

clean :
	@echo Remove build directory
	@rm -rf build

debug :
	@echo No debug build defined

test :
	. $(abspath $(DSTDIR)/bin/activate) ; pdo-test-contract --no-ledger --contract interface-test --expressions ${SCRIPTDIR}/interface-test/test-short.json
	. $(abspath $(DSTDIR)/bin/activate) ; pdo-test-contract --no-ledger --contract mock-contract --expressions ${SCRIPTDIR}/mock-contract/test-short.json
	. $(abspath $(DSTDIR)/bin/activate) ; pdo-test-contract --no-ledger --contract interpreter-test --expressions ${SCRIPTDIR}/interpreter-test/test-short.json


install : build
	@echo install contracts
	@cd build; make install

build :
	mkdir $@
	cd $@ ; emcmake cmake ..

.PHONY : all clean debug install test
