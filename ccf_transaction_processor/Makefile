# Copyright 2020 Intel Corporation
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

# SCRIPTDIR defaults to the current directory
# SRCDIR defaults to the parent directory
# CCFDSTDIR defaults /opt/pdo/ccf in PDO_INSTALL_ROOT
# Both can be overridden with environment variables

ifndef PDO_INSTALL_ROOT
$(error Incomplete configuration, PDO_INSTALL_ROOT is not defined)
endif

ifndef SGX_MODE
$(error Incomplete configuration, SGX_MODE is not defined)
endif

ifndef CCF_BASE
$(error Incomplete configuration, CCF_BASE is not defined)
endif


NINJA ?= ninja $(NINJA_OPTIONS)

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CCFDSTDIR ?= $(PDO_INSTALL_ROOT)/opt/pdo/ccf
SRCDIR ?= $(abspath $(SCRIPTDIR)/..)
KEYDIR := $(CCFDSTDIR)/keys/
ETCDIR := $(CCFDSTDIR)/etc/
BINDIR := $(CCFDSTDIR)/bin/
BLDDIR := $(SCRIPTDIR)/build

KEYGEN=$(abspath $(BLDDIR)/keygenerator.sh
CNFGEN=$(abspath $(PDO_SOURCE_ROOT)/build/__tools__/expand-config)

PYTHON_DIR=$(CCFDSTDIR)/lib/python3.7

# this should be determined by SGX_MODE
CCF_MODE=virtual

all: environment keys config install

build: build-ccf build-pdo-tp

build-pdo-tp : $(BLDDIR)
	cd $(BLDDIR) && cmake .. -GNinja \
		-DCCF_DIR=$(CCF_BASE) \
		-DCOMPILE_TARGETS=virtual \
		-DCMAKE_INSTALL_PREFIX=$(CCFDSTDIR)
	cd $(BLDDIR) && $(NINJA)

clean : clean-build clean-install

clean-build:
	rm -rf $(BLDDIR)

clean-install :
	rm -rf $(CCFDSTDIR)

config : $(ETCDIR)/cchost.toml $(ETCDIR)/gov.lua

$(ETCDIR)/cchost.toml : etc/cchost.toml
	@ echo create configuration file for cchost
	@ . $(abspath $(CCFDSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			single --file $(notdir $@)

$(ETCDIR)/gov.lua : etc/gov.lua
	cp etc/gov.lua $(ETCDIR)/gov.lua

environment : $(CCFDSTDIR) $(PYTHON_DIR)

$(BLDDIR) :
	@echo CREATE BUILD DIRECTORY $(BLDDIR)
	mkdir -p $(BLDDIR)

$(CCFDSTDIR) :
	@echo CREATE INSTALLATION DIRECTORY $(CCFDSTDIR)
	mkdir -p $(CCFDSTDIR)
	mkdir -p $(CCFDSTDIR)/keys
	mkdir -p $(CCFDSTDIR)/etc
	mkdir -p $(CCFDSTDIR)/logs
	mkdir -p $(CCFDSTDIR)/run

$(PYTHON_DIR) :
	echo ${PYTHON_DIR}
	virtualenv -p python3.7 --no-download $(CCFDSTDIR)
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade pip
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade setuptools
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade -r $(CCF_BASE)/bin/requirements.txt

install : install-ccf install-pdo-tp

PDO_BASH_SCRIPTS=start_ccf_network.sh start_cchost.sh stop_cchost.sh
PDO_PYTHON_SCRIPTS=configure_ccf_network.py generate_ledger_authority.py fetch_ledger_authority.py

install-pdo-tp : build-pdo-tp
	cd $(BLDDIR) && $(NINJA) install
	mkdir -p $(BINDIR)/lib && cp $(SRCDIR)/bin/lib/common.sh $(BINDIR)/lib/pdo_common.sh
	cp $(addprefix scripts/,$(PDO_BASH_SCRIPTS)) $(BINDIR)
	cp $(addprefix scripts/,$(PDO_PYTHON_SCRIPTS)) $(BINDIR)

keys :
	cd $(KEYDIR) && $(CCF_BASE)/bin/keygenerator.sh --name memberccf --gen-enc-key
	cd $(KEYDIR) && $(CCF_BASE)/bin/keygenerator.sh --name userccf --gen-enc-key

.PHONY : all build build-ccf build-pdo-tp
.PHONY : clean clean-build clean-install
.PHONY : config environment
.PHONY : install install-ccf install-pdo-tp keys
