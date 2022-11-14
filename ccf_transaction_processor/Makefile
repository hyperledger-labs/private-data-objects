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

ifndef PDO_LEDGER_KEY_ROOT
$(error Incomplete configuration, PDO_LEDGER_KEY_ROOT is not defined)
endif

ifndef CCF_BASE
$(error Incomplete configuration, CCF_BASE is not defined)
endif


NINJA ?= ninja $(NINJA_OPTIONS)

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CCFDSTDIR ?= $(PDO_INSTALL_ROOT)/opt/pdo/ccf
SRCDIR ?= $(abspath $(SCRIPTDIR)/..)
KEYDIR := $(PDO_LEDGER_KEY_ROOT)
ETCDIR := $(CCFDSTDIR)/etc/
BINDIR := $(CCFDSTDIR)/bin/
BLDDIR := $(SCRIPTDIR)/build

KEYGEN=$(abspath $(BLDDIR)/keygenerator.sh
CNFGEN=$(abspath $(PDO_SOURCE_ROOT)/build/__tools__/expand-config)

PYTHON_DIR=$(CCFDSTDIR)/lib/python3.8

COMPILE_TARGET=virtual

all: environment keys config install

build: build-ccf build-pdo-tp

build-pdo-tp : $(BLDDIR)
	cd $(BLDDIR) && cmake .. -GNinja \
		-DCCF_DIR=$(CCF_BASE) \
		-DCOMPILE_TARGETS=$(COMPILE_TARGET) \
		-DLVI_MITIGATIONS=OFF \
		-DCMAKE_INSTALL_PREFIX=$(CCFDSTDIR)
	cd $(BLDDIR) && $(NINJA)

clean : clean-build clean-install

clean-build:
	rm -rf $(BLDDIR)

clean-install :
	rm -rf $(CCFDSTDIR)

config : $(ETCDIR)/cchost.toml $(ETCDIR)/constitution.js

$(ETCDIR)/cchost.toml : etc/cchost.toml
	@ echo create configuration file for cchost
	@ . $(abspath $(CCFDSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			single --file $(notdir $@)

$(ETCDIR)/constitution.js : etc/constitution.js
	cp etc/constitution.js $(ETCDIR)/constitution.js

environment : $(CCFDSTDIR) $(PYTHON_DIR)

$(BLDDIR) :
	@echo CREATE BUILD DIRECTORY $(BLDDIR)
	mkdir -p $(BLDDIR)

$(CCFDSTDIR) :
	@echo CREATE INSTALLATION DIRECTORY $(CCFDSTDIR)
	mkdir -p $(CCFDSTDIR)
	mkdir -p $(CCFDSTDIR)/logs
	mkdir -p $(CCFDSTDIR)/run
	mkdir -p $(ETCDIR)
	mkdir -p $(KEYDIR)

$(PYTHON_DIR) :
	echo ${PYTHON_DIR}
	virtualenv -p python3.8 --no-download $(CCFDSTDIR)
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade pip
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade setuptools
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade -r $(CCF_BASE)/bin/requirements.txt
	. $(abspath $(CCFDSTDIR)/bin/activate) && pip install --upgrade ccf==1.0.19 toml

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

.PHONY : all build build-ccf build-pdo-tp
.PHONY : clean clean-build clean-install
.PHONY : config environment
.PHONY : install install-ccf install-pdo-tp keys
