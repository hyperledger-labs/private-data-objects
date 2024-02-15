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
# Both can be overridden with environment variables

ifndef PDO_INSTALL_ROOT
$(error Incomplete configuration, PDO_INSTALL_ROOT is not defined)
endif

ifndef CCF_BASE
$(error Incomplete configuration, CCF_BASE is not defined)
endif

ifndef PDO_SOURCE_ROOT
$(error Incomplete configuration, PDO_SOURCE_ROOT is not defined)
endif

CCF_COMPILE_TARGET ?= virtual
CCF_VERSION ?= 4.0.1
CCF_LEDGER_DIR ?= $(PDO_INSTALL_ROOT)/opt/pdo/ccf

NINJA ?= ninja $(NINJA_OPTIONS)

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
BLDDIR := $(SCRIPTDIR)/build

all: environment install

# -----------------------------------------------------------------
# There are two environments that need to be created: the PDO
# environment and the ledger environment. This is necessitated by
# the incompatibilities between the client requirements (which requires
# ccf 1.0.19 which is the last python package with the ccf client modules)
# and the ledger requirements (which installs the python modules from
# our current verson of CCF). The client environment may be useful on
# any pdo installation (e.g. ledger ping test makes sense on any client)
# while the ledger environment is only useful where ccf nodes are run
# -----------------------------------------------------------------
environment: pdo-environment ledger-environment

pdo-environment : $(PDO_INSTALL_ROOT)

ledger-environment : $(CCF_LEDGER_DIR)/lib/python3.8

# This directory indicates whether the pdo python virtual
# environment has been created
$(PDO_INSTALL_ROOT) :
	make -C $(PDO_SOURCE_ROOT)/build environment
	make -C $(PDO_SOURCE_ROOT)/bin install

# This directory indicates whether the ccf ledger python
# virtual environment has been created
$(CCF_LEDGER_DIR)/lib/python3.8 : pdo-environment
	mkdir -p $(CCF_LEDGER_DIR)
	mkdir -p $(CCF_LEDGER_DIR)/workspace
	virtualenv -p python3.8 --no-download $(PDO_HOME)/ccf
	$(CCF_LEDGER_DIR)/bin/pip install --upgrade pip
	$(CCF_LEDGER_DIR)/bin/pip install --upgrade -r $(CCF_BASE)/bin/requirements.txt
	$(CCF_LEDGER_DIR)/bin/pip install ccf==$(CCF_VERSION)

# -----------------------------------------------------------------
# build it
# -----------------------------------------------------------------
build : build-pdo-tp

build-pdo-tp : $(BLDDIR)
	cmake --build $(BLDDIR)

$(BLDDIR) :
	cmake -S . -B $(BLDDIR) -GNinja \
		-DCCF_DIR=$(CCF_BASE) \
		-DCOMPILE_TARGET=$(CCF_COMPILE_TARGET) \
		-DCMAKE_INSTALL_PREFIX=$(CCF_LEDGER_DIR)

# -----------------------------------------------------------------
# clean up
# -----------------------------------------------------------------
clean : clean-build clean-ledger

clean-build:
	rm -rf $(BLDDIR)

clean-ledger :
	rm -rf $(CCF_LEDGER_DIR)

# -----------------------------------------------------------------
# install the pdo tp library and scripts in the appropriate
# directories; the library and bash scripts are only necessary
# for running the ledger and go in the ledger directory; the
# python scripts may be useful on any client so they are installed
# in the pdo install root directory where the rest of the pdo
# scripts are installed. future work to move the python scripts
# to an installable wheel file
# -----------------------------------------------------------------

PDO_BASH_SCRIPTS = $(wildcard scripts/*.sh)
PDO_PYTHON_SCRIPTS = $(wildcard scripts/*.py)

install : install-pdo-tp install-pdo-scripts

# cd $(BLDDIR) && $(NINJA) install
install-pdo-tp : ledger-environment build-pdo-tp
	cmake --install $(BLDDIR)
	cp $(PDO_BASH_SCRIPTS) $(CCF_LEDGER_DIR)/bin

install-pdo-scripts : pdo-environment
	cp $(PDO_PYTHON_SCRIPTS) $(PDO_INSTALL_ROOT)/bin

# -----------------------------------------------------------------
.PHONY : all
.PHONY : environment pdo-environment ledger-environment
.PHONY : build build-pdo-tp
.PHONY : clean clean-build clean-ledger
.PHONY : install install-pdo-tp install-pdo-scripts
