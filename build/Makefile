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

# SCRIPTDIR defaults to the current directory
# SRCDIR defaults to the parent directory
# DSTDIR defaults to _dev under the current directory
# Both can be overridden with environment variables

ifndef PDO_INSTALL_ROOT
$(error Incomplete configuration, PDO_INSTALL_ROOT is not defined)
endif

ifndef PDO_SGX_KEY_ROOT
$(error Incomplete configuration, PDO_SGX_KEY_ROOT is not defined)
endif

ifndef SGX_MODE
$(error Incomplete configuration, SGX_MODE is not defined)
endif

ifndef PDO_LEDGER_TYPE
$(error Incomplete configuration, PDO_LEDGER_TYPE is not defined)
endif

ifndef PDO_INTERPRETER
$(error Incomplete configuration, PDO_INTERPRETER is not defined)
endif

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DSTDIR ?= $(PDO_INSTALL_ROOT)
SRCDIR ?= $(abspath $(SCRIPTDIR)/..)

BUILD = $(abspath $(SCRIPTDIR)/__tools__/build.sh)
VERIFY_PRE_BUILD = $(abspath $(SCRIPTDIR)/__tools__/verify-pre-build.sh)
CLEAN = $(abspath $(SCRIPTDIR)/__tools__/clean.sh)
TESTSCRIPT = $(abspath $(SCRIPTDIR)/__tools__/run-tests.sh)
BENCHMARKSCRIPT = $(abspath $(SCRIPTDIR)/__tools__/run-benchmarks.sh)

PY_VERSION = ${shell python3 --version | sed 's/Python \(3\.[0-9]*\)\.[0-9]*/\1/'}
PYTHON_DIR = $(DSTDIR)/lib/python$(PY_VERSION)/site-packages/

ifndef NO_SGX_RUN_DURING_BUILD
  CONDITIONAL_CONF_TARGET = verified-config
  ifeq ($(SGX_MODE),HW)
    CONDITIONAL_REGISTER_TARGET = register
  endif
else
  ifneq ($(SGX_MODE),HW)
    CONDITIONAL_CONF_TARGET = verified-config
  endif
endif

all: environment system-keys verified-build $(CONDITIONAL_CONF_TARGET) $(CONDITIONAL_REGISTER_TARGET)

clean : clean-build clean-install

clean-install :
	rm -rf $(DSTDIR)

clean-build : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(CLEAN)

environment : $(DSTDIR) $(PYTHON_DIR)

$(PYTHON_DIR) : $(DSTDIR)
	virtualenv -p python3 --no-download $(DSTDIR)
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade pip
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade setuptools
	. $(abspath $(DSTDIR)/bin/activate) && pip install -r python_requirements.txt

$(DSTDIR) :
	@echo CREATE INSTALLATION DIRECTORY $(DSTDIR)
	@mkdir -p $(DSTDIR)
	@mkdir -p $(DSTDIR)/opt/pdo/bin
	@mkdir -p $(DSTDIR)/opt/pdo/contracts
	@mkdir -p $(DSTDIR)/opt/pdo/data
	@mkdir -p $(DSTDIR)/opt/pdo/etc
	@mkdir -p $(DSTDIR)/opt/pdo/etc/keys/sgx
	@mkdir -p $(DSTDIR)/opt/pdo/etc/keys/ledger
	@mkdir -p $(DSTDIR)/opt/pdo/keys
	@mkdir -p $(DSTDIR)/opt/pdo/logs

verify-pre-build :
	$(VERIFY_PRE_BUILD)

build : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(BUILD)

verified-build : verify-pre-build
	${MAKE} build

rebuild : clean-build build $(CONDITIONAL_REGISTER_TARGET)

system-keys : ${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem

${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem :
	openssl genrsa -3 -out ${PDO_SGX_KEY_ROOT}/enclave_code_sign.pem 3072

# SERVICES_COUNT is the number of services of each type to create
# First value is the number of eservices, then pservices, then
# sservices, 5 of each is the default
SERVICES_COUNT ?= 5 5 5
SERVICES_CONF_TEMPLATES = $(addprefix $(SCRIPTDIR)/template/, eservice.toml pservice.toml)
SERVICES_CONF_TARGET = $(DSTDIR)/opt/pdo/.services_configured

$(SERVICES_CONF_TARGET) : $(PYTHON_DIR) $(SERVICE_CONF_TEMPLATES)
	. $(abspath $(DSTDIR)/bin/activate) && \
		pdo-configure-services -o $(DSTDIR)/opt/pdo -t $(SCRIPTDIR)/template -c $(SERVICES_COUNT)
	touch $(SERVICES_CONF_TARGET)

config-services : $(SERVICES_CONF_TARGET)

verified-config :
	${MAKE} config

config : config-services config-client

force-config :
	- rm -f $(SERVICES_CONF_TARGET) $(CLIENT_CONF_TARGET)
	${MAKE} config

ifeq ($(SGX_MODE),HW)
register : $(PYTHON_DIR)
	@ echo Register the enclave registration policy on the ledger
	. $(abspath $(DSTDIR)/bin/activate) && $(SRCDIR)/eservice/bin/register-with-ledger.sh

else
register :

endif

client: environment build-client config-client

build-client : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(BUILD) --client

# CLIENT_KEY_COUNT is the number of user keys to create
# For the test environment we create 10 by default
CLIENT_KEY_COUNT ?= 10
CLIENT_CONF_TEMPLATES = $(addprefix $(SCRIPTDIR)/template/, pcontract.toml site.psh)
CLIENT_CONF_TARGET = $(DSTDIR)/opt/pdo/.client_configured

$(CLIENT_CONF_TARGET) : $(PYTHON_DIR) $(CLIENT_CONF_TEMPLATES)
	. $(abspath $(DSTDIR)/bin/activate) && \
		pdo-configure-users -o $(DSTDIR)/opt/pdo -t $(SCRIPTDIR)/template -c $(CLIENT_KEY_COUNT)
	touch $(CLIENT_CONF_TARGET)

config-client : $(CLIENT_CONF_TARGET)

test : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(TESTSCRIPT)

benchmark : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(BENCHMARKSCRIPT)

.PHONY : all environment register system-keys
.PHONY : build rebuild verified-build verify-pre-build
.PHONY : clean clean-build clean-install
.PHONY : config config-services force-config verified-config
.PHONY : client build-client config-client
.PHONY : benchmark test
