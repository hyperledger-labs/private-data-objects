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

ifndef PDO_ENCLAVE_CODE_SIGN_PEM
$(error Incomplete configuration, PDO_ENCLAVE_CODE_SIGN_PEM is not defined)
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

# this is an optional configuration variable to control the
# hostname used in configuration files; we use it here to
# customize the site.psh file; this may be most useful when
# building a client that will connect to services on a
# different/remote host
SERVICE_HOST ?= $(PDO_HOSTNAME)

# splitting out the configuration root in order to make it easier
# to build a separate configuration that can be used with the startup
# scripts; by default the configuration is put into the regular tree
CONFDIR ?= $(DSTDIR)
KEYDIR = $(CONFDIR)/opt/pdo/keys/
ETCDIR = $(CONFDIR)/opt/pdo/etc/

KEYGEN = $(abspath $(SCRIPTDIR)/__tools__/make-keys)
CNFGEN = $(abspath $(SCRIPTDIR)/__tools__/expand-config)
BUILD = $(abspath $(SCRIPTDIR)/__tools__/build.sh)
VERIFY_PRE_BUILD = $(abspath $(SCRIPTDIR)/__tools__/verify-pre-build.sh)
VERIFY_PRE_CONF = $(abspath $(SCRIPTDIR)/__tools__/verify-pre-conf.sh)
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

all: environment template system-keys verified-build keys $(CONDITIONAL_CONF_TARGET) $(CONDITIONAL_REGISTER_TARGET)

clean : clean-build clean-install

clean-install :
	rm -rf $(DSTDIR)

clean-build : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(CLEAN)

environment : $(DSTDIR) $(PYTHON_DIR)

$(PYTHON_DIR) :
	virtualenv -p python3 --no-download $(DSTDIR)
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade pip
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade setuptools
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade toml
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade requests
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade requests_toolbelt
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade colorlog
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade twisted
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade pyyaml
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade google
	. $(abspath $(DSTDIR)/bin/activate) && pip install secp256k1==0.13.2
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade cryptography
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade pyparsing
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade lmdb
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade loguru
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade requests_http_signature
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade websocket-client
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade msgpack
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade ccf==1.0.19
	. $(abspath $(DSTDIR)/bin/activate) && pip install --upgrade mergedeep

$(DSTDIR) :
	@echo CREATE INSTALLATION DIRECTORY $(DSTDIR)
	@mkdir -p $(DSTDIR)
	@mkdir -p $(DSTDIR)/opt/pdo/bin
	@mkdir -p $(DSTDIR)/opt/pdo/contracts
	@mkdir -p $(DSTDIR)/opt/pdo/data
	@mkdir -p $(DSTDIR)/opt/pdo/logs

# these are kept separate so that we can build a service
# configuration from the templates that is different from
# the test configuration
$(KEYDIR) :
	@echo Create the key directory $(KEYDIR)
	@mkdir -p $(KEYDIR)

$(ETCDIR) :
	@echo Create the etc directory $(ETCDIR)
	@mkdir -p $(ETCDIR)
	@mkdir -p $(ETCDIR)/keys/sgx
	@mkdir -p $(ETCDIR)/keys/ledger

verify-pre-build :
	$(VERIFY_PRE_BUILD)

verify-pre-config :
	$(VERIFY_PRE_CONF)

build : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(BUILD)

verified-build : verify-pre-build
	${MAKE} build

rebuild : clean-build build $(CONDITIONAL_REGISTER_TARGET)

system-keys : ${PDO_ENCLAVE_CODE_SIGN_PEM}

${PDO_ENCLAVE_CODE_SIGN_PEM} :
	openssl genrsa -3 -out ${PDO_ENCLAVE_CODE_SIGN_PEM} 3072

service_indexes = 1 2 3 4 5

ifeq ($(PDO_LEDGER_TYPE),ccf)
	ESERVICE_KEYS := $(addprefix $(KEYDIR),$(foreach i,$(service_indexes),eservice$(i)_private.pem))
	ecdsa_curve := secp384r1
endif

SSERVICE_PEM = $(addprefix $(KEYDIR)/,$(foreach i,$(service_indexes),sservice$(i)_private.pem))
PSERVICE_PEM = $(addprefix $(KEYDIR)/,$(foreach i,$(service_indexes),pservice$(i)_private.pem))

user_indexes = 1 2 3 4 5 6 7 8 9 10
USER_PEM = $(addprefix $(KEYDIR)/,$(foreach i,$(user_indexes),user$(i)_private.pem))

%.pem :
	. $(abspath $(DSTDIR)/bin/activate) && $(KEYGEN) --keyfile $(subst _private,,$*) --format pem --curve $(ecdsa_curve)

service-keys : $(KEYDIR) $(ESERVICE_KEYS) $(SSERVICE_PEM) $(PSERVICE_PEM)

user-keys : $(KEYDIR) $(USER_PEM)

keys : service-keys user-keys

ESERVICE_CONF = $(ETCDIR)/eservice1.toml
SSERVICE_CONF = $(ETCDIR)/sservice1.toml
PSERVICE_CONF = $(ETCDIR)/pservice1.toml
ENCLAVE_CONF = $(ETCDIR)/enclave.toml
CONTRACT_CONF = $(ETCDIR)/pcontract.toml

GENERATED_CONF_FILES = $(ESERVICE_CONF) $(SSERVICE_CONF) $(PSERVICE_CONF) $(ENCLAVE_CONF) $(CONTRACT_CONF)

ESERVICE_CONF_TEMPLATE = $(SCRIPTDIR)/opt/pdo/etc/template/eservice.toml

verified-config : verify-pre-config
	${MAKE} config

config : $(ETCDIR) $(GENERATED_CONF_FILES) $(ETCDIR)/site.psh

force-config : verify-pre-config
	- rm -f $(ESERVICE_CONF) $(SSERVICE_CONF) $(PSERVICE_CONF)
	- rm -f  $(ETCDIR)/enclave.toml $(ETCDIR)/pcontract.toml
	- rm -f $(ETCDIR)/site.psh
	${MAKE} config

$(ETCDIR)/site.psh : $(SCRIPTDIR)/opt/pdo/etc/template/site.psh
	@ echo create site.psh
	@ sed "s/SERVICE_HOST/$(SERVICE_HOST)/" $(SCRIPTDIR)/opt/pdo/etc/template/site.psh > $(ETCDIR)/site.psh

$(ESERVICE_CONF) : $(ESERVICE_CONF_TEMPLATE)
	@ echo create configuration files for eservice
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			multiple --file-base eservice --count 5

$(SSERVICE_CONF) : $(SCRIPTDIR)/opt/pdo/etc/template/sservice.toml
	@ echo create configuration files for $(basename $(notdir $<))
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			multiple --file-base $(basename $(notdir $<)) --count 5

$(PSERVICE_CONF) : $(SCRIPTDIR)/opt/pdo/etc/template/pservice.toml
	@ echo create configuration files for $(basename $(notdir $<))
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			multiple --file-base $(basename $(notdir $<)) --count 5

$(ENCLAVE_CONF) : $(SCRIPTDIR)/opt/pdo/etc/template/enclave.toml
	@ echo create configuration files for $(basename $(notdir $<))
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			single --file $(notdir $@)

$(CONTRACT_CONF) : $(SCRIPTDIR)/opt/pdo/etc/template/pcontract.toml
	@ echo create configuration files for $(basename $(notdir $<))
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		$(CNFGEN) --template $(notdir $<) --template-directory $(dir $<) \
			--output-directory $(dir $@) \
			single --file $(notdir $@)

template : $(DSTDIR) $(ETCDIR) $(KEYDIR)

ifeq ($(SGX_MODE),HW)
register : $(PYTHON_DIR)
	@ echo registering enclave and IAS public key on the ledger
	. $(abspath $(DSTDIR)/bin/activate) && $(SRCDIR)/eservice/bin/register-with-ledger.sh

else
register :

endif

client: environment template build-client config-client

build-client : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(BUILD) --client

config-client : $(CONTRACT_CONF) $(USER_PEM) $(ETCDIR)/site.psh

test : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(TESTSCRIPT)

benchmark : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) && $(BENCHMARKSCRIPT)

.PHONY : all build verified-build clean clean-build clean-install config verified-config environment
.PHONY : install rebuild template test verify-pre-build verify-pre-config
.PHONY : client build-client config-client
.PHONY : keys service-keys system-keys user-keys
.PHONY : register
