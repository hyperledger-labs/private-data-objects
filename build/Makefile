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

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DSTDIR ?= $(PDO_INSTALL_ROOT)
SRCDIR ?= $(SCRIPTDIR)/..

KEYGEN=$(abspath $(SCRIPTDIR)/__tools__/make-keys)
CNFGEN=$(abspath $(SCRIPTDIR)/__tools__/expand-config)
BUILD=$(abspath $(SCRIPTDIR)/__tools__/build.sh)
VERIFY=$(abspath $(SCRIPTDIR)/__tools__/verify.sh)
CLEAN=$(abspath $(SCRIPTDIR)/__tools__/clean.sh)
TESTSCRIPT=$(abspath $(SCRIPTDIR)/__tools__/run-tests.sh)

PY_VERSION=${shell python3 --version | sed 's/Python \(3\.[0-9]\).*/\1/'}
PYTHON_DIR=$(DSTDIR)/lib/python$(PY_VERSION)/site-packages/

ifeq ($(SGX_MODE),HW)
all: environment template system-keys verify build keys conf register
else
all: environment template system-keys verify build keys conf
endif

clean : clean-build clean-install

clean-install :
	rm -rf $(DSTDIR)

clean-build : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) ; $(CLEAN)

environment : $(PYTHON_DIR)

$(PYTHON_DIR) : $(DSTDIR)
	virtualenv -p python3 --no-download $(DSTDIR)
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade pip
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade setuptools
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade toml
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade requests
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade colorlog
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade twisted
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade pyyaml
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade google
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade protobuf
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade secp256k1
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade cryptography
	. $(abspath $(DSTDIR)/bin/activate) ; pip install --upgrade pyparsing

$(DSTDIR) :
	mkdir -p $(DSTDIR)

verify :
	$(VERIFY)

build : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) ; $(BUILD)

rebuild : clean-build build

system-keys : ${PDO_ENCLAVE_CODE_SIGN_KEY}

${PDO_ENCLAVE_CODE_SIGN_KEY} :
	openssl genrsa -3 -out ${PDO_ENCLAVE_CODE_SIGN_KEY} 3072

keys : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) ; \
		for i in 1 2 3 4 5 ; do $(KEYGEN) --keyfile $(DSTDIR)/opt/pdo/keys/eservice$${i} --format skf; done
	. $(abspath $(DSTDIR)/bin/activate) ; \
		for i in 1 2 3 4 5 ; do $(KEYGEN) --keyfile $(DSTDIR)/opt/pdo/keys/pservice$${i} --format pem; done
	. $(abspath $(DSTDIR)/bin/activate) ; \
		for i in 1 2 3 4 5 6 7 8 9 10 ; do $(KEYGEN) --keyfile $(DSTDIR)/opt/pdo/keys/user$${i} --format pem; done

conf : $(PYTHON_DIR)
	@ echo Create configuration files from templates
	@ . $(abspath $(DSTDIR)/bin/activate) ; \
		$(CNFGEN) --template eservice.toml --template-directory $(SCRIPTDIR)/opt/pdo/etc/template \
		--output-directory $(DSTDIR)/opt/pdo/etc \
		multiple --file-base eservice --http-base 7100 --count 5
	@ . $(abspath $(DSTDIR)/bin/activate) ; \
		$(CNFGEN) --template pservice.toml --template-directory $(SCRIPTDIR)/opt/pdo/etc/template \
		--output-directory $(DSTDIR)/opt/pdo/etc \
		multiple --file-base pservice --http-base 7000 --count 5
	@ . $(abspath $(DSTDIR)/bin/activate) ; \
		$(CNFGEN) --template enclave.toml --template-directory $(SCRIPTDIR)/opt/pdo/etc/template \
		--output-directory $(DSTDIR)/opt/pdo/etc \
		single --file enclave.toml
	@ . $(abspath $(DSTDIR)/bin/activate) ; \
		$(CNFGEN) --template pcontract.toml --template-directory $(SCRIPTDIR)/opt/pdo/etc/template \
		--output-directory $(DSTDIR)/opt/pdo/etc \
		single --file pcontract.toml

template : $(PYTHON_DIR)
	mkdir -p $(DSTDIR)/opt/pdo/data
	mkdir -p $(DSTDIR)/opt/pdo/etc
	mkdir -p $(DSTDIR)/opt/pdo/etc/keys/sgx
	mkdir -p $(DSTDIR)/opt/pdo/etc/keys/sawtooth
	mkdir -p $(DSTDIR)/opt/pdo/keys
	mkdir -p $(DSTDIR)/opt/pdo/logs

ifeq ($(SGX_MODE),HW)
register : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) ; cd $(SRCDIR)/eservice; ./register_with_ledger.sh

.PHONY : register
endif

test : $(PYTHON_DIR)
	. $(abspath $(DSTDIR)/bin/activate) ; $(TESTSCRIPT)

.PHONY : build clean clean-build clean-install conf environment keys rebuild system-keys template test verify
