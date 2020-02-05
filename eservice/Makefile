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

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRCDIR ?= $(abspath $(SCRIPTDIR)/..)

PY_VERSION=${shell python --version | sed 's/Python \([0-9]\.[0-9]\).*/\1/'}
MOD_VERSION=${shell ../bin/get_version}

ifndef SGX_MODE
$(error Incomplete configuration, SGX_MODE is not defined)
endif

ifneq ($(basename ${PY_VERSION}),3)
$(error must be run with python3)
endif

EGG_FILE=dist/pdo_eservice-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg

ENCLAVE_LIB=deps/bin/libpdo-enclave.signed.so

SWIG_SOURCES = \
	pdo_enclave_internal.i\
	swig_utils.cpp \
	enclave/ocall.cpp \
	enclave/base.cpp \
	enclave/contract.cpp \
	enclave/signup.cpp \
	enclave/enclave.cpp \
	enclave_info.cpp \
	signup_info.cpp \
	contract.cpp \
	block_store.cpp
SWIG_FILES = $(addprefix pdo/eservice/enclave/,$(SWIG_SOURCES))
SWIG_TARGET = pdo/eservice/enclave/pdo_enclave_internal.py

PYTHON_FILES = $(shell cat MANIFEST)

SCRIPTS = \
	bin/es-start.sh \
	bin/es-stop.sh \
	bin/es-status.sh \
	bin/ss-start.sh \
	bin/ss-stop.sh \
	bin/ss-status.sh

ENCLAVE_FILES = $(wildcard lib/libpdo_enclave/*.cpp lib/libpdo_enclave/*.h lib/libpdo_enclave/*.edl)
ENCLAVE_FILES += $(wildcard ${SGX_SSL}/include/*.edl)
ENCLAVE_FILES += $(wildcard ${SRCDIR}/common/build/*.a)

all : $(ENCLAVE_LIB) $(EGG_FILE)

$(EGG_FILE) : $(ENCLAVE_LIB) $(SWIG_TARGET) $(PYTHON_FILES) $(SCRIPTS)
	@echo Build Distribution
	python setup.py bdist_egg

$(ENCLAVE_LIB) : build $(ENCLAVE_FILES)
	@echo Build Enclave
	$(MAKE) -C build

$(SWIG_TARGET) : $(SWIG_FILES) $(ENCLAVE_LIB)
	python setup.py build_ext

build :
	mkdir $@
	cd $@ ; cmake .. -G "Unix Makefiles"

install: $(EGG_FILE)
	easy_install $<

# these cannot be run in the current directory because python tries to
# pick up the local versions of the library which do not have the same
# paths as the installed libraries
test:
	@echo run the local secrets and requests tests
	cd tests; python test-secrets.py --logfile __screen__ --loglevel warn
	cd tests; pdo-test-request --no-ledger --iterations 10 --logfile __screen__ --loglevel warn

clean:
	rm -f $(addprefix pdo/eservice/enclave/, pdo_enclave_internal.py pdo_enclave_internal_wrap.cpp)
	rm -rf build deps dist *.egg-info
	find . -iname '*.pyc' -delete
	find . -iname '__pycache__' -delete

print_enclave_files:
	@echo $(ENCLAVE_FILES)


.phony : all
.phony : clean
.phony : enclave
.phone : install
.phony : test
.phony : print_enclave_files
.phony : info
