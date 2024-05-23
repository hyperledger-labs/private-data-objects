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
DSTDIR ?= $(PDO_INSTALL_ROOT)

PY_VERSION=${shell python3 --version | sed 's/Python \(3\.[0-9]*\)\.[0-9]*/\1/'}
MOD_VERSION=${shell ../bin/get_version}

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
	bin/es-status.sh

TEST_LOG_LEVEL ?= warn
TEST_LOG_FILE ?= __screen__

all : $(ENCLAVE_LIB) $(EGG_FILE)

$(EGG_FILE) : $(ENCLAVE_LIB) $(SWIG_TARGET) $(PYTHON_FILES) $(SCRIPTS)
	@echo Build Distribution
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python3 setup.py bdist_egg

$(ENCLAVE_LIB) : build
	@echo Build Enclave
	cmake --build build

$(SWIG_TARGET) : $(SWIG_FILES) $(ENCLAVE_LIB)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python3 setup.py build_ext

build :
	mkdir $@
	cd $@ && cmake .. $(CMAKE_ARGS) -G "Unix Makefiles"

install: $(EGG_FILE)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python3 setup.py install

# these cannot be run in the current directory because python tries to
# pick up the local versions of the library which do not have the same
# paths as the installed libraries
test:
	@echo run the local secrets and requests tests
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		cd tests && python3 test-secrets.py --logfile $(TEST_LOG_FILE) --loglevel $(TEST_LOG_LEVEL)
	cd tests && pdo-test-request --no-ledger --iterations 10 --logfile $(TEST_LOG_FILE) --loglevel $(TEST_LOG_LEVEL)

clean:
	@ echo Remove build directory
	@ if [ -d build ]; then \
		make -C build clean; \
		rm -rf build deps dist *.egg-info ; \
	fi
	@ echo clean swig files
	@ rm -f $(addprefix pdo/eservice/enclave/, pdo_enclave_internal.py pdo_enclave_internal_wrap.cpp)
	@ echo Clean up python caches
	@ find . -iname '*.pyc' -delete
	@ find . -iname '__pycache__' -delete

print_enclave_files:
	@echo $(ENCLAVE_FILES)


.phony : all
.phony : clean
.phony : enclave
.phone : install
.phony : test
.phony : print_enclave_files
.phony : info
