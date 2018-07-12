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

PY_VERSION=${shell python3 --version | sed 's/Python \(3\.[0-9]\).*/\1/'}
MOD_VERSION=${shell ../bin/get_version}

EGG_FILE=dist/pdo_eservice-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg

ENCLAVE_LIB=deps/bin/libpdo-enclave.signed.so

SWIG_SOURCES = \
	pdo_enclave_internal.i\
	log.cpp \
	swig_utils.cpp \
	enclave/ocall.cpp \
	enclave/base.cpp \
	enclave/contract.cpp \
	enclave/signup.cpp \
	enclave/enclave.cpp \
	enclave_info.cpp \
	signup_info.cpp \
	contract.cpp
SWIG_FILES = $(addprefix pdo/eservice/enclave/,$(SWIG_SOURCES))
SWIG_TARGET = pdo/eservice/enclave/pdo_enclave_internal.py

PYTHON_FILES = \
	pdo/eservice/enclave/pdo_enclave_internal.py \
	pdo/eservice/pdo_helper.py \
	pdo/eservice/enclave/__init__.py \
	pdo/eservice/pdo_helper.py \
	pdo/eservice/scripts/EServiceCLI.py \
	pdo/eservice/scripts/__init__.py \
	pdo/eservice/pdo_enclave.py \
	pdo/eservice/__init__.py \
	pdo/eservice/utility/ias_client.py \
	pdo/eservice/utility/__init__.py \
	pdo/__init__.py

ENCLAVE_FILES = $(wildcard lib/libpdo_enclave/*.cpp lib/libpdo_enclave/*.h lib/libpdo_enclave/*.edl)

all : $(ENCLAVE_LIB) $(EGG_FILE)

$(EGG_FILE) : $(ENCLAVE_LIB) $(SWIG_TARGET) $(PYTHON_FILES)
	@echo Build Distribution
	python setup.py bdist_egg

$(ENCLAVE_LIB) : build $(ENCLAVE_FILES)
	@echo Build Enclave
	$(MAKE) -C build

$(SWIG_TARGET) : $(SWIG_FILES)
	python setup.py build_ext

build :
	mkdir $@
	cd $@ ; cmake .. -G "Unix Makefiles"

install: $(EGG_FILE)
	easy_install $<

test: install
	(cd tests; python test-secrets.py)
	(cd tests; python test-request.py)

clean:
	rm -f $(addprefix pdo/eservice/enclave/, pdo_enclave_internal.py pdo_enclave_internal_wrap.cpp)
	rm -rf build deps dist *.egg-info
	find . -iname '*.pyc' -delete
	find . -iname '__pycache__' -delete

.phony : all
.phony : clean
.phony : enclave
.phone : install
.phony : test
