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

EGG_FILE=dist/pdo_pservice-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg

ENCLAVE_LIB=deps/bin/libpdo-enclave.signed.so

SWIG_SOURCES = \
	pdo_enclave_internal.i\
	swig_utils.cpp \
	enclave/ocall.cpp \
	enclave/base.cpp \
	enclave/enclave.cpp \
	enclave/secret.cpp \
	enclave_info.cpp \
	secret_info.cpp
SWIG_FILES = $(addprefix pdo/pservice/enclave/,$(SWIG_SOURCES))
SWIG_TARGET = pdo/pservice/enclave/pdo_enclave_internal.py

SCRIPTS = \
	bin/ps-start.sh \
	bin/ps-stop.sh \
	bin/ps-status.sh

PYTHON_FILES = \
	pdo/pservice/enclave/__init__.py \
	pdo/pservice/pdo_helper.py \
	pdo/pservice/scripts/PServiceCLI.py \
	pdo/pservice/scripts/__init__.py \
	pdo/pservice/pdo_enclave.py \
	pdo/pservice/__init__.py \
	pdo/pservice/utility/ias_client.py \
	pdo/pservice/utility/__init__.py \
	pdo/__init__.py

CONTRACT_ENCLAVE_MRENCLAVE_C_FILE = lib/libpdo_enclave/contract_enclave_mrenclave.cpp
CONTRACT_ENCLAVE_MRENCLAVE_TEMPLATE_FILE = lib/libpdo_enclave/contract_enclave_mrenclave.cpp.template
CONTRACT_ENCLAVE_MRENCLAVE_META_FILE = ../eservice/build/lib/libpdo-enclave.signed.so.meta
ENCLAVE_FILES = $(CONTRACT_ENCLAVE_MRENCLAVE_C_FILE) $(wildcard lib/libpdo_enclave/*.cpp lib/libpdo_enclave/*.h lib/libpdo_enclave/*.edl)

all : $(ENCLAVE_LIB) $(EGG_FILE)

$(EGG_FILE) : $(ENCLAVE_LIB) $(SWIG_TARGET) $(PYTHON_FILES) $(SCRIPTS)
	@echo Build Distribution
	python setup.py bdist_egg

$(CONTRACT_ENCLAVE_MRENCLAVE_C_FILE): $(CONTRACT_ENCLAVE_MRENCLAVE_TEMPLATE_FILE) $(CONTRACT_ENCLAVE_MRENCLAVE_META_FILE)
	VAR_MRENCLAVE=$$(perl -0777 -ne 'if (/metadata->enclave_css.body.enclave_hash.m:([a-fx0-9 \n]+)/) { $$eh = $$1; $$eh=~s/0x| |\n//g; $$eh=~tr/a-z/A-Z/; print "$${eh}\n"; }' $(CONTRACT_ENCLAVE_MRENCLAVE_META_FILE)) && \
	sed "s/MR_ENCLAVE_PLACEMARK/$${VAR_MRENCLAVE}/" $(CONTRACT_ENCLAVE_MRENCLAVE_TEMPLATE_FILE) > $(CONTRACT_ENCLAVE_MRENCLAVE_C_FILE)

$(ENCLAVE_LIB) : build $(ENCLAVE_FILES)
	@echo Build Enclave
	$(MAKE) -C build

$(SWIG_TARGET) : $(SWIG_FILES)
	python setup.py build_ext

build :
	mkdir $@
	cd $@ && cmake .. -G "Unix Makefiles"

install: $(EGG_FILE)
	python setup.py install

clean:
	rm -f $(addprefix pdo/pservice/enclave/, pdo_enclave_internal.py pdo_enclave_internal_wrap.cpp)
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
