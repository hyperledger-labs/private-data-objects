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

EGG_FILE = dist/pdo_common_library-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg
PROTOBUF_SOURCE = pdo_contract_ccl.proto pdo_contract_enclave_registry.proto pdo_contract_registry.proto
PROTOBUF_PYTHON = $(subst .proto,_pb2.py,$(PROTOBUF_SOURCE))
PYTHON_SOURCE = $(shell cat MANIFEST)

CRYPTO_SWIG_SOURCE = pdo/common/crypto.i
CRYPTO_SWIG_TARGET = pdo/common/crypto.py
CRYPTO_SWIG_FILES =				\
	pdo/common/crypto.py			\
	pdo/common/crypto_wrap.cpp

KV_SWIG_SOURCE =					\
	pdo/common/key_value_swig/key_value_swig.i	\
	pdo/common/key_value_swig/block_store.h		\
	pdo/common/key_value_swig/block_store.cpp	\
	pdo/common/key_value_swig/key_value.h		\
	pdo/common/key_value_swig/key_value.cpp
KV_SWIG_TARGET = pdo/common/key_value_swig/key_value_swig.py
KV_SWIG_FILES =							\
	pdo/common/key_value_swig/key_value_swig.py		\
	pdo/common/key_value_swig/key_value_swig_wrap.cpp

KEYVAL_LIB = ../common/build/libpdo-lmdb-block-store.a

BUILD_CLIENT ?= 0
ifeq ($(BUILD_CLIENT),1)
	COMMON_LIB = ../common/build/libcpdo-common.a
	CRYPTO_LIB = ../common/build/libcpdo-crypto.a
else
	COMMON_LIB = ../common/build/libupdo-common.a
	CRYPTO_LIB = ../common/build/libupdo-crypto.a
endif

all: $(EGG_FILE)

#$(PROTOBUF_DPATH)%_pb2.py : $(PROTOBUF_SPATH)%.proto
#	protoc --python_out=$(PROTOBUF_DPATH) --proto_path=$(PROTOBUF_SPATH) $<

#$(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON)) : $(addprefix $(PROTOBUF_SPATH),$(PROTOBUF_SOURCE))

#$(EGG_FILE) : $(CRYPTO_SWIG_TARGET) $(KV_SWIG_TARGET) $(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON)) $(PYTHON_SOURCE)
$(EGG_FILE) : $(CRYPTO_SWIG_TARGET) $(KV_SWIG_TARGET) $(PYTHON_SOURCE)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		BUILD_CLIENT=$(BUILD_CLIENT) python3 setup.py bdist_egg

# In the following, we use the pattern rule with multiple targets
# so that make knows that they are created through a single invocation of the target-body
# Without that, when make runs with multiple threads, the target-body is executed
# multiple times, possibly inducing build corruptions
# This pattern rule can be avoided by using grouped targets starting in make 4.3
pdo/common/crypto%py pdo/common/key_value_swig/key_value_swig%py : $(CRYPTO_SWIG_SOURCE) $(KV_SWIG_SOURCE) $(COMMON_LIB) $(CRYPTO_LIB) $(KEYVAL_LIB)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		BUILD_CLIENT=$(BUILD_CLIENT) python3 setup.py build_ext --force
	test -e pdo/common/crypto$*py
	test -e pdo/common/key_value_swig/key_value_swig$*py

install: $(EGG_FILE)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		BUILD_CLIENT=$(BUILD_CLIENT) python3 setup.py install

test: install
	(cd ../common/tests/crypto && python3 test_cryptoWrapper.py)

clean:
	#rm -f $(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON))
	rm -f $(addprefix pdo/common/, crypto.py crypto_wrap.cpp)
	rm -f $(addprefix pdo/common/key_value_swig/, key_value_swig.py key_value_swig_wrap.cpp)
	rm -rf build dist pdo_common_library.egg-info
	find . -iname '*.pyc' -delete
	find . -iname '__pycache__' -delete

.phony : all
.phony : clean
.phony : install
.phony : test
