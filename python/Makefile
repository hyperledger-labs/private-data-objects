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

ifndef PDO_INSTALL_ROOT
$(error Incomplete configuration, PDO_INSTALL_ROOT is not defined)
endif

ifndef PDO_INTERPRETER
$(error Incomplete configuration, PDO_INTERPRETER is not defined)
endif

SCRIPTDIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
DSTDIR ?= $(PDO_INSTALL_ROOT)

PY_VERSION=${shell python3 --version | sed 's/Python \(3\.[0-9]*\)\.[0-9]*/\1/'}
MOD_VERSION=${shell ../bin/get_version}

EGG_FILE = dist/pdo_common_library-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg
PROTOBUF_DPATH = pdo/submitter/sawtooth/pdo_protos/
PROTOBUF_SPATH = pdo/submitter/sawtooth/pdo_protos/protobufs/
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

COMMON_LIB = ../common/build/libupdo-common.a

all: $(EGG_FILE)

$(PROTOBUF_DPATH)%_pb2.py : $(PROTOBUF_SPATH)%.proto
	protoc --python_out=$(PROTOBUF_DPATH) --proto_path=$(PROTOBUF_SPATH) $<

$(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON)) : $(addprefix $(PROTOBUF_SPATH),$(PROTOBUF_SOURCE))

$(EGG_FILE) : $(CRYPTO_SWIG_TARGET) $(KV_SWIG_TARGET) $(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON)) $(PYTHON_SOURCE)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python setup.py bdist_egg

$(CRYPTO_SWIG_TARGET) $(KV_SWIG_TARGET) : $(CRYPTO_SWIG_SOURCE) $(KV_SWIG_SOURCE) $(COMMON_LIB)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python setup.py build_ext --force

install: $(EGG_FILE)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python setup.py install

test: install
	(cd ../common/tests/crypto && python test_cryptoWrapper.py)

clean:
	rm -f $(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON))
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python setup.py clean --all

.phony : all
.phony : clean
.phony : install
.phony : test
