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

EGG_FILE = dist/pdo_common_library-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg
PROTOBUF_DPATH = pdo/submitter/sawtooth/pdo_protos/
PROTOBUF_SPATH = pdo/submitter/sawtooth/pdo_protos/protobufs/
PROTOBUF_SOURCE = pdo_contract_ccl.proto pdo_contract_enclave_registry.proto pdo_contract_registry.proto
PROTOBUF_PYTHON = $(subst .proto,_pb2.py,$(PROTOBUF_SOURCE))
PYTHON_SOURCE = $(shell cat MANIFEST)

SWIG_FILES = pdo/common/crypto.i
SWIG_TARGET = pdo/common/crypto.py
COMMON_LIB = ../common/build/libupdo-common.a

all: $(EGG_FILE)

$(PROTOBUF_DPATH)%_pb2.py : $(PROTOBUF_SPATH)%.proto
	protoc --python_out=$(PROTOBUF_DPATH) --proto_path=$(PROTOBUF_SPATH) $<

$(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON)) : $(addprefix $(PROTOBUF_SPATH),$(PROTOBUF_SOURCE))

$(EGG_FILE) : $(SWIG_TARGET) $(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON)) $(PYTHON_SOURCE)
	python setup.py bdist_egg

$(SWIG_TARGET) : $(SWIG_FILES) $(COMMON_LIB)
	python setup.py build_ext --force

install: $(EGG_FILE)
	easy_install $<

test: install
	(cd ../common/tests/crypto; python test_cryptoWrapper.py)

clean:
	rm -f $(addprefix $(PROTOBUF_DPATH),$(PROTOBUF_PYTHON))
	python setup.py clean --all

.phony : all
.phony : clean
.phone : install
.phony : test
