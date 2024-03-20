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

EGG_FILE=dist/pdo_client-${MOD_VERSION}-py${PY_VERSION}.egg
PYTHON_SOURCE = $(shell cat MANIFEST)

all : $(EGG_FILE)

install: $(EGG_FILE)
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python3 setup.py install

$(EGG_FILE) : $(PYTHON_SOURCE) bin/pdo-invoke.psh bin/pdo-create.psh
	@echo Build Distribution
	@ . $(abspath $(DSTDIR)/bin/activate) && \
		python3 setup.py bdist_egg

clean :
	rm -rf build dist *.egg-info

.phony : all
.phony : clean
.phony : build_contracts
.phony : install
