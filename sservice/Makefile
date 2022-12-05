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

ifneq ($(basename ${PY_VERSION}),3)
$(error must be run with python3)
endif

EGG_FILE=dist/pdo_sservice-${MOD_VERSION}-py${PY_VERSION}-linux-x86_64.egg

PYTHON_FILES = $(shell cat MANIFEST)

SCRIPTS = \
	bin/ss-start.sh \
	bin/ss-stop.sh \
	bin/ss-status.sh

all : $(EGG_FILE)

$(EGG_FILE) : $(PYTHON_FILES) $(SCRIPTS)
	@echo Build Distribution
	python setup.py bdist_egg

install: $(EGG_FILE)
	python setup.py install

clean:
	rm -rf build deps dist *.egg-info
	find . -iname '*.pyc' -delete
	find . -iname '__pycache__' -delete

.phony : all
.phony : clean
.phone : install
