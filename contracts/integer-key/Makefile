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

PDO_HOME ?= /opt/pdo

SRCDIR?=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOTDIR := $(abspath $(SRCDIR)/../..)
GIPSY_SCHEME := $(ROOTDIR)/contracts/bin/gipsyscheme
INSTALLDIR = $(PDO_HOME)/contracts

PACKAGES := $(wildcard ../packages/*.scm)
CONTRACTS := _integer-key.scm
PLUGINS := integer-key.py

all: $(CONTRACTS)

debug :

test :
	@echo No automated tests defined

_integer-key.scm : integer-key.bld integer-key.scm $(PACKAGES)
	$(GIPSY_SCHEME) -1 integer-key.bld

_debug_integer-key.scm : integer-key.bld integer-key.scm integer-key-test.scm
	$(GIPSY_SCHEME) -1 integer-key.bld debug test-integer-key

install : $(CONTRACTS) $(PLUGINS)
	@echo copy $(CONTRACTS) to $(INSTALLDIR)
	@mkdir -p $(INSTALLDIR)
	@cp $(CONTRACTS) $(INSTALLDIR)
	@cp $(PLUGINS) $(INSTALLDIR)

clean :
	rm -f $(CONTRACTS) $(DEBUGCONTRACTS)

.PHONY : all clean debug install test
