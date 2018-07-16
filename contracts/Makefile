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

SRCDIR?=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOTDIR := $(abspath $(SRCDIR)/../..)
EXTENSIONPATH := $(ROOTDIR)/common/build

BASEPACKAGES := alist.scm comlist.scm hash.scm hashtab.scm
CONTRACTPACKAGES := contract-base.scm counter.scm escrow-counter.scm key-store.scm
PACKAGES := $(BASEPACKAGES) $(CONTRACTPACKAGES)
PACKAGES := $(addprefix packages/, $(PACKAGES))

TARGETS := all clean debug install
CONTRACTS := auction exchange integer-key mock-contract

$(TARGETS): $(CONTRACTS)

$(CONTRACTS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: $(TARGETS) $(CONTRACTS)
