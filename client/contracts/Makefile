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

CONTRACTS := _auction.scm _integer-key.scm _mock-contract.scm
DEBUGCONTRACTS := $(addprefix _debug, $(CONTRACTS)) _aptest.scm

contracts: $(CONTRACTS)

debug : $(DEBUGCONTRACTS)

_mock-contract.scm : mock-contract.bld contracts/mock-contract.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 mock-contract.bld

_debug_mock-contract.scm : mock-contract.bld contracts/mock-contract.scm
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 mock-contract.bld debug

_auction.scm : auction.bld contracts/auction.scm $(PACKAGES)
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 auction.bld

_debug_auction.scm : auction.bld contracts/auction.scm contracts/auction-test.scm $(PACKAGES)
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 auction.bld debug test-auction

_integer-key.scm : integer-key.bld contracts/integer-key.scm $(PACKAGES)
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 integer-key.bld

_debug_integer-key.scm : integer-key.bld contracts/integer-key.scm contracts/integer-key-test.scm $(PACKAGES)
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 integer-key.bld debug test-integer-key

_aptest.scm : aptest.bld contracts/auction-protocol-test.scm contracts/integer-key.scm contracts/auction.scm $(PACKAGES)
	LD_LIBRARY_PATH=$(EXTENSIONPATH) tinyscheme -1 aptest.bld debug aptest

clean :
	rm -f $(CONTRACTS) $(DEBUGCONTRACTS)
