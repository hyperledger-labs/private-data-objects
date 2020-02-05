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

CONTRACT_SRC := auction.scm asset_type.scm exchange.scm issuer.scm vetting_organization.scm
CONTRACTS := _auction.scm _asset_type.scm _exchange.scm _issuer.scm _vetting_organization.scm

PACKAGE_SRC := \
	packages/asset_class.scm packages/asset_request_class.scm \
	packages/authoritative_asset_class.scm packages/authority_class.scm \
	packages/exchange_common.scm packages/ledger_entry.scm packages/bid_store_package.scm \
	../packages/contract-base.scm ../packages/key-store.scm ../packages/persistent-key-store.scm \
	../packages/safe-key-store.scm ../packages/hashtab.scm ../packages/alist.scm ../packages/hash.scm

PLUGINS := asset_type.py exchange.py issuer.py vetting.py

TEST_PACKAGE_SRC := \
	tests/test_common.scm \
	../packages/debug.scm

TEST_CONTRACTS := _auction_test.scm _exchange_test.scm _issuer_test.scm

all: $(CONTRACTS)

debug :

test :
	@echo TESTS DISABLED

x-test : $(TEST_CONTRACTS)
	@echo Run exchange contract tests
	@$(GIPSY_SCHEME) -1 _issuer_test.scm loglevel 2
	@$(GIPSY_SCHEME) -1 _exchange_test.scm loglevel 2
	@$(GIPSY_SCHEME) -1 _auction_test.scm loglevel 2
	@rm -f exchange-test.mdb exchange-test.mdb-lock

_auction_test.scm : tests/auction_test.bld tests/auction_test.scm $(CONTRACT_SRC) $(PACKAGE_SRC) $(TEST_PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 tests/auction_test.bld debug

_exchange_test.scm : tests/exchange_test.bld tests/exchange_test.scm $(CONTRACT_SRC) $(PACKAGE_SRC) $(TEST_PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 tests/exchange_test.bld debug

_issuer_test.scm : tests/issuer_test.bld tests/issuer_test.scm $(CONTRACT_SRC) $(PACKAGE_SRC) $(TEST_PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 tests/issuer_test.bld debug

_asset_type.scm : asset_type.bld asset_type.scm $(PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 asset_type.bld

_auction.scm : auction.bld auction.scm $(PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 auction.bld

_exchange.scm : exchange.bld exchange.scm $(PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 exchange.bld

_issuer.scm : issuer.bld issuer.scm $(PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 issuer.bld

_vetting_organization.scm : vetting_organization.bld vetting_organization.scm $(PACKAGE_SRC)
	$(GIPSY_SCHEME) -1 vetting_organization.bld

install : $(CONTRACTS) $(PLUGINS)
	@echo copy $(CONTRACTS) to $(INSTALLDIR)
	@mkdir -p $(INSTALLDIR)
	@cp $(CONTRACTS) $(INSTALLDIR)
	@cp $(PLUGINS) $(INSTALLDIR)

clean :
	@rm -f $(CONTRACTS) $(TEST_CONTRACTS)
	@rm -f exchange-test.mdb exchange-test.mdb-lock

.PHONY : all clean debug install test
