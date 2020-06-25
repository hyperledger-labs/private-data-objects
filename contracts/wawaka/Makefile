# Copyright 2019 Intel Corporation
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

# skip downloading LLVM and building wamrc unless we're in wawaka-aot mode
ifeq ($(PDO_INTERPRETER),wawaka-aot)
BUILD_AOT:=build-wamrc
endif

LLVM_VERSION=10.0.0
LLVM_REPO=https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)
LLVM_TAR=clang+llvm-$(LLVM_VERSION)-x86_64-linux-gnu-ubuntu-18.04
LLVM_BIN=$(WASM_SRC)/core/deps/llvm/build/llvm/bin/llvm-lto # proxy for llvm dependency

CDI_COMPILER_SIGN_PEM=$(PDO_INSTALL_ROOT)/opt/pdo/keys/cdi_compiler1_private.pem
CDI_COMPILER_VERIF_PEM=$(PDO_INSTALL_ROOT)/opt/pdo/keys/cdi_compiler1_public.pem

all : build
	@cd build && make all

clean :
	@echo Remove build directory
	@rm -rf build $(WASM_SRC)/core/deps/llvm/build $(WASM_SRC)/wamr-compiler/build
	@$(MAKE) -C benchmarks clean

debug :
	@echo No debug build defined

test :
	. $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger --contract interface-test --expressions ${SCRIPTDIR}/interface-test/test-short.json
	. $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger --contract mock-contract --expressions ${SCRIPTDIR}/mock-contract/test-short.json
	. $(abspath $(DSTDIR)/bin/activate) && pdo-test-contract --no-ledger --contract interpreter-test --expressions ${SCRIPTDIR}/interpreter-test/test-short.json

install : build
	@echo install contracts
	@cd build && make install

build : $(CDI_COMPILER_SIGN_PEM) $(BUILD_AOT)
	mkdir -p $@
	cd $@ && emcmake cmake ..

$(CDI_COMPILER_SIGN_PEM):
	@echo Generating CDI compiler keys
	@openssl ecparam -name secp256k1 -genkey -noout -out $(CDI_COMPILER_SIGN_PEM)
	@openssl ec -in  $(CDI_COMPILER_SIGN_PEM) -pubout -out $(CDI_COMPILER_VERIF_PEM)

$(LLVM_BIN):
	@echo Downloading LLVM dependencies
	@cd $(WASM_SRC)/core/deps && mkdir -p llvm/build/ && \
	wget -q $(LLVM_REPO)/$(LLVM_TAR).tar.xz && \
	tar -xf $(LLVM_TAR).tar.xz -C llvm/build/ && \
	cd llvm/build/ && mv $(LLVM_TAR) llvm

build-wamrc: $(LLVM_BIN)
	@echo Building wamrc
	@cd $(WASM_SRC)/wamr-compiler && mkdir -p build && cd build && cmake .. && make

.PHONY : all clean debug install test
