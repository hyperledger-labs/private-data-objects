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

include ../../../Makefile.variables
TEST_CRYPTO_DIR := ../../
TEST_CRYPTO_SRC := $(TEST_CRYPTO_DIR)/testCrypto.cpp
ENCLAVE_DIR = .
Common_Library_Name := tpdo_common
COMMON_LIBRARY_PATH = ../../../

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
	SGX_SDK_INC := $(SGX_SDK)/include
	STL_PORT_INC := $(SGX_SDK)/include
endif

ifdef DEBUG
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

# Added to build with SgxSSL libraries
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
TSETJMP_LIB := #-lsgx_tsetjmp

#$(if $(shell [ $(SGXSDK_INT_VERSION) -ge 20 ] && echo "OK"), \
    $(eval TSETJMP_LIB := ))

ifdef DEBUG
        SGX_COMMON_CFLAGS += -O0 -g
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/debug/
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/release/
endif


ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

ifeq ($(SGX_MODE), HW)
ifndef DEBUG
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif

Trusted_Include_Paths := -I. -I../../../ -I../../../packages/base64  -I$(TEST_CRYPTO_DIR) -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(OPENSSL_PACKAGE)/include  -include "tsgxsslio.h" -I$(SGX_SDK)/include/libcxx

Trusted_C_Cpp_Flags := -DOS_ID=$OS_ID $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security  -include "tsgxsslio.h"
Trusted_C_Flags := $(Trusted_C_Cpp_Flags) -Wno-implicit-function-declaration -std=c11
Trusted_Cpp_Flags :=  $(Trusted_C_Cpp_Flags) -std=c++11 -nostdinc++

TestEnclave_Cpp_Files := $(wildcard $(ENCLAVE_DIR)/*.cpp)
TestEnclave_C_Files := $(wildcard $(ENCLAVE_DIR)/*.c)

TestEnclave_Cpp_Objects := $(TestEnclave_Cpp_Files:.cpp=.o)
TestEnclave_C_Objects := $(TestEnclave_C_Files:.c=.o)

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
						 -l$(OpenSSL_Crypto_Library_Name)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

TestEnclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) \
	$(SgxSSL_Link_Libraries) -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdcxx -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto $(TSETJMP_LIB) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(ENCLAVE_DIR)/TestEnclave.lds

.PHONY: all run

all: TestEnclave.signed.so
# usually release mode don't sign the enclave, but here we want to run the test also in release mode
# this is not realy a release mode as the XML file don't disable debug - we can't load real release enclaves (white list)

run: all


######## TestEnclave Objects ########

$(ENCLAVE_DIR)/TestEnclave_t.c: $(SGX_EDGER8R) $(ENCLAVE_DIR)/TestEnclave.edl
	@cd $(ENCLAVE_DIR) && $(SGX_EDGER8R) --trusted TestEnclave.edl --search-path $(OPENSSL_PACKAGE)/include --search-path $(SGX_SDK_INC)
	@echo "GEN  =>  $@"

$(ENCLAVE_DIR)/TestEnclave_t.o: $(ENCLAVE_DIR)/TestEnclave_t.c
	@$(CC) $(Trusted_Include_Paths) $(Trusted_C_Flags)  -c $< -o $@
	@echo "CC   <=  $<"
$(ENCLAVE_DIR)/testCrypto.o: $(TEST_CRYPTO_SRC)
	@$(CXX) $(Trusted_Include_Paths) $(Trusted_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.cpp
	@$(CXX) $(Trusted_Include_Paths) $(Trusted_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c
	@$(CC) $(TestEnclave_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

TestEnclave.so: $(ENCLAVE_DIR)/TestEnclave_t.o $(ENCLAVE_DIR)/testCrypto.o $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)
	@$(CXX) $^  -o $@ -L$(COMMON_LIBRARY_PATH) -l$(Common_Library_Name) $(TestEnclave_Link_Flags)
	@echo "LINK  <=  $@"

TestEnclave.signed.so: TestEnclave.so
	@$(SGX_ENCLAVE_SIGNER) sign -key $(ENCLAVE_DIR)/TestEnclave_private.pem -enclave TestEnclave.so -out $@ -config $(ENCLAVE_DIR)/TestEnclave.config.xml
	@echo "SIGN =>  $@"

clean:
	@rm -f *.o *.so $(ENCLAVE_DIR)/TestEnclave_t.* $(TestEnclave_Cpp_Objects) $(TestEnclave_C_Objects)

