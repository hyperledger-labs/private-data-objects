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

include ../../Makefile.variables

UNTRUSTED_DIR = app
EnclaveObjects = TestEnclave.so TestEnclave.signed.so
ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
	SGX_SDK_INC := $(SGX_SDK)/include
endif

ifdef DEBUG
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifdef DEBUG
        SGX_COMMON_CFLAGS += -O0 -g
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/debug/
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
        OPENSSL_LIBRARY_PATH := $(OPENSSL_PACKAGE)/lib64/release/
endif


######## App Settings ########


App_Cpp_Files := $(UNTRUSTED_DIR)/TestApp.cpp
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Include_Paths := -I$(UNTRUSTED_DIR) -I$(SGX_SDK_INC)

App_C_Flags := $(SGX_COMMON_CFLAGS) -fpic -fpie -fstack-protector -Wformat -Wformat-security -Wno-attributes $(App_Include_Paths)
App_Cpp_Flags := $(App_C_Flags) -std=c++11

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
endif

SgxSSL_Link_Libraries := sgx_usgxssl

Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

App_Link_Flags := $(SGX_COMMON_CFLAGS) $(Security_Link_Flags) $(SGX_SHARED_LIB_FLAG) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) -L$(OPENSSL_LIBRARY_PATH) -l$(SgxSSL_Link_Libraries) -lpthread


ifeq ($(SGX_MODE), HW)
ifndef DEBUG
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all run

all: TestApp $(EnclaveObjects)

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/TestApp
	@echo "RUN  =>  TestApp [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

######## App Objects ########
$(EnclaveObjects):
	cd enclave && make
	@cp ./enclave/*.so .
	@echo "./enclave/make"

$(UNTRUSTED_DIR)/TestEnclave_u.c: $(SGX_EDGER8R) enclave/TestEnclave.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../enclave/TestEnclave.edl --search-path $(OPENSSL_PACKAGE)/include --search-path $(SGX_SDK_INC)
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/TestEnclave_u.o: $(UNTRUSTED_DIR)/TestEnclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

TestApp: $(UNTRUSTED_DIR)/TestEnclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@cd enclave && make clean
	@rm -f TestApp *.so $(App_Cpp_Objects) $(UNTRUSTED_DIR)/TestEnclave_u.* $(UNTRUSTED_DIR)*.o

