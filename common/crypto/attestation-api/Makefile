# Copyright 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

export SGX_MODE ?= SIM
export SGX_SSL ?= /opt/intel/sgxssl
export SGX_SDK ?= /opt/intel/sgxsdk
export DCAP_PRIMITIVES ?= /tmp/SGXDataCenterAttestationPrimitives

all: build test

build:
	mkdir -p build
	cd build && cmake ..
	. ${SGX_SDK}/environment && make -C build

.PHONY: test
test:
	. ${SGX_SDK}/environment && env CTEST_OUTPUT_ON_FAILURE=1 make -C build test

clean:
	rm -rf build

