# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

TOP = ../..
#include $(TOP)/build.mk

BUILD_DIR := build

build: 
	@if [ ! -d $(BUILD_DIR) ]; then \
		mkdir -p $(BUILD_DIR) && \
		cd $(BUILD_DIR) && \
		cmake ./.. ; \
	fi
	$(MAKE) --directory=$(BUILD_DIR)

test: build
	$(MAKE) -C $(BUILD_DIR) test

clean:
	rm -rf $(BUILD_DIR)
