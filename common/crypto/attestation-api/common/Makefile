# Copyright 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

.jwt-cpp-patched:
	cd jwt-cpp && git apply ../jwt-cpp.patch && touch ../.jwt-cpp-patched

all build test: .jwt-cpp-patched

clean:
	if [ -f .jwt-cpp-patched ]; then \
		cd jwt-cpp && git apply --reverse ../jwt-cpp.patch && rm ../.jwt-cpp-patched ;\
	fi


