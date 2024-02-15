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

ifndef PDO_INSTALL_ROOT
$(error Incomplete configuration, PDO_INSTALL_ROOT is not defined)
endif

DSTDIR ?= $(PDO_INSTALL_ROOT)/opt/pdo
BIN_LIB_DIR=$(DSTDIR)/bin/lib

all : install

build :

install : build
	mkdir -p $(BIN_LIB_DIR)
	cp lib/*.sh $(BIN_LIB_DIR)

clean:

.phony : all
.phony : clean
.phone : install
