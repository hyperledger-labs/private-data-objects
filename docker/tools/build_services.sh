#!/bin/bash
# Copyright 2023 Intel Corporation
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

# these variables should be unused during build
export PDO_HOSTNAME=
export PDO_LEDGER_URL=

source /opt/intel/sgxsdk/environment
source /project/pdo/tools/environment.sh

make -C ${PDO_SOURCE_ROOT}/build environment
make -C ${PDO_SOURCE_ROOT}/build template
make -C ${PDO_SOURCE_ROOT}/build system-keys
make -C ${PDO_SOURCE_ROOT}/build verified-build
