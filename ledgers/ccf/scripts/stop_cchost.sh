#!/bin/bash

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

# -----------------------------------------------------------------
# -----------------------------------------------------------------
source ${PDO_HOME}/bin/lib/common.sh
check_pdo_runtime_env

if [ -f ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid ]; then
    kill $(cat ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid)
    #Kill the parent as well. Otherwise cchost continues to linger as a defunct process
    CCHOST_PID=$(cat ${PDO_HOME}/ccf/workspace/sandbox_0/node.pid)
    kill $(cat /proc/${CCHOST_PID}/status | grep PPid | cut -f2) > /dev/null
fi
