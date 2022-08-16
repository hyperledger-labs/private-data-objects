#!/bin/bash

# Copyright 2022 Intel Corporation
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

SCRIPTDIR="$(dirname $(readlink --canonicalize ${BASH_SOURCE}))"
SRCDIR="$(realpath ${SCRIPTDIR}/../..)"

source ${SRCDIR}/bin/lib/common.sh

yell "Start log dump <<<"

for f in build/_dev/opt/pdo/logs/*.log; do \
    yell "Dumping $f <<<"; \
    cat $f; \
    yell ">>>"
done

for f in docker/opt-pdo-logs/*.log; do \
    yell "Dumping $f <<<"; \
    cat $f; \
    yell ">>>"
done
    
yell "End log dump >>>"
