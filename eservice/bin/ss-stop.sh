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

F_USAGE='-b|--base port -c|--count services'
F_BASE=7201
F_COUNT=1

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
TEMP=`getopt -o b:c:h --long base:,count:,help \
     -n 'stop.sh' -- "$@"`

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -b|--base) F_BASE="$2" ; shift 2 ;;
        -c|--count) F_COUNT="$2" ; shift 2 ;;
        --help) echo $F_USAGE ; exit 1 ;;
	--) shift ; break ;;
	*) echo "Internal error!" ; exit 1 ;;
    esac
done

for port in `seq $F_BASE $(($F_BASE+$F_COUNT))` ; do
    curl -s "http://localhost:$port/shutdown"
done
