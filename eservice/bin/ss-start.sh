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

PY3_VERSION=$(python --version | sed 's/Python 3\.\([0-9]\).*/\1/')
if [[ $PY3_VERSION -lt 5 ]]; then
    echo activate python3 first
    exit
fi

F_SERVICEHOME="$( cd -P "$( dirname ${BASH_SOURCE[0]} )/.." && pwd )"
source ${F_SERVICEHOME}/bin/common.sh

F_USAGE='-c|--count services -b|--base name -o|--output dir -l|--loglevel [debug|info|warn]'
F_COUNT=1
F_BASENAME='sservice'
F_OUTPUTDIR=''
F_LOGLEVEL='info'

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
TEMP=`getopt -o b:c:l:o: --long base:,count:,help,loglevel:,output: \
     -n 'ss-start.sh' -- "$@"`

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -b|--base) F_BASENAME="$2" ; shift 2 ;;
        -c|--count) F_COUNT="$2" ; shift 2 ;;
        -l|--loglevel) F_LOGLEVEL="$2" ; shift 2 ;;
        -o|--output) F_OUTPUTDIR="$2" ; shift 2 ;;
        --help) echo $F_USAGE ; exit 1 ;;
	--) shift ; break ;;
	*) echo "Internal error!" ; exit 1 ;;
    esac
done

# (1) do not start if service already running
pgrepf  "\bsservice .* --config ${F_BASENAME}[0-9].toml\b"
if [ $? == 0 ] ; then
    echo existing storage services detected, please shutdown first
    exit 1
fi

# (2) start services asynchronously
for index in `seq 1 $F_COUNT` ; do
    IDENTITY="${F_BASENAME}$index"
    echo start storage service $IDENTITY

    rm -f $F_LOGDIR/$IDENTITY.log $F_LOGDIR/$IDENTITY.pid

    if [ "$F_OUTPUTDIR" != "" ]  ; then
        EFILE="$F_OUTPUTDIR/$IDENTITY.err"
        OFILE="$F_OUTPUTDIR/$IDENTITY.out"
        rm -f $EFILE $OFILE
    else
        EFILE=/dev/null
        OFILE=/dev/null
    fi

    sservice --identity ${IDENTITY} --config ${IDENTITY}.toml --config-dir ${F_CONFDIR} \
             --loglevel ${F_LOGLEVEL} --logfile ${F_LOGDIR}/${IDENTITY}.log 2> $EFILE > $OFILE &
    echo $! > ${F_LOGDIR}/${IDENTITY}.pid
done

# (3) wait for successfull start of the services
for index in `seq 1 $F_COUNT` ; do
    IDENTITY="${F_BASENAME}$index"
    echo waiting for startup completion of storage service $IDENTITY

    url="$(get_url_base $IDENTITY)/info" || { echo "no url found for storage service"; exit 1; }
    resp=$(${CURL_CMD} ${url})
    if [ $? != 0 ] || [ $resp != "200" ]; then
	echo "storage service $IDENTITY not properly running"
	exit 1
    fi
done
