# Copyright 2019 Intel Corporation
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

F_LOGDIR=$F_SERVICEHOME/logs
F_CONFDIR=$F_SERVICEHOME/etc
F_BINDIR=$PDO_INSTALL_ROOT/bin

SCRIPT_NAME=$(basename ${BASH_SOURCE[-1]} )


# =======================================================================
# to handle some docker oddities, define our own pgrep rather than the normal one ..
pgrepf() { PLIST=$(ps -ef | egrep -v '<defunct>|egrep|awk' | egrep "$1"); rc=$?; echo "${PLIST}" | awk '{ print $2 }'; return $rc; }


# =======================================================================
# get url base from config
get_url_base() {
    IDENTITY=$1
    config_file="${F_CONFDIR}/${IDENTITY}.toml"
    host=$(perl -n -e'/^\s*Host\s*=\s*"([a-zA-Z0-9-.]+)"/ && print $1' ${config_file})
    [ ! -z "${host}" ] || { echo "no valide host found for service $IDENTITY"; exit 1; }
    # As the host might be defined to listen on all interfaces, we have to remap below this special case
    if [ ${host} = "0.0.0.0" ]; then host="127.0.0.1"; fi
    port=$(perl -n -e'/^\s*HttpPort\s*=\s*([0-9]+)/ && print $1' ${config_file})
    [ ! -z "${port}" ] || { echo "no valide port found for service $IDENTITY"; exit 1; }
    url_base="http://${host}:${port}"
    echo $url_base
}

# curl command for liveness test
# - expects URL as additional argument
# - will return HTTP return code & exist 0 if successfull, string "000" and non-zero error return code
# Note: --ipv4 is crucial as retry logic with --retry-connrefuse doesn't work as expected for IPv6
CURL_CMD='curl --ipv4 --retry-connrefuse --retry 10 --retry-max-time 50 --connect-timeout 5 --max-time 10  -sL -w %{http_code} -o /dev/null'


# =======================================================================
# service status
# - requires setting F_BASENAME, F_SERVICE_CMD and F_SERVICE_NAME to be set
# - cmd-line params have to be passed as arguments of function
service_start() {
    F_LEDGERURL=''
    F_OUTPUTDIR=''
    F_CLEAN='no'
    F_LOGLEVEL=''

    # this is needed for extended pattern matching of configuration file names
    shopt -s extglob

    # -----------------------------------------------------------------
    # Process command line arguments
    # -----------------------------------------------------------------
    if [ "${F_SERVICE_CMD}" = "sservice" ]; then
	F_USAGE='-b|--base name --clean -c|--config directory -o|--output dir -l|--loglevel [debug|info|warn]'
	SHORT_OPTS='b:c:o:l:'
	LONG_OPTS='base:,config:,clean,help,loglevel:,output:'
    else
	F_USAGE='-b|--base name --clean -c|--config directory --ledger url -o|--output dir --clean -l|--loglevel [debug|info|warn]'
	SHORT_OPTS='b:c:o:l:'
	LONG_OPTS='base:,config:,clean,help,loglevel:,output:,ledger:'
    fi

    TEMP=$(getopt -o ${SHORT_OPTS} --long ${LONG_OPTS} -n "${SCRIPT_NAME}" -- "$@")
    if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi

    eval set -- "$TEMP"
    while true ; do
        case "$1" in
            -b|--base) F_BASENAME="$2" ; shift 2 ;;
            --clean) F_CLEAN="yes" ; shift 1 ;;
            -c|--config) F_CONFDIR="$2" ; shift 2 ;;
            --ledger) F_LEDGERURL="--ledger $2" ; shift 2 ;;
            -l|--loglevel) F_LOGLEVEL="--loglevel $2" ; shift 2 ;;
            -o|--output) F_OUTPUTDIR="$2" ; shift 2 ;;
            --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
        esac
    done

    # (1) do not start if service already running
    PLIST=$(pgrepf  "${F_BINDIR}/${F_SERVICE_CMD} .* --config ${F_BASENAME}[0-9]+.toml\b")
    if [ -n "$PLIST" ] ; then
        echo existing ${F_SERVICE_NANME} services detected, please shutdown first
        exit 1
    fi

    # (2) start services asynchronously
    ILIST=$(basename --suffix=.toml ${F_CONFDIR}/${F_BASENAME}+([0-9]).toml)
    for IDENTITY in ${ILIST[@]} ; do
        echo start ${F_SERVICE_NAME} service $IDENTITY

        if [ "${F_CLEAN}" == "yes" ]; then
            rm -f "${F_SERVICEHOME}/data/${IDENTITY}.enc"
	    if [ "${F_SERVICE_CMD}" = "pservice" ]; then
		rm -f "${F_SERVICEHOME}/data/${IDENTITY}.data"
	    fi
        fi

        rm -f $F_LOGDIR/$IDENTITY.log $F_LOGDIR/$IDENTITY.pid

        if [ "$F_OUTPUTDIR" != "" ]  ; then
            EFILE="$F_OUTPUTDIR/$IDENTITY.err"
            OFILE="$F_OUTPUTDIR/$IDENTITY.out"
            rm -f $EFILE $OFILE
        else
            EFILE=/dev/null
            OFILE=/dev/null
        fi

	if [ "${F_SERVICE_CMD}" = "sservice" ]; then
            ${F_SERVICE_CMD} --identity ${IDENTITY} --config ${IDENTITY}.toml --config-dir ${F_CONFDIR} \
			     ${F_LOGLEVEL} 2> $EFILE > $OFILE &
            echo $! > ${F_LOGDIR}/${IDENTITY}.pid
	else
            ${F_SERVICE_CMD} --identity ${IDENTITY} --config ${IDENTITY}.toml --config-dir ${F_CONFDIR} \
                             ${F_LEDGERURL} ${F_LOGLEVEL} 2> $EFILE > $OFILE &
            echo $! > ${F_LOGDIR}/${IDENTITY}.pid
	fi
    done

    # (3) wait for successfull start of the services
    for IDENTITY in ${ILIST[@]} ; do
        echo waiting for startup completion of ${F_SERVICE_NAME} service $IDENTITY

        url="$(get_url_base ${IDENTITY})/info" || { echo "no url found for ${F_SERVICE_NAME} service"; exit 1; }
        resp=$(${CURL_CMD} ${url})
        if [ $? != 0 ] || [ $resp != "200" ]; then
    	    echo "${F_SERVICE_NAME} service $IDENTITY not properly running"
    	    exit 1
        fi
    done
}

# =======================================================================
# service status
# - requires setting F_BASENAME, F_SERVICE_CMD and F_SERVICE_NAME to be set
# - cmd-line params have to be passed as arguments of function
service_status() {
    F_USAGE='-b|--base name'

    # -----------------------------------------------------------------
    # Process command line arguments
    # -----------------------------------------------------------------
    TEMP=$(getopt -o b:h --long base:,help \
         -n "${SCRIPT_NAME}" -- "$@")

    if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi


    eval set -- "$TEMP"
    while true ; do
        case "$1" in
            -b|--base) F_BASENAME="$2" ; shift 2 ;;
            --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}"; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
        esac
    done

    echo "running processes of ${F_SERVICE_NAME} service"

    PLIST=$(pgrepf  "${F_BINDIR}/${F_SERVICE_CMD} .* --config ${F_BASENAME}[0-9]+.toml\b")
    if [ -n "$PLIST" ] ; then
        ps -h --format pid,start,cmd -p $PLIST
    fi
}


# =======================================================================
# stop service
# - requires setting F_BASENAME and F_SERVICE_NAME to be set
# - cmd-line params have to be passed as arguments of function
service_stop() {
    F_USAGE='-c|--config path -b|--base name'

    # this is needed for extended pattern matching of configuration file names
    shopt -s extglob

    # -----------------------------------------------------------------
    # Process command line arguments
    # -----------------------------------------------------------------
    TEMP=$(getopt -o "b:c:h" --long "base:,config:,help" \
		  -n "${SCRIPT_NAME}" -- "$@")

    if [ $? != 0 ] ; then echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" >&2 ; exit 1 ; fi

    eval set -- "$TEMP"
    while true ; do
        case "$1" in
            -b|--base) F_BASENAME="$2" ; shift 2 ;;
            -c|--config) F_CONFDIR="$2" ; shift 2 ;;
            --help) echo "Usage: ${SCRIPT_NAME} ${F_USAGE}" ; exit 0 ;;
    	--) shift ; break ;;
    	*) echo "Internal error!" ; exit 1 ;;
        esac
    done

    rc=0
    ILIST=$(basename --suffix=.toml ${F_CONFDIR}/${F_BASENAME}+([0-9]).toml)
    for IDENTITY in ${ILIST[@]} ; do
        echo "stopping ${F_SERVICE_NAME} service ${IDENTITY}"
        if [ -f ${F_LOGDIR}/${IDENTITY}.pid ]; then
            kill -SIGTERM $(cat ${F_LOGDIR}/${IDENTITY}.pid)
            rm -f ${F_LOGDIR}/${IDENTITY}.pid
        else
    	    echo "${F_SERVICE_NAME} service ${IDENTITY} not running or not properly shut down"
    	    rc=1
        fi
    done
    exit $rc
}
