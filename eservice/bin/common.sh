F_LOGDIR=$F_SERVICEHOME/logs
F_CONFDIR=$F_SERVICEHOME/etc

# to handle some docker oddities, define our own pgrep rather than the normal one ..
pgrepf() { PLIST=$(ps -ef | egrep -v '<defunct>|egrep|awk' | egrep "$1"); rc=$?; echo "${PLIST}" | awk '{ print $2 }'; return $rc; }

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
