#!/bin/bash

source ${PDO_HOME}/bin/lib/common.sh

# generate core dumps where we want them
ulimit -c unlimited

for i in $(seq 1 2) ; do
    say "kv test iteration $i"
    scripts/kv-test.psh --loglevel $1 --logfile $2
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        yell "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX <<KV TEST FAILED>> XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        if [ -f /tmp/core.python3 ]; then
            yell "==================== <<BACKTRACE START>> ===================="
            gdb -batch -ex "bt" python3 /tmp/core.python3
            yell "==================== <<BACKTRACE END>> ===================="
        fi
        rm -f /tmp/core.python3
        exit $exit_code
    fi
done

exit 0
