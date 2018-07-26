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

# This script combines scheme packages together into a single file,
# removing extra white space and comments, then converts the result
# into a header file that can be included directly into the interpreter

F_PACKAGE_NAME='_init_package'

# -----------------------------------------------------------------
# Process command line arguments
# -----------------------------------------------------------------
TEMP=`getopt -o p: --long package: \
     -n 'build-init-package.sh' -- "$@"`

if [ $? != 0 ] ; then echo "Terminating..." >&2 ; exit 1 ; fi

eval set -- "$TEMP"
while true ; do
    case "$1" in
        -p|--package) F_PACKAGE_NAME="$2" ; shift 2 ;;
	--) shift ; break ;;
	*) echo "Internal error!" ; exit 1 ;;
    esac
done

SCRIPTFILE=`mktemp --suffix .scm`
cat > $SCRIPTFILE << EOF
(for-each (lambda (file)
            (call-with-input-file file
              (lambda (iport)
                (let read-one ((expr (read iport)))
                  (if (not (eof-object? expr))
                      (begin (write expr) (newline) (read-one (read iport))))))))

          *args*)
EOF

function cleanup {
    rm -f ${SCRIPTFILE}
}

trap cleanup EXIT


tinyscheme -1 $SCRIPTFILE $@ > ${F_PACKAGE_NAME}.scm
xxd -i ${F_PACKAGE_NAME}.scm ${F_PACKAGE_NAME}.h
