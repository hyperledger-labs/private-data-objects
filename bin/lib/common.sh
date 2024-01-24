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


# -----------------------------------------------------------------
# -----------------------------------------------------------------
cred=`tput setaf 1`
cgrn=`tput setaf 2`
cblu=`tput setaf 4`
cmag=`tput setaf 5`
cwht=`tput setaf 7`
cbld=`tput bold`
bred=`tput setab 1`
bgrn=`tput setab 2`
bblu=`tput setab 4`
bwht=`tput setab 7`
crst=`tput sgr0`

function recho () {
    echo "${cbld}${cred}" $@ "${crst}" >&2
}

function becho () {
    echo "${cbld}${cblu}" $@ "${crst}" >&2
}

# Common reporting functions: say, yell & die
#-----------------------------------------
# say is stdout, yell is stderr
function say () {
    echo "$(basename $0): $*"
}

function yell () {
    becho "$(basename $0): $*" >&2;
}

function die() {
    recho "$(basename $0): ERROR: $*" >&2
    exit 111
}

# Common functions to run commands
#-----------------------------------------
function try() {
    "$@" || die "operation failed: $*"
}

# Common function to test python version
#-----------------------------------------
function check_python_version() {
    VERSION=$(python3 --version | sed 's/Python 3\.\([0-9][0-9]*\).*/\1/')
    if [[ $VERSION -lt 5 ]]; then
        die unsupported version of python
    fi
}

# Common function to force name/address to address format
#-----------------------------------------
function force_to_ip()
{
    local name=$1

    if [[ $name =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo $name
    else
        echo $(dig +short $name)
    fi
}

# -----------------------------------------
# Check for build time environment variables
# -----------------------------------------
function check_pdo_build_env()
{
    # note: despite the 'die' below this does _not_ terminate, just prints error!
    : "${PDO_SOURCE_ROOT:-$(die Missing environment variable PDO_SOURCE_ROOT)}"
    : "${PDO_HOME:-$(die Missing environment variable PDO_HOME)}"
    : "${PDO_INTERPRETER:-$(die Missing environment variable PDO_INTERPRETER)}"
    : "${PDO_LEDGER_TYPE:-$(die Missing environment variable PDO_LEDGER_TYPE)}"
    : "${PDO_LEDGER_KEY_ROOT:-$(die Missing environment variable PDO_LEDGER_KEY_ROOT)}"
}

# -----------------------------------------
# Check for runtime environment variables
# -----------------------------------------
function check_pdo_runtime_env()
{
    # PDO_SOURCE_ROOT is a runtime dependency we should remove
    : "${PDO_SOURCE_ROOT:-$(die Missing environment variable PDO_SOURCE_ROOT)}"

    # Base path for finding libraries and configuration files
    : "${PDO_HOME:-$(die Missing environment variable PDO_HOME)}"

    # Used for building contracts
    : "${PDO_INTERPRETER:-$(die Missing environment variable PDO_INTERPRETER)}"

    # Used for selection of key formats
    : "${PDO_LEDGER_TYPE:-$(die Missing environment variable PDO_LEDGER_TYPE)}"

    # Used to find the ledger keys
    : "${PDO_LEDGER_KEY_ROOT:-$(die Missing environment variable PDO_LEDGER_KEY_ROOT)}"

    # Used to find the ledger
    : "${PDO_LEDGER_URL:-$(die Missing environment variable PDO_LEDGER_URL)}"

    # Used to identify the interface for services
    : "${PDO_HOSTNAME:-$(die Missing environment variable PDO_HOSTNAME)}"
}
