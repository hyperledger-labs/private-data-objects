<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Host System Installation

Instructions in this document assume the environment variable
`PDO_SOURCE_ROOT` points to the PDO source directory. Information about
other [environment variables](environment.md) that control build and
installation is described below.

## Process Overview

- Setup the basic development environment
- Download TinyScheme source
- Install SGX SDK and untrusted platform libraries/services
- Install LVI-aware binutils
- Install SGX SSL
- Install required build dependencies
- Set up environment variables to configure the build
- Build and install Sawtooth
- Build the PDO package

## <a name="environment">Setup Build Environment</a>

On a minimal Ubuntu system, the following packages are required. Other
distributions will require similar packages.

```bash
sudo apt install -y cmake curl git pkg-config unzip xxd libssl-dev
sudo apt install -y swig python3 python3-dev python3-venv virtualenv
sudo apt install -y liblmdb-dev libprotobuf-dev libsecp256k1-dev protobuf-compiler
```

<!--
    virtualenv will cause python3 and python3-virtualenv to be installed
-->

## <a name="tinyscheme">Build Tinyscheme</a>

This project contains a modified version of the Tinyscheme interpreter
for use within a secure enclave.  You **also** need a separate, plain
copy of Tinyscheme to use outside the enclave for contract development.

- Download the Tinyscheme source:
```bash
wget https://downloads.sourceforge.net/project/tinyscheme/tinyscheme/tinyscheme-1.41/tinyscheme-1.41.zip -P /tmp
```

- Extract and compile it:
```bash
cd ${PDO_SOURCE_ROOT}
unzip /tmp/tinyscheme-1.41.zip
cd tinyscheme-1.41
make FEATURES='-DUSE_DL=1 -DUSE_PLIST=1'
```

- Set the `TINY_SCHEME_SRC` environment variable to the directory where
you built the package (this environment variable will be used in
the PDO build process so you might consider adding it to your login
shell script (`~/.bashrc` or similar):

```bash
export TINY_SCHEME_SRC=${PDO_SOURCE_ROOT}/tinyscheme-1.41
```

## Install SGX Platform Libraries and Services

You also need the SGX Platform Services (PSW) so an enclave can properly
be launched and can receive quotes for remote attestation.
Following commands will download and install PSW:

```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
apt-get update
apt-get build-essential python #dependencies
apt-get install -y libsgx-enclave-common sgx-aesm-service libsgx-urts libsgx-launch libsgx-epid libsgx-quote-ex libsgx-uae-service
```

if you want to debug and/or develop, also install following packages
```bash
apt-get install -y libsgx-enclave-common-dbgsym libsgx-enclave-common-dev
```

## Install the SGX SDK

Private Data Objects has been tested with version 2.9.1 of the SGX
SDK. You can download prebuilt binaries for the SDK and kernel drivers
from [01.org](https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/).

The following commands will download and install version 2.9.1 of the SGX
SDK. When asked for the installation directory, we suggest that you install
the SDK into the directory `/opt/intel`.

```bash
UBUNTU_VERSION=ubuntu18.04-server
DRIVER_REPO= https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/${UBUNTU_VERSION}/
SDK_FILE=sgx_linux_x64_sdk_2.9.101.2.bin

wget ${DRIVER_REPO}/${SDK_FILE}
chmod 777 ./${SDK_FILE}
echo -e "no\n/opt/intel" | ./${SDK_FILE}
```

The installer includes a file that sets environment variables to
configure the SGX SDK installation. For example, if you installed the
SDK into the directory `/opt/intel`, then the following will set the
necessary SGX environment variables:

```bash
source /opt/intel/sgxsdk/environment
```

You can also build and install the SGX SDK from source. Instructions for
building from source are available
[Intel SGX SDK git repository](https://github.com/intel/linux-sgx).

## Install binutils with LVI mitigations

Ubuntu 18.04 does not ship a version of `binutils` that
includes mitigations for LVI attacks. However, recent
releases of SGX SSL expect these mitigations to be in place.

Intel provides binary distributions of `binutils` (version 2.32)
that contain the necessary LVI mitigations. The following
commands will download and install these binaries:

```bash
wget "https://download.01.org/intel-sgx/sgx-linux/2.9.1/as.ld.objdump.gold.r1.tar.gz"
mkdir /opt/intel/sgxsdk.extras
tar -xzf as.ld.objdump.gold.r1.tar.gz -C /opt/intel/sgxsdk.extras
export PATH=/opt/intel/sgxsdk.extras/external/toolset:${PATH}
```

## Build and Install SGX SSL

SGX OpenSSL is a compilation of OpenSSL specifically for use within SGX
enclaves. We have tested PDO with SGX SSL version 2.9.1.

Detailed instructions for building and installing SGX SSL is available
from the
[Intel SGX SSL github repository](https://github.com/intel/intel-sgx-ssl).

Follow these steps to compile and install version 2.9.1:

- Ensure you have the SGX SDK environment variables activated:
```bash
source /opt/intel/sgxsdk/environment
```

- Clone the SGX SSL source:
```bash
git clone 'https://github.com/intel/intel-sgx-ssl.git'
```

- Check out the recommended version (lin_2.9_1.1.1d):

```bash
cd intel-sgx-ssl
git checkout lin_2.9_1.1.1d
```

- Download the OpenSSL source package that will form the base of this
SGX SSL install:

```bash
cd openssl_source
wget 'https://www.openssl.org/source/openssl-1.1.1d.tar.gz'
cd ..
```

- Set the environment variable for hardware or simulation mode. For
simulation mode use `export SGX_MODE=SIM`. For hardware mode use `export
SGX_MODE=HW`. Note that to build in hardware and run the tests in hardware
mode you must have installed the [SGX kernel driver](install.md).

- Compile and install the SGX SSL project.
```bash
cd Linux
make DESTDIR=/opt/intel/sgxssl all
sudo make install
```

- Export the `SGX_SSL` environment variable to enable the build
utilities to find and link this library.  Consider adding this to your
login shell script (`~/.bashrc` or similar)

```bash
export SGX_SSL=/opt/intel/sgxssl
```

## Build and Install Ledger

Hyperledger Private Data Objects uses the Hyperledger Sawtooth distributed
ledger to store data object instances and state, and to guarantee update
atomicity.

Application logic is implemented in Sawtooth through the use of Transaction
Processors; transaction processors enable the distributed ledger to handle
application requests. This repository contains the code required to build
Transaction Processors that handle PDO requests.

Follow the
[setup document](../sawtooth/docs/SETUP.md)
to install both Sawtooth and the custom Sawtooth Transaction Processors.

Note that the Sawtooth components do not depend on any other components of the
PDO project, and can be set up on an entirely separate machine from the one
running Private Data Objects. It is recommended that Sawtooth be run on Ubuntu
16.04 as it is the only operating system version on which Sawtooth is actively
supported.

There is an ongoing effort to support Microsoft CCF based ledger
in addition to Hyperledger Sawtooth. Currently PDO supports CCF ledger under
the SIMULATE mode for PDO enclaves, and virtual mode for CCF enclaves.

See [HERE](../ccf_transaction_processor/Readme.md) to learn more about the ccf based transaction processor.
The default ledger choice for PDO is Sawtooth. CCF based ledger can be enabled by setting the
environment variable PDO_LEDGER_TYPE=ccf (assuming that a CCF ledger has already been set up).

## Build and Install PDO

Assuming you have installed and configured the pre-requisites in the
default location lcations, the following commands will build and install
PDO into a Python virtual environment in the directory
`${PDO_SOURCE_ROOT}/build/_dev`.

```bash
export TINY_SCHEME_SRC=${PDO_SOURCE_ROOT}/tinyscheme-1.41
export SGX_MODE=SIM
export SGX_SSL=/opt/intel/sgxssl
source /opt/intel/sgxsdk/environment
source ${PDO_SOURCE_ROOT}/build/common-config.sh

cd ${PDO_SOURCE_ROOT}/build
make
make test
```
