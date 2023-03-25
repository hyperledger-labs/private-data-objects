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
- Build and install the ledger
- Build the PDO package

## <a name="environment">Setup Build Environment</a>

On a minimal Ubuntu system, the following packages are required. Other
distributions will require similar packages.

```bash
sudo apt install -y cmake curl git pkg-config unzip xxd libssl-dev build-essential
sudo apt install -y swig python3 python3-dev python3-venv virtualenv
sudo apt install -y liblmdb-dev libsecp256k1-dev libncurses5-dev
```

<!--
    virtualenv will cause python3 and python3-virtualenv to be installed
-->

## <a name="tinyscheme">Build Tinyscheme</a>

This project contains a modified version of the Tinyscheme interpreter
for use within a secure enclave.  You **also** need a separate, plain
copy of Tinyscheme to use outside the enclave for contract development. Use the following
command to install tinyscheme.


```bash
sudo apt install tinyscheme
```

## Install SGX Platform Libraries and Services

You also need the SGX Platform Services (PSW) so an enclave can properly
be launched and can receive quotes for remote attestation.
Following commands will download and install PSW:

```bash
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install build-essential python #dependencies
sudo apt-get install -y sgx-aesm-service libsgx-urts libsgx-uae-service
```

if you want to debug, also install following packages
```bash
sudo apt-get install -y libsgx-enclave-common-dbgsym sgx-aesm-service-dbgsym libsgx-urts-dbgsym libsgx-uae-service-dbgsym
```

Note: If you are behind a proxy, you will have to configure the proxy settings
in `/etc/aesmd.confg` and restart aesmd with `systemctl restart aesmd.

## Install the SGX SDK

Private Data Objects has been tested with version 2.15.1 of the SGX
SDK. You can download prebuilt binaries for the SDK and kernel drivers
from [01.org](https://download.01.org/intel-sgx/sgx-linux/2.15.1/distro/ubuntu20.04-server/).

The following commands will download and install version 2.15.1 of the SGX
SDK. When asked for the installation directory, we suggest that you install
the SDK into the directory `/opt/intel`.

```bash
DRIVER_REPO=https://download.01.org/intel-sgx/sgx-linux/2.15.1/distro/ubuntu20.04-server/
SDK_FILE=sgx_linux_x64_sdk_2.15.101.1.bin

wget ${DRIVER_REPO}/${SDK_FILE} -P /tmp
chmod a+x /tmp/${SDK_FILE}
echo -e "no\n/opt/intel" | sudo /tmp/${SDK_FILE}
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

Ubuntu 20.04 does not ship a version of `binutils` that
includes mitigations for LVI attacks. However, recent
releases of SGX SSL expect these mitigations to be in place.

Intel provides binary distributions of `binutils` (version 2.32)
that contain the necessary LVI mitigations. The following
commands will download and install these binaries:

```bash
wget "https://download.01.org/intel-sgx/sgx-linux/2.15.1/as.ld.objdump.r4.tar.gz" -P /tmp
sudo mkdir /opt/intel/sgxsdk.extras
sudo tar -xzf /tmp/as.ld.objdump.r4.tar.gz -C /opt/intel/sgxsdk.extras
export PATH=/opt/intel/sgxsdk.extras/external/toolset/ubuntu20.04:${PATH}
```

## Build and Install SGX SSL

SGX OpenSSL is a compilation of OpenSSL specifically for use within SGX
enclaves. We have tested PDO with SGX SSL version `lin_2.10_1.1.1g`

Detailed instructions for building and installing SGX SSL is available
from the
[Intel SGX SSL github repository](https://github.com/intel/intel-sgx-ssl).

Follow these steps to compile and install version `lin_2.10_1.1.1g`:

- Ensure you have the SGX SDK environment variables activated:
```bash
source /opt/intel/sgxsdk/environment
```

- Clone the SGX SSL source:
```bash
git clone 'https://github.com/intel/intel-sgx-ssl.git'
```

- Check out the recommended version (`lin_2.10_1.1.1g`):

```bash
cd intel-sgx-ssl
git checkout lin_2.10_1.1.1g
```

- Download the OpenSSL source package that will form the base of this
SGX SSL install:

```bash
cd openssl_source
wget 'https://www.openssl.org/source/openssl-1.1.1g.tar.gz'
cd ..
```

- Set the environment variable for hardware or simulation mode. For
simulation mode use `export SGX_MODE=SIM`. For hardware mode use `export
SGX_MODE=HW`. Note that to build in hardware and run the tests in hardware
mode you must have installed the [SGX kernel driver](install.md).

- Compile and install the SGX SSL project.
```bash
cd Linux
make all
sudo make DESTDIR=/opt/intel/sgxssl install
```

- Export the `SGX_SSL` environment variable to enable the build
utilities to find and link this library.  Consider adding this to your
login shell script (`~/.bashrc` or similar)

```bash
export SGX_SSL=/opt/intel/sgxssl
```

## Build and Install PDO

Assuming you have installed and configured the pre-requisites in the
default location lcations, the following commands will build and install
PDO into a Python virtual environment in the directory
`${PDO_SOURCE_ROOT}/build/_dev`.

```bash
export SGX_MODE=SIM
export SGX_SSL=/opt/intel/sgxssl
source /opt/intel/sgxsdk/environment
source ${PDO_SOURCE_ROOT}/build/common-config.sh

cd ${PDO_SOURCE_ROOT}/build
make
```

## Running the Ledger

Hyperledger Private Data Objects supports two types of ledgers
to store data object instances and state, and to guarantee update
atomicity.

Application logic is implemented through the use of Transaction
Processors; transaction processors enable the distributed ledger to handle
application requests. This repository contains the code required to build
Transaction Processors that handle PDO requests.

Currently, PDO supports one type of ledger: Microsoft CCF.

We recommend running a ledger instance locally in the provided Docker image:
```
cd $PDO_SOURCE_ROOT
mkdir -p $PDO_LEDGER_KEY_ROOT
make -C docker test-env-setup # for CCF ledger use make -C docker test-env-setup-ccf-only
cp docker/ccf_keys/*.pem $PDO_LEDGER_KEY_ROOT # only for CCF ledger
```

For details on how to configure PDO for a given ledger, see [environment.md](./environment.md).

### Build and Install Ledger Natively

It is also possible to run the ledger natively on the host.

See [HERE](../ccf_transaction_processor/Readme.md) to learn more about the
ccf based transaction processor. Currently PDO supports CCF ledger under
the SIMULATE mode for PDO enclaves, and virtual mode for CCF enclaves.

When using CCF based ledger, every pdo client must install CCF base using
tarball from CCF release page.
This enables use of CCF client modules from the CCF base package. Please
see instructions in (../ccf_transaction_processor/Readme.md) for host
installation details.

## Testing the Installation

Once you have a ledger instance running, you can run the PDO unit tests:
```
cd $PDO_SOURCE_ROOT/build
make test
```
