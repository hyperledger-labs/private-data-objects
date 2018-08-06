<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Private Data Objects Requirements

This project depends on several freely available software components. These
must be installed and configured before compiling Hyperledger Private Data
Objects. This document describes how to get and compile these required
components.

# Table of Contents

- [Required Packages](#packages)
- [Environment Variables](#environment)
- [Software Guard Extensions (SGX)](#sgx)
- [OpenSSL](#openssl)
- [SGX OpenSSL](#sgxssl)
- [Troubleshooting SGX OpenSSL Installation](#troubleshooting)
- [Tinyscheme](#tinyscheme)

# Recommended host system

The recommended host-system configuration for Private Data Objects is to
separate the Private Data Objects components from the Sawtooth components. This
means (at least) two different physical systems if using SGX-enabled hardware.
If running in SGX simulation mode, this could be two virtual machines or
containers.

Sawtooth (and the PDO transaction processors for Sawtooth) should be run on
Ubuntu 16.04.

Private Data Objects services (specifically the enclave service, provisioning
service, and the client) should be run on Ubuntu 18.04. PDO has been tested on
Ubuntu 16.04, 17.10, and 18.04.

Sawtooth and PDO may run on other Linux distributions, but the installation
process is likely to be more complicated, and the use of other distributions is
not supported by their respective communities at this time.

# <a name="environment"></a>Environment Variables
Summary of all environment variables required to build Hyperledger Private Data
Objects. Follow the instructions in the remainder of this document to install
and configure these components.

- `SGX_SDK` and `LD_LIBRARY_PATH` including SGX libraries
These are used to find the Intel&reg; Software Guard Extensions (SGX) Software
Development Kit (SDK). They are normally set by sourcing the SGX SDK activation
script (e.g. `source /opt/intel/sgxsdk/environment`)

- `SGX_MODE`
This variable is used to switch between SGX simulator and hardware mode.
`SGX_MODE` is expected to be set to either `HW` or `SIM`.

- `TINY_SCHEME_SRC`
Used to locate a compatible source distribution of Tinyscheme, which is used to
run contracts.

- `SGX_SSL`
Used to locate an SGX-compatible version of OpenSSL

- `PDO_ENCLAVE_PEM`
This needs to be set to a valid enclave signing key. You can generate one
yourself using OpenSSL, then export the path to it:
```
openssl genrsa -3 -out private_rsa_key.pem 3072
export PDO_ENCLAVE_PEM=`pwd`/private_rsa_key.pem
```

# <a name="packages"></a>Required Packages
On a minimal Ubuntu system, the following packages are required. Other
distributions will require similar packages.
```
sudo apt-get update
sudo apt-get install -y cmake swig pkg-config python3-dev python3-venv python
sudo apt-get install -y software-properties-common virtualenv curl tinyscheme xxd
sudo apt-get install -y git unzip dh-autoreconf ocaml ocamlbuild libsecp256k1-dev
```

# <a name="protobuf"></a>Protobuf Compiler
Many components of the project use Google's Protocol Buffers (including SGX),
so installing support for them early is recommended. Protobuf v3 or later
support is required - check your package manager first to see what is
available. If a package is not available, follow these steps to compile and
install protobuf tools manually:

```
wget https://github.com/google/protobuf/releases/download/v3.5.1/protobuf-python-3.5.1.tar.gz
tar xzf protobuf-python-3.5.1.tar.gz
cd protobuf-3.5.1
./configure
make -j16
make check -j16
sudo make install
export LD_LIBRARY_PATH=/usr/local/lib
```

# <a name="sgx"></a>Software Guard Extensions (SGX)
Hyperledger Private Data Objects is intended to be run on SGX-enabled
Intel&reg; platforms. However, it can also be run in "simulator mode" on
platforms that do not have hardware support for SGX.


## SGX in Hardware-mode
If you plan to run this on SGX-enabled hardware, you will need the SGX driver,
PSW, and SDK. You can find the Linux installation instructions for SGX at the
[main SGX GitHub page](https://github.com/intel/linux-sgx). It is recommended
to install Intel SGX SDK in /opt/intel/sgxsdk because the SGX OpenSSL library
expects the Intel SGX SDK in this location by default.

Also, if using PDO jointly with Sawtooth, you will need to set
up the ledger with the appropriate parameters
([here](https://github.com/hyperledger-labs/private-data-objects/blob/master/sawtooth/docs/SETUP.md))
for the validation of attestation verifications from the Intel Attestation Service (IAS).
Namely: the enclave measurement, the basename and Intel Attestation Service (IAS) public key.
For information on how to create and register a certificate with IAS see [here](eservice/docs/REQUIREMENTS.md).

You will need to import the Intel IAS Attestation Report Signing CA Certificate,
in order to enable the verification of attestation inside enclaves. From the project root folder,
simply make sure you have a working internet connection and type the following:
```
cd common/crypto/verify_ias_report
./build_ias_certificates_cpp.sh
```
The script will download the root IAS certificate from the Intel website and
import it in the enclave code.

Finally, make sure you have the `SGX_SDK` and `LD_LIBRARY_PATH` environment variables
active for your current shell session before continuing. They are normally set
by sourcing the SGX SDK activation script (e.g. `source /opt/intel/sgxsdk/environment`).

## SGX in Simulator-mode
If running only in simulator mode (no hardware support), you only
need the SGX SDK. To learn more about Intel SGX, read the Intel SGX SDK
documentation [here](https://software.intel.com/en-us/sgx-sdk/documentation) or
visit the Intel SGX homepage [here](https://software.intel.com/en-us/sgx).

# <a name="openssl"></a>OpenSSL
OpenSSL is a popular cryptography library. This project requires OpenSSL
version 1.1.0h or later.

Many Linux distributions have an older version of OpenSSL installed by default.
If your version of OpenSSL is too old, follow these steps to compile a newer
version from source. If you already have a newer version than 1.1.0h, you can
skip this.

If using a Debian-based Linux distribution (Ubuntu, Mint, etc.) the recommended
path is to download and install pre-build OpenSSL packages for your system. For
example, to install OpenSSL v1.1.0h on an Ubuntu system:
```
wget 'http://http.us.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.0h-4_amd64.deb'
wget 'http://http.us.debian.org/debian/pool/main/o/openssl/libssl-dev_1.1.0h-4_amd64.deb'
sudo dpkg -i libssl1.1_1.1.0h-4_amd64.deb
sudo dpkg -i libssl-dev_1.1.0h-4_amd64.deb
sudo apt-get install -f
```

If you are unable to locate a suitable precompiled package for your system you
can build OpenSSL from source using the following commands. If you installed
the package directly as described above you do *not* need to do this. These
steps detail installing OpenSSL to the `install` directory under your current
directory location.
```
wget https://www.openssl.org/source/openssl-1.1.0h.tar.gz
tar -zxvf openssl-1.1.0h.tar.gz
cd openssl-1.1.0h/
mkdir ../install
./Configure --prefix=$(pwd)/../install
./config --prefix=$(pwd)/../install
THREADS=8
make -j$THREADS
make check
make test
make install -j$THREADS
cd ..
```

If the above succeeds, define/extend the `PKG_CONFIG_PATH` environment variable
accordingly, e.g.,
```
export PKG_CONFIG_PATH="$(pwd)/install/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
```
If you installed in a standard location (e.g., default /usr/local/lib) you might have to call 'ldconfig'; if in a non-standard location you might have to extend LD_LIBRARY_PATH, e.g., as
```
export LD_LIBRARY_PATH="$(pwd)/install/lib/${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

# <a name="sgxssl"></a>SGX OpenSSL
SGX OpenSSL is a compilation of OpenSSL specifically for use with Software
Guard Extensions secure enclaves.

This project specifically requires SGX OpenSSL based on OpenSSL version 1.1.0h
or later. It should match the version installed on your host system or set up
in the previous step.

Follow these steps to compile and install SGX SSL. Note that if you run into
trouble there is a [troubleshooting](#troubleshooting) section specifically for
SGX OpenSSL with fixes for commonly encountered problems.
- Ensure you have the SGX SDK environment variables activated for the current shell session (e.g. `source /opt/intel/sgxsdk/environment`)
- Create a new directory to build the sgxssl components
```
mkdir ~/sgxssl
cd ~/sgxssl
```

- Download the latest SGX SSL git repository:
```
git clone 'https://github.com/intel/intel-sgx-ssl.git'
```

- Download the OpenSSL source package that will form the base of this SGX SSL install:
```
cd intel-sgx-ssl/openssl_source
wget 'https://www.openssl.org/source/openssl-1.1.0h.tar.gz'
cd ..
```

- Compile and install the sgxssl project. If your system does not have SGX support, use `SGX_MODE=SIM` instead.
```
cd Linux
make SGX_MODE=HW DESTDIR=/opt/intel/sgxssl all test
sudo make install
```

- Export the `SGX_SSL` environment variable to enable the build utilities to find and link this library.
Consider adding this to your login shell script (`~/.bashrc` or similar)
```
export SGX_SSL=/opt/intel/sgxssl
```

## <a name="troubleshooting"></a>Troubleshooting SGX OpenSSL Installation
- If you get the error:
`./test_app/TestApp: error while loading shared libraries: libprotobuf.so.9: cannot open shared object file: No such file or directory`
you may not have libprotobuf installed. You can install it via:
```
sudo apt-get install libprotobuf-dev
```
- If you still get the above error about libprotobuf.so.9, your distribution
may not include the .so.9 version of libprotobuf. You can work around this by simply
creating a symbolic link to the current version like:
```
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s libprotobuf.so.10 libprotobuf.so.9
```

# <a name="tinyscheme"></a>Tinyscheme
This project contains a modified version of the Tinyscheme interpreter for use within a secure enclave.
You **also** need a separate, plain copy of Tinyscheme to use outside the enclave.

Download the Tinyscheme source:
```
cd ~
wget https://downloads.sourceforge.net/project/tinyscheme/tinyscheme/tinyscheme-1.41/tinyscheme-1.41.zip
```

Extract and compile it:
```
unzip tinyscheme-1.41.zip
cd tinyscheme-1.41
make
```

- Export the `TINY_SCHEME_SRC` environment variable to enable the build utilities to find and link this library.
Consider adding this to your login shell script (`~/.bashrc` or similar)
```
export TINY_SCHEME_SRC=~/tinyscheme-1.41
```

