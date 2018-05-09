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

Ubuntu 16.04 is recommended for both Sawtooth and PDO. Sawtooth and PDO may run
on other Linux distributions, but the installation process is likely to be more
complicated, and the use of other distribuitons is not supported by their
respctive communities at this time.

# <a name="environment"></a>Environment Variables
Summary of all environment variables required to build Hyperledger Private Data
Objects. Follow the instructions in the remainder of this document to install
and configure these components.

- `SGX_SDK` and `LD_LIBRARY_PATH` including SGX libraries
These are used to find the Intel&reg; Software Guard Extensions (SGX) Software
Development Kit (SDK). They are normally set by sourcing the SGX SDK activation
script (e.g. `source /opt/intel/sgxsdk/environment`)

- `TINY_SCHEME_SRC`
Used to locate a compatible source distribution of Tinyscheme, which is used to
run contracts.

- `SGX_SSL`
Used to locate an SGX-compatible version of OpenSSL

- `PDO_ENCLAVE_PEM`
This needs to be set to a valid enclave signing key. You can generate one
yourself using openssl, then export the path to it:
```
openssl genrsa -3 -out private_rsa_key.pem 3072
export PDO_ENCLAVE_PEM=`pwd`/private_rsa_key.pem
```

# <a name="packages"></a>Required Packages
On a minimal Ubuntu system, the following packages are required. Other
distributions will require similar packages.
```
sudo apt-get update
sudo apt-get install -y cmake swig pkg-config python3-dev python3-venv software-properties-common python3-dev virtualenv curl tinyscheme git unzip
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

If you plan to run this on SGX-enabled hardware, you will need the SGX driver,
PSW, and SDK. If running only in simulator mode (no hardware support), you only
need the SGX SDK. To learn more about Intel SGX, read the Intel SGX SDK
doumentation [here](https://software.intel.com/en-us/sgx-sdk/documentation) or
visit the Intel SGX homepage [here](https://software.intel.com/en-us/sgx).

You can find the Linux installation instructions for SGX at the
[main SGX Github page](https://github.com/intel/linux-sgx). It is recommended
to install Intel SGX SDK in /opt/intel/sgxsdk because the SGX OpenSSL library
expects the Intel SGX SDK in this location by default.

Make sure you have the `SGX_SDK` and `LD_LIBRARY_PATH` environment variables
active for your current shell session before continuing. They are normally set
by sourcing the SGX SDK activation script (e.g. `source /opt/intel/sgxsdk/environment`)

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
wget 'http://http.us.debian.org/debian/pool/main/o/openssl/libssl1.1_1.1.0h-2_amd64.deb'
wget 'http://http.us.debian.org/debian/pool/main/o/openssl/libssl-dev_1.1.0h-2_amd64.deb'
sudo dpkg -i libssl1.1_1.1.0h-2_amd64.deb
sudo dpkg -i libssl-dev_1.1.0h-2_amd64.deb
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
You might also want to extend `LD_LIBRARY_PATH`, e.g., as
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
- Download the necessary components (you may need a newer version if your base system uses newer than 1.1.0h)
 - OpenSSL v1.1.0h: `wget 'https://www.openssl.org/source/openssl-1.1.0h.tar.gz'`
 - SGX SSL (latest version): `git clone 'https://github.com/intel/intel-sgx-ssl.git'`

- Move the OpenSSL source into the correct folder
```
mv openssl-1.1.0h.tar.gz intel-sgx-ssl/openssl_source
```
- Compile the sgxssl project
```
cd intel-sgx-ssl/Linux
./build_sgxssl.sh
```
- Install the sgxssl folder somewhere on your file system (example here installs for all users using sudo)
```
sudo mkdir -p /opt/intel/sgxssl
cd /opt/intel/sgxssl
sudo tar xzf ~/sgxssl/intel-sgx-ssl/Linux/sgxssl.2.1.100.99999.tar.gz
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
- If you get the error:
`./test_app/TestApp: symbol lookup error: /usr/lib/libsgx_uae_service.so: undefined symbol: _ZN6google8protobuf2io16CodedInputStream20ReadVarint32FallbackEPj`
you are probably not running on SGX enabled hardware. The sgx-ssl test
application only works with "real" SGX, not the simulator. So just remove the
lines from the build script that reference the test\_app
```diff
diff --git a/Linux/build_sgxssl.sh b/Linux/build_sgxssl.sh
index 9ff2799..02469f8 100755
--- a/Linux/build_sgxssl.sh
+++ b/Linux/build_sgxssl.sh
@@ -164,9 +164,6 @@ rm -rf $OPENSSL_VERSION || clean_and_ret 1
 cd $SGXSSL_ROOT/sgx || clean_and_ret 1

 make OS_ID=$OS_ID SGXSDK_INT_VERSION=$SGXSDK_INT_VERSION $LINUX_BUILD_FLAG || clean_and_ret 1 # will also copy the resulting files to package
-if [[ $1 != "linux-sgx" && $2 != "linux-sgx" ]] ; then
-   ./test_app/TestApp || clean_and_ret 1 # verify everything is working ok
-fi
 make clean || clean_and_ret 1


@@ -196,15 +193,9 @@ rm -rf $OPENSSL_VERSION || clean_and_ret 1
 cd $SGXSSL_ROOT/sgx || clean_and_ret 1

 make OS_ID=$OS_ID SGXSDK_INT_VERSION=$SGXSDK_INT_VERSION SGX_MODE=SIM DEBUG=1 $LINUX_BUILD_FLAG || clean_and_ret 1 # will also copy the resulting files to package
-if [[ $1 != "linux-sgx" && $2 != "linux-sgx" ]] ; then
-   ./test_app/TestApp || clean_and_ret 1 # verify everything is working ok
-fi
 make clean || clean_and_ret 1

 make OS_ID=$OS_ID SGXSDK_INT_VERSION=$SGXSDK_INT_VERSION DEBUG=1 $LINUX_BUILD_FLAG || clean_and_ret 1 # will also copy the resulting files to package
-if [[ $1 != "linux-sgx" && $2 != "linux-sgx" ]] ; then
-   ./test_app/TestApp || clean_and_ret 1 # verify everything is working ok
-fi
 make clean || clean_and_ret 1
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

