<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Client-Only Installation

Instructions in this document assume the environment variable
`PDO_SOURCE_ROOT` points to the PDO source directory. Information about
other [environment variables](environment.md) that control build and
installation is described below.

## Process Overview

- Setup the basic development environment
- Install required build dependencies
- Set up environment variables to configure the build
- Build the PDO package

## <a name="environment">Setup Build Environment</a>

On a minimal Ubuntu system, the following packages are required. Other
distributions will require similar packages.

```bash
sudo apt install -y cmake curl git pkg-config unzip xxd libssl-dev build-essential
sudo apt install -y swig python3 python3-dev python3-venv virtualenv
sudo apt install -y liblmdb-dev libprotobuf-dev libsecp256k1-dev protobuf-compiler libncurses5-dev
```

<!--
    virtualenv will cause python3 and python3-virtualenv to be installed
-->

## Build and Install PDO

Assuming you have installed and configured the pre-requisites in the
default location, the following commands will build and install
PDO into a Python virtual environment in the directory
`${PDO_SOURCE_ROOT}/build/_dev`.

```bash
source ${PDO_SOURCE_ROOT}/build/common-config.sh

cd ${PDO_SOURCE_ROOT}/build
make client
```
