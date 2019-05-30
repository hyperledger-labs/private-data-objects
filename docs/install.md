<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Instructions to Build and Install Private Data Objects

Private Data Objects (PDO) can be installed directly to a host system or
it may be installed through Docker. This document contains instructions
for both methods of installation.

PDO requires installation of the SDK for Intel Software Guard Extensions
(SGX). SGX can be used either in simulation mode or hardware
mode. Simulation mode will work even when there is no processor support
for SGX. However, simulation mode is not secure and is suitable soley
for development and demonstration. Hardware mode, which uses trusted
execution capabilities in the processor to protect confidentiality and
integrity of computation, requires appropriate processor
support. Information about supported processors is provided below.

## Recommended Host System

The required host-system configuration for Private Data Objects is to
separate the Private Data Objects components from the Sawtooth components. 
This means if you want to run PDO on a single physical host, either PDO or the
Sawtooth will have to run in a separate VM or container. In particular, to run
PDO in SGX HW mode, the PDO component has to run in an SGX-enabled environment. 
Below installation and configuration instructions will make sure that the host 
and the docker components fullfill this requirement.

Sawtooth (and the PDO transaction processors for Sawtooth) should be run on
Ubuntu 16.04.

Private Data Objects services (specifically the enclave service, provisioning
service, and the client) should be run on Ubuntu 18.04  (server or client). 
PDO also has been tested on Ubuntu 16.04 and 17.10. However, for these configuration
not all standard libraries match the required versions and you will have to, e.g., 
install by hand an openssl version >= 1.1.0g (the default libssl-dev on these 
platforms is still based on 1.0.2)

Sawtooth and PDO may run on other Linux distributions, but the installation
process is likely to be more complicated, and the use of other distributions is
not supported by their respective communities at this time.

## <a name="SGX">Intel Software Guard Extensions (SGX)</a>
### Overview

Private Data Objects uses the trusted execution capabilities provided by
Intel SGX to protect integrity and confidentiality. More information
about SGX can be found on the
[Intel SGX website](https://software.intel.com/en-us/sgx) including
[detailed installation instructions](https://download.01.org/intel-sgx/linux-2.4/docs/Intel_SGX_Installation_Guide_Linux_2.4_Open_Source.pdf).

SGX can operate in either simulation mode or hardware mode. Simulation
mode does not require any processor support for SGX and can be useful
for development and testing. However, simulation mode does not provide
any protection for confidential data and does not guarantee integrity of
execution. To use SGX in simulation mode set the `SGX_MODE` environment
variable to `SIM`:

```bash
export SGX_MODE=SIM
```

SGX hardware mode uses capabilities for trusted execution in the
processor to protect confidentiality and integrity of computation. SGX
hardware mode requires processor support for SGX
([commonly available on recent Intel processors](https://ark.intel.com/content/www/us/en/ark/search/featurefilter.html)).
To use SGX in hardware mode set the `SGX_MODE` environment variable to
`HW`:

```bash
export SGX_MODE=HW
```

The remainder of this section provides information about preparing to
run Private Data Objects using SGX in hardware mode. Specifically, there
are steps that must be taken to enable attestation of the hardware
platform using the Intel Attestation Service (IAS).

### SGX in Hardware Mode

#### Update the BIOS

It may be advisable to update your BIOS to pick up any recent
patches. For example, if you want to run PDO on an Intel NUC, you can
visit the
[Intel Download Center](https://downloadcenter.intel.com/)
(and select `Mini PCs`) to find the latest BIOS release. Other vendors
may provide similar updates.

Note: If the Trusted Computing Base (TCB) of the platform performing an
attestation is outdated, IAS can still verify an attestation; however,
the verification may include a `GROUP_OUT_OF_DATE` or
`CONFIGURATION_NEEDED` quote status. It is up to the verifier to decide
whether to trust an attestation from a platform whose TCB has been
identified as outdated. Note that PDO will flag this situation with a
warning.

#### Create an IAS Authentication Key

Access to IAS requires that a service provider create an identity (SPID)
and a client authentication key. To create the SPID and the key you
first need to register with the
[Intel Developer Portal](https://api.portal.trustedservices.intel.com/developer).

Once your registration is complete subscribe for a
[linkable quote](https://api.portal.trustedservices.intel.com/EPID-attestation)
to create the client authentication key. The key will be available from
your profile page.

Assuming that existing keys are found in `${PDO_SGX_KEY_ROOT}` (which
defaults to the directory
`${PDO_SOURCE_ROOT}/build/keys/sgx_simulation`),
copy the key from your profile page into a file called
`${PDO_SGX_KEY_ROOT}/sgx_spid_api_key.txt`.

In addition, your SPID can be found on your developer portal profile
page. Copy the contents of the SPID into the file
`${PDO_SGX_KEY_ROOT}/sgx_spid.txt`.

#### Install the SGX Kernel Driver (Hardware Support)

SGX can run in either simulation or hardware mode. No kernel driver is
required to run in simulation mode. However, if you plan to run with SGX
hardware support, it is necessary to install the SGX kernel driver. The
following commands will download and install v2.4 of the SGX kernel
driver (for Ubuntu 18.04 server):

```bash
wget https://download.01.org/intel-sgx/linux-2.4/ubuntu18.04-server/sgx_linux_x64_driver_778dd1f.bin
sudo /bin/bash sgx_linux_x64_driver_778dd1f.bin
```

Note that if you update your Linux kernel, you may need to reinstall the driver.

#### Install SGX Platform Services
You also need the SGX Platform Services (PSW) so an (HW) enclave can properly be launched and can receive quotes for remote attestation.
Following commands will download and install PSW:

```bash
sudo apt-get install libssl-dev libcurl4-openssl-dev libprotobuf-dev

wget https://download.01.org/intel-sgx/linux-2.4/ubuntu18.04-server/libsgx-enclave-common_2.4.100.48163-bionic1_amd64.deb
sudo dpkg -i libsgx-enclave-common_2.4.100.48163-bionic1_amd64.deb
```

If the installation of PSW (and kernel driver) was successfull, you should have a running PSW daemon (aesm_service) which you can confirm by running `systemctl status aesmd.service`.

## Configuration

PDO uses a number of environment variables to control build,
installation and operation. While PDO should build and run with only the
default values, some configuration may be required. A list of commonly
used environment variables is available [here](environment.md).

## Docker Installation

Docker provides the easiest way to install and run PDO. It allows you to
develop easily on a variety of systems and isolates all package
installations from the host. Further, it simplifies end-to-end setup
with a local Sawtooth ledger. Instructions for installation with docker are available
[here](docker_install.md).

## Host System Installation

While the docker installation simplifies installation and execution,
sometimes it is helpful to have more control over the
process. Instructions for host system installation are available
[here](host_install.md).
