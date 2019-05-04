<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Overview

This directory contains configurations to run PDO with docker and docker-compose.
This allows you to develop easily on non-ubuntu 18.04 machines and/or
without "poluting" your install.  Additionally, it also enables easy
end-to-end setups with a local sawtooth ledger and automated end to
end tests.


# Preparation

## Installation of dependencies

As prerequisite, you will need docker and docker-compose installed.
On Ubuntu 18.04, this simply means running:
```bash
	sudo apt install docker-compose
```

## Proxy configuration

If you are behind a proxy, there are a few more things to do to configure docker.
See [docker docu](https://docs.docker.com/config/daemon/systemd/#httphttps-proxy)
for more info. Assumming you run Ubuntu 18.04 and have the `http_proxy`, `https_proxy`
and `no_proxy` environment variables defined, it essentially means:
```bash
  mkdir /etc/systemd/system/docker.service.d
  /bin/echo -e "[Service]\nEnvironment='HTTP_PROXY=${http_proxy}' 'HTTPS_PROXY=${https_proxy}' 'NO_PROXY=${no_proxy}'\n" \
    > /etc/systemd/system/docker.service.d/http-proxy.conf
  systemctl daemon-reload
  systemctl restart docker
```
If your system runs systemd-resolved (which is now default for
ubuntu), make sure you are running a version 18.09 of docker or
greater. Recently refreshed versions of ubuntu 18.04 should meet this
condition. If you have to use an older version of docker, you also
might have to run
```bash
  ln -sf ../run/systemd/resolve/resolv.conf /etc/resolv.conf # originally was ../run/systemd/resolve/stub-resolv.conf
```
This is necessary due to, on the one hand, systemd.resolved only
listening to loopback address in a way which makes it unreachable from
docker and, on the other hand, docker limitations which hardcodeds
google DNS address with no option to configure custom DNS when it
cannot re-use DNS config from /etc/resolv.conf as in this case.
See [this](https://github.com/moby/moby/pull/37485)
and [this](https://github.com/docker/libnetwork/issues/2068) link for
background.



# Getting Started

The easiest way to get started is to run
```bash
	make test
```
which will build your current locally committed branch and run the
end-to-end tests based on a completely freshly setup sawtooth ledger
in default configuration.  Starting from a good branch, this should
also normally successfully run and hence allows also making sure that
the docker setup is ok.

# End-to-end testing

You are also encouraged to run `make test` whenever you create a new pull
request as it is easiest way to robustly check your commits. Doing so
doesn't require any deeper understanding of docker or docker-compose
and should run out-of the box.

By default it will build and run tests only in SGX simulator mode but
the makefile does honor
the `SGX_MODE` environment variable if you want to test in SGX HW
mode (in which case, though, you will have to put proper sgx attestation info
files (`sgx_spid.txt`,  `sgx_spid_api_key`, `sgx_ias_key.pem`) into the 
sgx sub-directory or define the `PDO_SGX_KEY_ROOT` environment variable to
point to a suiteable destination.
See `../build/common-config.sh --help` for more information on
`PDO_SGX_KEY_ROOT` and related settings.


# Developing and manual testing with docker(-compose)

If you want to run your own experiments in the test environment, you
can run
 ```bash
make test-env-setup
```
which launches the various containers of the topology. You can then
interact with the environment using the standard docker-compose commands like
`exec` to log into individual containers, `ps` to see status, `top` to monitor
cpu inside containers or `down` to shut the invironment down again.
See [docker-compose commandline reference](https://docs.docker.com/compose/reference/)
for more information on commands.  To make sure these commands run
with settings consistent with on how you invoked `test-env-setup`, you
can invoke them with also with the makefile target  `run` . Just
invoke it as
```bash
	make run ARGS='<docker-compose subcommand & args>'
```
e.g.  run `make run ARGS='exec pdo-build bash'` to start a shell in
the pdo-build container.

If you define the `PDO_DEBUG_BUILD` environment variable, the make
commands will (with help of [`sawtooth.debugging.yaml`](sawtooth.debugging.yaml)) build
the code with debugging and and run docker containers such that
gdb/sgx-gdb-based debugging is possible.
Note though, that due to some docker(-compose)ism, terminating daemon
processes such as the ones started
by ps-start/es-start will run in zombie processes. They don't hold any
resources such as sockets or alike and subseequent
\*-start/\*-status/\*-stop script should work as expected.

While you can run end-to-end tests inside docker, sometimes it might
be easier to test outside so you can, e.g., monitor localhost traffic
with `wireshark` which is challenging within docker. Note that with
`make test-env-setup` (or `make test-env-setup-with-no-build` if you
are sure container images for PDO-TP and other components are already
properly built) you get a fresh sawtooth setup where ledger rest API
is also exposed to the host, i.e., the default url
`http://localhost:8008` does also work from the host and you can test
client and {e,s,p}services on the host with a fresh and
self-contained/single machine installation.

For more advanced docker-compose usage, check the headers in the yaml
files:
  - [sawtooth-pdo.yaml](sawtooth-pdo.yaml)
  - [sawtooth-pdo.local-code.yaml](sawtooth-pdo.local-code.yaml)
  - [sawtooth-pdo.proxy.yaml](sawtooth-pdo.proxy.yaml)
  - [sawtooth-pdo.sgx.yaml](sawtooth-pdo.sgx.yaml)
  - [sawtooth-pdo.debugging.yaml](sawtooth-pdo.debugging.yaml)

Similarly, the Dockerfiles also have additional information in the header if you want
to use them separately:
  - [Dockerfile.pdo-dev](Dockerfile.pdo-dev)
  - [Dockerfile.pdo-build](Dockerfile.pdo-build)
  - [Dockerfile.pdo-tp](Dockerfile.pdo-tp)


# Makefile customization

The makefile allows you some local overrides/customization via the (optional) `docker/make.loc`
file. E.g., you can add more debugging tools (apt packages) into your pdo containers and define HW sgx-mode as default
using a file like:
```bash
DOCKER_BUILD_OPTS=--build-arg ADD_APT_PKGS='vim gdb net-tools strace ltrace telnet net-tools vim dnsutils ed'
SGX_MODE=HW
```
