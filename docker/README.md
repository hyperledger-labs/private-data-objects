<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

Overview
-------------
This directory contains configurations to run PDO with docker and docker-compose.
This allows you to develop easily on non-ubuntu 18.04 machines and/or without "poluting" your install.
It also enables easy end-to-end setups with a sawtooth ledger and automated build & tests using the target 'test' of the Makefile.

The easiest way to get started is to run 'make test' which will build your current
locally committed branch and run the end-to-end tests of a completely freshly setup
sawtooth ledger in default configuration.
Starting from a good branch, this should also normally successfully run and hence
allows making sure that the docker setup is ok.
This also might be the most common use-case as it is the easiest way to robustly check your
commits before a PR and shouldn't require docker and docker-compose understanding.
By default it will build and run tests only in SGX simulator mode but it does honor
the SGX_MODE environment variable if you want to test in SGX HW mode (in which case, though,
will have to put proper sgx key & cert files (sgx_spid.txt, sgx_spid_key_cert.pem, sgx_ias_key.pem)
into the sgx sub-directory or define the `PDO_SGX_KEY_ROOT` environment variable.
See `../build/common-config.sh --help` for more information on PDO_SGX_KEY_ROOT and related settings.

If you want to run your own experiments in the test environment, you can use the `test-env-setup`
make target which launches the various containers of the topology. You can then
interact with the environment using the standard docker-compose commands like
`exec` to log into individual containers, `ps` to see status, `top` to monitor
cpu inside containers or `down` to shut the invironment down again.
See [docker-compose commandline reference](https://docs.docker.com/compose/reference/)
for more information on commands.  Note also the 'run' makefile target which
should simplify the invocation by guaranteeing that the parameters are consistent
with what was used during `test-env-setup`, just invoke as `make run ARGS='<docker-compose subcommand & args>'`

For more advanced docker-compose usage, check the headers in the yaml files.
Similarly, the Dockerfiles also have additional information in the header if you want
to use them separately.

Preparation
-------------
As prerequisite, you will need docker and docker-compose installed.
On Ubuntu 18.04, this simply means running an `apt install docker-compose`.

If you are behind a proxy, there are a few more things to do to configure docker.
See [docker docu](https://docs.docker.com/config/daemon/systemd/#httphttps-proxy)
for more info but assumming you run Ubuntu 18.04 and have the `http_proxy`, `https_proxy`
and `no_proxy` environment variables defined, it more or less this means:
```bash
  mkdir /etc/systemd/system/docker.service.d
  /bin/echo -e "[Service]\nEnvironment='HTTP_PROXY=${http_proxy}' 'HTTPS_PROXY=${https_proxy}' 'NO_PROXY=${no_proxy}'\n" \
    > /etc/systemd/system/docker.service.d/http-proxy.conf
  systemctl daemon-reload
  systemctl restart docker
```
If your system runs systemd-resolved (which is now default for ubuntu),
you also might have to run
```bash
  ln -sf ../run/systemd/resolve/resolv.conf /etc/resolv.conf # originally was ../run/systemd/resolve/stub-resolv.conf
```
This is necessary due to, on the one hand, systemd.resolved only listening to loopback address in a way
which makes it unreachable from docker and, on the other hand, docker limitations which
hardcodeds google DNS address with no option to configure custom DNS when it cannot re-use DNS config
from /etc/resolv.conf as in this case.
Note: This should be fixed in docker 18.09+, see [this](https://github.com/moby/moby/pull/37485)
and [this](https://github.com/docker/libnetwork/issues/2068) link.
