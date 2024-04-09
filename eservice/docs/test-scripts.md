<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# Running System Test Scripts #

Two system test scripts provide a means for validating the correct
operation of various parts of the Private Data Objects project. The
first, ``test-request.py`` uses a simple, fixed contract with a single
operation that increments a counter in the state of the contract. The
second script, ``test-contract.py`` supports arbitrary contracts and
reads the messages from a file.

Both scripts can optionally include the provisioning service, enclave
service and a ledger.

The flow for both scripts includes the following:
1. create and register an enclave, if necessary
2. create and register a contract
3. send a series of messages to the contract and save the results in the ledger

Depending on the log level, the scripts will generate information about
the operations that are performed. If the loglevel is set to ``warn``,
then only errors will be shown. Regardless of the loglevel, the script
will exit with status 0 if successful and 255 if an error occurred. This
can be used for automated tests.

The tests assume that the PDO package has been installed in a Python
virtualenv pointed to be the environment variable
``PDO_HOME``. Instructions for configuring and running enclave and
provisioning services is provided seperately.

## Environment ##

The expectation is that the environment variable ``PDO_HOME`` points
to the root of the pdo install in your virtualenv directory where the
PDO packages have been installed. Typically, you would set ``PDO_HOME``
to ``$VIRTUAL_ENV/opt/pdo``.

## Configuration File ##

Default values for test configuration are set in a ``toml`` configuration
file. The default configuration file is ``eservice_tests.toml`` located
in either the current directory on in ``./etc``. The ``--config``
command line parameter can be used to specify an alternate configuration
file.

The following configuration variables can be specified:

* ``Ledger``
  * ``LedgerURL`` -- the URL to use for the ledger; if no value is
  specified, then the test will not send transactions to the ledger
  * ``Organization`` -- the organization name used in the enclave
  registration transaction; unused if an eservice is specified

* ``PDO``
  * ``DataPath`` -- directory for writing data files
  * ``SourceSearchPath`` -- list of directories to search for contract
  source

* ``Logging``
  * ``LogLevel`` -- set the verbosity of logging, one of ``debug``,
    ``info``, ``warn``, ``error``
  * ``LogFile`` -- name of the file used to capture logs, ``__screen__``
  will send all logging information to the console

* ``EnclaveModule``
  * ``ias_url`` --  URL of the Intel Attestation Service (IAS) server (ignored)
  * ``sgx_key_root`` -- folder containing the sgx keys (ignored)

* ``contract`` -- the base name of the contract to use, this is
  expected to reference a file found in ``SourceSearchPath``

* ``eservice-url`` -- the URL of an enclave service, if no enclave
  service is specified, a local enclave will be created

* ``pservice-urls`` -- a list of URLs for provisioning services, if no
  provisioning service URLs are specified, provisioning secrets will be
  created locally

Most configuation parameters can be overridden through command line
parameters as described below.

## Common Command-Line Parameters ##

The two test scripts share most command line parameters. Most command
line parameters can be specified in a configuration file. By default,
the configuration file

* ``--config <string>`` -- name of the configuration file
* ``--config-dir <string>`` -- path to the configuration file if the config file
  name is not absolute
* ``--ledger <string>`` -- URL for the ledger
* ``--no-ledger`` -- flag to indicate that no ledger should be used
* ``--data <string>`` -- path to directory used for storing data
* ``--secret-count <integer>`` -- number of secrets to generate if no
  provision service is used
* ``--eservice-url <string>`` -- URL for the enclave service
* ``--pservice <string> <string> ...`` -- list of URLs for provisioning
  ``--eservice-db`` -- json file for eservice database
  ``--eservice-name`` -- the name of an enclave service as in the client's eservice database

  services
* ``--logfile <string>`` -- name of the log file to use, ``__screen__``
  dumps the log to the console
* ``--loglevel (debug|info|warn|error)`` -- verbosity of the log

## test-request.py ##

The ``test-request.py`` script uses the ``mock-contract`` contract with
a single operation to increment a counter in the state of the
contract. In addition to the common command-line parameters, this script
adds the following options:

* ``--iterations`` -- the number of increment operations to perform

The ``mock-contract`` is a simple contract that defines operations on a
single counter.

## test-contract.py ##

The ``test-contract.py`` script takes a contract and a file of messages
to send to the contract. In addition to the common comand-line
parameters, this script adds the following options:

* ``--contract <string>`` -- name of the contract to use, defaults to
  ``mock-contract``
* ``--expressions <string>`` -- the name of a file that contains
  messages to send to the contract, one message per line

The expression file contains expressions that will be sent
as messages to an instance of the contract. For example, the following
expression file would increment the value of the counter in a
``mock-contract`` twice and then retrieve the value. By default, the
expression file used will match the contract name with a '.exp'
extension.

## Examples ##

```bash
# Run the test only using a locally instantiated enclave
$ python test-request.py --no-ledger

# Run the test with a ledger receiving transactions
$ python test-request.py --ledger ${PDO_LEDGER_URL} --loglevel warn

# Run the test with the integer key contract, a ledger
# and two provisioningservices
$ python test-contract.py --ledger ${PDO_LEDGER_URL} \
    --pservice http://localhost:7101 http://localhost:7102 \
    --contract integer-key

# Run the test with the mock-contract, a ledger, two provisioning
# services, and an enclave service, 500 increment operations
$ python test-request.py --ledger ${PDO_LEDGER_URL} \
    --pservice http://localhost:7101 http://localhost:7102 \
    --eservice http://localhost:7001 \
    --iterations 500

```
