<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Exchange Scripts

This directory contains a number of pdo-shell scripts to test the
exchange contract family. The scripts assume that a complete
installation of the PDO client is complete.

The scripts use pdo-shell variables that can be set from the pdo-shell
invocation using the `-m` switch: `-m <variable> <value>`.

## Test Scripts

### `run-tests.sh`

This script sets up and runs the functional test suite for the exchange
contract family. The actual tests will be found in the pdo-shell script
`functional_test.psh`

### `setup.sh`

This script creates the keys and assets in preparation for the exchange
and auction tests. It will invoke many of the contract invocation
scripts in order to setup and execute the exchange and auction tests.

## Contract Invoctaion Scripts

Contract invocation scripts provide wrappers for basic interactions
with the exchange contract family.

The following pdo-shell variables are used:
* color -- the color to use for the marble
* data -- the directory where eservice database is stored
* save -- the directory where the contract objects are stored
* path -- the directory where the PSH scripts are stored

The script assumes that there are three keys available for each colorad
marble type:
* `${color}_type` -- keys used for the asset type object
* `${color}_vetting` -- keys used for the vetting rganization
* `${color}_issuer` -- keys used for the issuer

For the most part, the scripts will be invoke like this:

```bash
pdo-shell -s <command>.psh -m color <color> -m path <contract path>
```

### `approve_issuer.psh`

This script will allow a vetting organization to approve an issuer. The
vetting organization and issuer must be created first.

### `create_issuer.psh`

This script will create an issuer. The vetting organization and asset
type must be created first.

### `create_type.psh`

This script will create an asset type. This is the first script that
will generally be invoked.

### `create_vetting.psh`

This script will create a vetting organization. A vetting organization
is the root of a trust hierarchy of issuers for an particular asset
type.  The asset type must be created first.

### `initialize_issuer.psh`

This script will initialize an issuer that has been approved by
a vetting organization. The script copies the authority chain
from the vetting organization into the issuer.

## `issue.psh`

This script will issue assets for a particular issuee. The issuee must
have keys available. The script takes two additional parameter beyond
the common paramters.

* `issuee` -- the name of the invidual who will be issued assets, there
must be a public key in the key directory for the issuee Keys must be
available for the issuee.
* `count` -- the number of assets to be issued to the issuee

This script can be invoked as follows:

`$ pdo-shell -s issue.psh -m color <color> -m path <contract path> -m issuee <identity> -m count <count>`

## Support Scripts

### `create_eservice_db.psh`

Script to set up the eservice database. Should be removed later
in favor of a commonly available version of the script.

### `functional_test.psh`

This script provides a functional test of the various contract
types in the exchange contract family. In general, this should
not be invoked directly but should be called through `run-tests.sh`.

### `init.psh`

Simple initialization script that loads the plugins for the exchange
suite of contracts. This script also creates some enclave service
and provisioning service groups that are useful for creating contract
objects.
