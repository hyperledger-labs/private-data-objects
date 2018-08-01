<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Exchange Scripts

This directory contains a number of pdo-shell scripts. The scripts
assume that a complete installation of the PDO client is complete.

The scripts use pdo-shell variables that can be set from the pdo-shell
invocation using the `-m` switch: `-m <variable> <value>`.

## init.psh

Simple initialization script that loads the plugins for the exchange
suite of contracts.

## create.psh

This script creates the contract objects required for a colored marble
exchange. The assumuption is that there are three keys available:

  - `${color}_type` -- keys used for the asset type object
  - `${color}_vetting` -- keys used for the vetting organization
  - `${color}_issuer` -- keys used for the issuer

Two pdo-shell variables are used:

  -  color -- the color to use for the marble
  -  path -- the path where the contract objects are stored

This can be invoked as follows:

`$ pdo-shell -s create.psh -m color <color> -m path <contract path>`

## issue.psh

This script issues assets to participants for a colored marble exchange.

The assumption is that the following keys are available:

    - `${color}_type` -- keys used for the asset type object
    - `${color}_vetting` -- keys used for the vetting organization
    - `${color}_issuer` -- keys used for the issuer
    - issuee -- keys for the participant being issued the assets

The following pdo-shell variables are assumed:

    - color -- the color to use for the marble (default = 'green')
    - path -- the path where the contract objects are stored (default = '.')
    - issuee -- name of the issuee, there must be a public key in the path (required)
    - count -- number of assets to issue (default = 100)

This can be invoked as follows:

`$ pdo-shell -s issue.psh -m color <color> -m path <contract path> -m issuee <identity> -m count <count>`

## exchange.psh

This script demonstrates the fair exchange of assets between two parties
where the only mediator is the contract object.

The following pdo-shell variables are assumed:

    - path -- the path where the contract objects are stored (default = '.')
    - offer_user -- the identity of the user initiating the exchange (default = user1)
    - offer_color -- the color to use for the offered marbles (default = 'green')
    - exchange_user -- the identity of the user responding to the exchange (default = user6)
    - exchange_color -- the color to use for the requested marbles (default = 'red')
    - request_count -- the number of marbles requested for the offered marbles (default = 60)

This can be invoked as follows:

`$ pdo-shell -s exchange.psh -m offer_user <identity> -m exchange_user <identity>`
