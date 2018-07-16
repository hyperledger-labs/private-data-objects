# Vetting Organization Contract #

The vetting organization contract is a relatively simple contract that
provides a root for building trust chains of issuers for a particular
asset type. The expectation is that the actual vetting of asset issuers
happens interactively. The vetting organization contract provides a
means of recording decisions to grant authority to asset issuers.

## State Update Methods ##

* `(initialize _asset-type-id)` -- initialize the object with an asset
type identifier, must be invoked by the object creator
    * `_asset-type-id` -- the identifier returned by `(get-identifier)`
      from the asset type contract object

* `(add-approved-key _issuer-verifying-key)` -- record the decision to approve
an asset issuer, must be invoked by the object creator
    * `_issuer-verifying-key` -- the ECDSA verifying key from the asset issuer
      contract object

## Immutable Methods ##

* `(get-verifying-key)` -- get the ECDSA verifying key for the contract object

* `(get-authority _issuer-verifying-key)` -- create a proof of authority
  for a previously approved issuer, the structure of the proof of
  authority is described below
    * `_issuer-verifying-key` -- the ECDSA verifying key from the asset issuer
      contract object
