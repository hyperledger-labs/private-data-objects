# Fair Exchange Contract #

The fair exchange contract handles the bi-lateral transfer of asset ownership between ledgers. For
example, Alice gives three blue marbles to Bob in exchange for four red marbles. This transaction
must atomically transfer ownership of assets in the blue marble asset ledger and the red marble
asset ledger. There are several different interactions that would be reasonable for a fair exchange;
this is just one implementation.

## State Update Methods ##

* `(initialize _serialized-asset-request _root-authority-key)`\
Initialize the object, must be invoked by the object creator.

    * `_serialized-asset-request` -- serialized [asset request](protocol_objects.md#asset-request)

    * `_root-authority-key` -- ECDSA key for an asset authority (either an [issuer](issuer.md) or
      [vetting organization](vetting.md) that provides the root of trust

* `(offer-asset _serialized-authoritative-asset)`\
Offer an asset, must be invoked by the object creator.

    * `_serialized-authoritative-asset` -- the
      [serialized asset](protocol_objects.md#authoritative-asset) that will be offered for exchange

* `(exchange-asset _serialized-authoritative-asset)`\
Respond to the offer with an asset for exchange, the offered asset must match the asset request.

    * `_serialized-authoritative-asset` -- the
      [serialized asset](protocol_objects.md#authoritative-asset) that is offered in response to the
      exchange request

* `(cancel-offer)`\
Cancel the offer, must be invoked by the object creator.

## Immutable Methods ##

* `(get-verifying-key)`\
Get the verifying key for the contract object.

    * *RETURNS* -- an ECDSA verifying key

* `(cancel-attestation)`\
Get an attestation from the contract object that allows for release from escrow of offered assets.

    * *RETURNS* -- `(dependencies signature)`

* `(examine-offered-asset)`\
Get information about the asset that is offered for exchange.

    * *RETURNS* -- serialized [authoritative asset](protocol_objects.md#authoritative-asset)

* `(examine-requested-asset)`\
Get information about the asset that is requested.

    * *RETURNS* -- serialized [asset request](protocol_objects.md#asset-request)

* `(claim-offer)`\
Create a claim that can be given to the issuer contract to claim ownership of the offered asset.

    * *RETURNS* -- `(old-owner-identity dependencies signature)`

* `(claim-exchange)`\
Create a claim that can be given to the issuer contract to claim ownership of the exchanged asset.

    * *RETURNS* -- `(old-owner-identity dependencies signature)`
