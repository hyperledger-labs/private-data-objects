# Auction Contract #

The auction contract handles a multi-party auction for transfer of
ownership of assets between ledgers. For example, Alice offers three
blue marbles in exchange for the highest possible number of red
marbles.

## State Update Methods ##

* `(cancel-auction)`\
Cancel the offer, must be invoked by the auction creator. May not be
invoked once the auction is closed.

* `(cancel-bid)`\
Cancel a bid, must be invoked by the object creator. May not be invoked
by the auction winner once the auction is closed.

* `(close-auction)`\
Close the auction to further bidding. Commits the highest bidder to the
result of the auction. Must be invoked by the auction creator.

* `(confirm-close)`\
Confirm that the auction is closed. Must be invoked by the highest bidder.

* `(initialize _serialized-asset-request _root-authority-key)`\
Initialize the object, must be invoked by the object creator.

    * `_serialized-asset-request` -- serialized [asset request](protocol_objects.md#asset-request)

    * `_root-authority-key` -- ECDSA key for an asset authority (either an [issuer](issuer.md) or
      [vetting organization](vetting.md) that provides the root of trust

* `(offer-asset _serialized-authoritative-asset)`\
Offer an asset, must be invoked by the object creator.

    * `_serialized-authoritative-asset` -- the
      [serialized asset](protocol_objects.md#authoritative-asset) that will be offered for exchange

* `(submit-bid _serialized-authoritative-asset)`\
Submit a bid to the auction with an escrowed assets, the offered asset
must match the asset request including the minimum bid.

    * `_serialized-authoritative-asset` -- the
      [serialized asset](protocol_objects.md#authoritative-asset) that is offered in response to the
      auction

## Immutable Methods ##

* `(get-verifying-key)`\
Get the verifying key for the contract object.

    * *RETURNS* -- an ECDSA verifying key

* `(cancel-auction-attestation)`\
Get an attestation from the contract object that allows for release from escrow of offered assets.

    * *RETURNS* -- `(dependencies signature)`

* `(cancel-bid-attestation)`\
Get an attestation from the contract object that allows for release from escrow of bid assets.

    * *RETURNS* -- `(dependencies signature)`

* `(check-bid)`\
Get information about the bid submitted by the requestor.

    * *RETURNS* -- serialized [authoritative asset](protocol_objects.md#authoritative-asset)

* `(claim-bid)`\
Create a claim that can be given to the issuer of the bid assets to
claim ownership. Must be invoked by the auction creator.

    * *RETURNS* -- `(old-owner-identity dependencies signature)`

* `(claim-offer)`\
Create a claim that can be given to the issuer of the offered assets to
claim ownership. Must be invoked by the winning bidder.

    * *RETURNS* -- `(old-owner-identity dependencies signature)`

* `(examine-offered-asset)`\
Get information about the asset that is offered for exchange.

    * *RETURNS* -- serialized [authoritative asset](protocol_objects.md#authoritative-asset)

* `(examine-requested-asset)`\
Get information about the asset that is requested.

    * *RETURNS* -- serialized [asset request](protocol_objects.md#asset-request)

* `(max-bid)`\
Get information about the current maximum bid.

    * *RETURNS* -- `(asset-type-id amount)`
