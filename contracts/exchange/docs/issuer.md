# Issuer Contract #

The issuer contract maintains a balance sheet that captures ownership of assets. The issuer contract
is granted authority to issue assets by a [vetting organization](vetting.md). That authority is
captured in the contract and passed to assertions of asset ownership.

The issuer contract restricts participants to see only their own asset balances. Further, the
creator of the issuer contract may issue assets to a participant, but the contract does not grant
the right to see the balances after the initial issuance.

## State Update Methods ##

* `(initialize _asset-type-id _serialized-authority)`\
Initialize the contract object with an asset type identifier and a proof of authority, must be
invoked by the object creator.

    * `_asset-type-id` -- the identifier for the [asset type](asset_type.md), computed by the
      `get-identifier` method

    * `_serialized-authority` -- a [proof of authority](protocol_objects.md#proof-of-authority)
    rooted in a [vetting organization](vetting.md) that grants the contract object the right to
    issue assets of the specified type, computed by the `get-authority` method

* `(issue _owner-identity _count)`\
Assign ownership of assets to the given identity, must be invoked by the object creator.

    * `_owner-identity` -- ECDSA verifying key for owner of the assets

    * `_count` -- number of assets issued to the owner

* `(transfer _new-owner-identity _count)`\
Transfer ownership of some assets to a new identity, anyone can invoke the operation though it will
fail if the invoker lacks sufficient assets for the transfer.

    * `_new_owner-identity` -- ECDSA verifying key for the new owner of the assets

    * `_count` -- number of assets transferred

* `(escrow _escrow-agent-public-key)`\
Assign temporary responsibility for assets owned by the invoker to an escrow agent.

    * `_escrow-agent-public-key` -- ECDSA verifying key for the escrow agent, often this will be the
    veriying key from a contract object such as an [exchange object](fair_exchange.md)

* `(disburse _dependencies _signature)`\
Remove escrow for assets owned by the invoker.

    * `_dependencies` -- a list of state updates that must be committed prior to removing the escrow

    * `_signature` -- signature from the escrow agent granting the right to drop escrow on the
    balance

* `(claim _owner-identity _dependencies _signature)`\
Claim ownership of assets based on authority granted by an escrow agent.

    * `_owner-identity` -- the ECDSA verifying key of the current owner of assets to be claimed,
    these assets must be escrowed to the agent that creates the signature for the claim

    * `_dependencies` -- a list of state updates that must be committed prior to transferring
    ownership

    * `_signature` -- signature from the escrow agent granting the right to the invoker to claim
    ownership of the assets

## Immutable Methods ##

* `(get-verifying-key)`\
Get the verifying key for the contract object.

    * *RETURNS* -- an ECDSA verifying key

* `(get-balance)`\
Return the current number of assets owned by the invoker.

    * *RETURNS* -- an integer

* `(escrow-attestation)`\
Construct an authoritative asset that contains an attestation of escrow for the invoker's asset
balance.

    * *RETURNS* -- an [authoritative asset](protocol_objects.md#authoritative-asset)

## More on Escrow ##

Typically, the owner of an asset can both check the balance of assets owned and transfer some or all
of that balance to another party. However, when an asset is escrowed to an agent, the owner loses
some rights to perform operations on the asset. For example, the owner may continue to check on the
number of assets owned, but cannot transfer ownership of the asset to another party. For an asset
that has been escrowed, the agent takes responsibility to ensure that ownership of assets is done
under controlled circumstances.

The escrow agent is simply a signing authority. It can be a person, a service, or another contract
object. For the purpose of building a fair exchange protocol, the assets are escrowed to the fair
exchange contract object which then arbitrates the transfer of ownership for both parties.

The issuer contract class defines two methods for processing requests from an escrow agent. The
`disburse` method cancels an escrow. That is, the asset owner regains all rights to the asset. The
`claim` method transfers ownership of assets. In each case, the escrow agent provides the invoking
participant with a proof (in the form of a signed statement), that the operation can be performed.
