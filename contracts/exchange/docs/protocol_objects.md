# Protocol Objects #

## Proof of Authority ##

A proof of authority captures the data necessary to verify a chain of trust for a particular asset
type. The chain is represented as a tuple: `(authorized-key dependencies signature
parent-authority)` where:

* `authorized-key` is an ECDSA verifying key that is authorized to issue assets. For example, it
might be the verifying key from the Blue Marble Chapter contract object. The proof of authority
implies that a claim of issuance or escrow is valid if it is signed by the private key corresponding
to the `authorized-key`.

* `dependencies` identifies the state of a contract object that contextualizes the authority (that
is, the state must be committed in the ledger for the authorization to be valid). `dependencies` is
a list of tuples that contain a contract identifier and state hash. The pair uniquely identifies a
committed state update for the authorizing contract object.

* `parent-authority` is either a recursive proof of authority or the ECDSA verifying key of the
contract object that serves as the root of the chain of trust. For example, if the parent authority
is a vetting organization like the BMPA, then the value of the `parent-authority` field would be the
verifying key from the BMPA contract object. Otherwise, the proof-of-authority object describes the
chain of authority for the parent.

* The `signature` is created by the parent authority using its ECDSA signing key. The `signature` is
computed over the asset type identifier, the authorized key, and the dependencies.

## Serialized Asset ##

The serialized asset object is an issuer independent representation of an asset that captures type,
count, owner and escrow status. The asset is represented as a list `(asset-type-id count owner
escrow-agent)` where:

* `asset-type-id` is the identifier for an [asset type](asset_type.md), computed by the
`get-identifier` method on the contract object.

* `count` is the number of instances of the asset type.

* `owner` is the ECDSA verifying key for the owner of the asset.

* `escrow-agent` is the ECDSA verifying key for the escrow agent.

## Authoritative Asset ##

The authoritative asset object extends the serialized asset with a proof that the asset is
valid. The proof consists of two primary parts, a [proof of authority](#proof-of-authority) for the
participant that signs the asset, and the signature from the current authority. The authoritative
asset is represented as a list `(serialized-asset dependencies signature proof-of-authority)` where:

* `serialized-asset` contains information about the asset itself, including the type, count, owner
and current escrow agent.

* `dependencies` identifies the state of a contract object that contextualizes the claim. That is,
the claim about the asset holds for the contact states listed in the dependencies. `dependencies` is
a list of tuples that contain a contract identifier and state hash. The pair uniquely identifies a
committed state update for the authorizing contract object.

* The `signature` is created by the current authority using its ECDSA signing key. The `signature` is
computed over the serialized asset and the dependencies.

* `proof-of-authority` captures the right for the current authority to make an attestation about the
state of an asset.

## Asset Request ##

An asset request creates a predicate that can be used to match assets to requests. Currently, the
asset request object allows specification of three conditions: asset type, count, and
owner. Any combination of conditions may be used. For example, Alice might request 3 blue marbles
from Bob. Or Alice might simply request blue marbles.

An asset request is represented as a list `(asset-type-id count owner)`.
