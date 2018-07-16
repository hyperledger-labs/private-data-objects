# Asset Exchange Contract Suite #

The asset exchange suite of contracts demonstrates many of the capabilities of the private data
objects technologies.

Three contracts define the data elements of the asset exchange suite: the asset type contract, the
vetting organization contract, and the issuer contract.

An asset type contract object defines a unique, shared identifier for a type of asset and a schema
for the representation for assets of that type. For example, we might define a asset type contract
object for blue marbles. Since the identifier for the contract object is unique, it provides a
shared, unique identifier that can be used to refer to assets that are blue marbles.

A vetting organization contract object manages a list of contract objects authorized to issue
assets of a particular type. While actual vetting of an issuer occurs outside the contract object,
the object provides a means of recording the decision to authorize an issuer. In this way, the
vetting organization contract object provides a root of trust for issuers of a particular asset
type. Continuing the blue marble example, the Blue Marble Players Association might create a vetting
organization object to record the identities of local chapters that may issue blue marble holdings
to their members.

The issuer contract object maintains a balance sheet that captures ownership of assets of a
particular type. The issuer contract allows the creator of the contract object to issue assets (that
is, assign ownership of assets to a particular individual). However, once the initial issuance
occurs, confidentiality of transactions and balances is maintained; in this case, even the creator
of the issuer contract object is not granted the right to examine the quantity of assets owned by an
individual after the initial issuance. Local chapters of the Blue Marble Players Association each
create an issuer contract object to assign ownership of marbles to their members. Once the initial
issuance is complete, members can trade marbles, transfer ownership, or exchange different kinds of
marbles in complete confidentiality. And, for those who trust the Blue Marble Players Association,
those transactions can span local chapters.

While the issuer contract object supports simple ownership transfer, more complex multi-party
exchanges are managed through additional contracts. For example, an exchange contract mediates a
fair exchange of different kinds of marbles (e.g. Alice trades her red marbles for Bob's blue
marbles). More complex exchanges like a blind auction can be implemented as well.

## General Flow ##

The following examples assume that we want to support the exchange of red marbles and blue
marbles. We assume the following identities:

* Blue Marbles Player Association (BMPA) -- an oversight organization that tracks blue marble banks
* Blue Marble Chapter (BMC) -- a local chapter of the BMPA with a large store of blue marbles
* Red Marbles Player Association (RMPA) -- an oversight organization that tracks blue marble banks
* Red Marble Chapter (RMC) --a local chapter of the RMPA with a large store of red marbles
* Alice -- owns a number of blue marbles in in BMC
* Bob -- owners a number of red marbles in RMC

### Setup ###

The asset type and vetting organization contract objects allow for the establishment of a trust
anchor to verify the integrity of exchange operations. For each of the asset types, we need to set
up the asset type, the vetting organization, and one or more issuers. We'll walk through the
sequence of steps necessary for blue marbles; the same step is used to establish the trust anchors
for the red marbles.

1. The BMPA creates an asset type contract object for the blue marbles. The asset type contract
object defines a unique identifier (the current implementation uses the identity of the contract
object itself). In addition, information about the type (e.g. name, description, or a scheme for
data associated with assets of that type) can be provided.

2. The BMPA creates a vetting organization contract object where it can record record and report on
authorizations for organizations that issue blue marbles. When initializing the contract object, the
player association provides the type of asset that will be issued by authorized organizations.

3. Each local chapter that will issue blue marbles creates an issuer contract object. For now, we'll
just create the issuer contract object for the BMC chapter. When it is created, the BMC contract
object holds no authority to issue assets; that is, the issuer contract refuses to issue assets
until the issuer has been authorized. It must receive that authority from the BMPA. Out of band, the
BMPA verifies the integrity of BMP and records in the BMPA vetting organization contract object
authorization for the BMP issuer contract object to issue blue marble assets. Once the authorization
is complete, the BMC can retrieve a representation of the authorization from the BMPA contract
object (the structure of the authorization will be described later). That authorization is then
stored in the BMC issuer contract object.

4. Once the authority from the BMPA has been stored, the BMP may issue blue marble assets to its
members. The current implementation of the issuer contract does not limit the amount of assets that
can be issued; it would be a relatively straightforward extension for the BMPA authorization to
include a maximum number of assets that could be issued; a constraint that would be enforced by the
BMC issuer contract.

### Simple Fair Exchange ###

The fair exchange contract enables a simple, bi-lateral exchange of assets that are managed by
different issuers. For example, Alice and Bob (out of band) decide to exchange 100 red marbles for
100 blue marbles. A fair exchange contract coordinates the exchange of ownership to guarantee that
both sides receive their assets (or neither does).

![](./exchange_flow.png)
*Figure 1. Simple Fair Exchange Transaction Flow*

Figure 1 shows the flow of transactions that take place in a fair exchange. Each of these steps is
described below.

1. Alice creates an exchange contract object.

2. Alice initializes the exchange contract object with the requested number and type of asset
(i.e. the identifier from the red marble asset type contract object). While it is not shown in the
figure, Alice also provides the identity of a vetting organization that she trusts to authorize red
marble issuers. In this case, Alice uses the verifying key for the RMPA object.

3. In preparation for offering her blue marbles for exchange, Alice escrows her holding in the BMC
naming the exchange contract object as the escrow agent. Escrowing the blue marbles ensures that
Alice will not use those marbles in another transaction until the exchange contract object allows
it.

4. Alice records the blue marbles offered for exchange in the exchange contract object. To do this,
she requests a proof of escrow from the BMC. The proof contains three things: details about the
asset (i.e. 100 blue marbles), proof that a vetting organization authorized the issuer to issue blue
marbles, and the escrow claim. The escrow proof is set in the context of a particular instance of
the state of the BMC contract object. That is, the proof of escrow holds if and only if the current
state of the BMC (which captures that Alice's holding has been escrowed) has been committed to the
ledger. This requirement is captured by transaction dependencies that are enforced by the
Coordination and Commit transaction processor in Sawtooth. Figure 2 shows the dependencies between
state update transactions that must be enforced by the TP.

5. Once Alice finishes, Bob can examine the exchange object and see that Alice is offering 100 blue
marbles in exchange for 100 red marbles. Further, Bob can look at the authorization for Alice's
offer to convince himself that the Alice's issuer is appropriately vetted. Once satisfied, Bob goes
through the same process as Alice: he escrows his holding of red marbles, naming the exchange
contract object as the escrow agent.

6. Bob requests a proof of escrow from the RMC and submits it as the response to Alice's
request. The contract in the exchange object verifies the type and quantity of the asset and also
that Alice trusts Bob's issuer (that is, that the RMC was vetted by the RMPA). Assuming Bob's
response is accepted, the exchange contract object enters a "completed" state where no further
changes are accepted.

7. To complete the exchange, Bob and Alice independently request a claim from the exchange object
that tells the issuers to transfer ownership of assets. The claim contains information about the old
and new owners, and the identity of the exchange object (which must match the escrow state of the
assets). As with the escrow proof, the claim is situated in the context of a particular state
commit. That is, the claim is not valid unless the completed state of the exchange object is
committed to the ledger.

![](./dependencies.png)
*Figure 2. Fair Exchange Transaction Dependencies*

## Contract Details ##

* [Protocol Objects](protocol_objects.md)
* [Asset Type Contract](asset_type.md)
* [Vetting Organization Contract](vetting.md)
* [Issuer Contract](issuer.md)
* [Fair Exchange Contract](fair_exchange.md)
