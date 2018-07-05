# Asset Type Contract #

The asset type contract provides an identity for asset types that is anchored in the
blockchain. In the current design, there is no particular meaning intrinsically ascribed to the
identity; it simply provides a means to say two things are the same or two things are different.
That being said, this could be extended in the future into a more robust asset class
representation or even use this as a means of certifying issuers of a particular asset class.

## State Update Methods ##

* `(initialize _name _description _link)` -- initialize information about the asset type
    * `_name` -- a short name (32 characters) for the asset type
    * `_description` -- an extended description (256 characters)
    * `_link` -- a URL pointing to additional information (128 characters)

## Immutable Methods ##

* `(get-creator)` -- returns the ECDSA verifying key of the type's creator
* `(get-verfiying-key)` -- returns the ECDSA verifying key of the contract object
* `(get-identifier)` -- returns the unique identifier for the type, currently the contract identifier
* `(get-name)` -- returns the type's short name
* `(get-description)` -- returns the type's description
* `(get-link)` -- returns the type's URL
