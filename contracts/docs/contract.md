<!--- -*- mode: markdown; fill-column: 100 -*- --->
<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

# The VIP's Contract Language #

Gipsy is a language for developing contracts for private data objects based on the
[Scheme programming language](https://en.wikipedia.org/wiki/Scheme_(programming_language)). Gipsy
extends the [TinyScheme interpreter](http://tinyscheme.sourceforge.net/home.html) with
object-oriented extensions from the [Elk](http://www.dmn.tzi.org/software/elk/), a set of
cryptographic functions for signing and encryption, and a library of basic functions to simplify
contract development.

## Basics of a Contract ##

A contract is an object defined using the [object-oriented extensions](#Object-Oriented Extensions)
provided by Gipsy. Methods defined by the contract object handle messages sent to the contract. For
example, the ``simple-contract`` class shown below defines handlers for two messages: ``get_value``
and ``inc_value``. A client can send a message to the contract like ``'(inc_value)`` or
``'(get_value)``.  The contract enforces a policy that only the creator of the contract may perform
either operation.

```scheme
(define-class simple-contract
  (instance-vars
   (creator (get ':message 'originator))
   (value 0)))

(define-method simple-contract (get_value)
  (let* ((requestor (get ':message 'originator)))
    (assert (string=? requestor creator) "only the creator can get the value"))
  value)

(define-method simple-contract (inc_value)
  (let* ((requestor (get ':message 'originator)))
    (assert (string=? requestor creator) "only the creator can inc the value"))
  (instance-set! self 'value (+ value 1))
  value)
```

## Building the Contract Source ##

In general, the contract and any functions beyond those provided by the Gipsy interpreter must be
packaged into a single file. While there are many ways to do this, the PDO contracts package
provides helper functions for compiling a contract and any supporting files into a single image. The
``contract-builder`` utility package defines a function, ``build-contract`` that takes as parameters
an output file, an input file, and a list of directories to search for included files. A simple way
to build a contract is to define a build file like the one below which builds the simple
contract. This file can be executed to build the contract using the standard TinyScheme interpreter
as: ``tinyscheme -1 simple-contract.bld``.

```scheme
(load "util-packages/contract-builder.scm")

(define package-directories
  '("." "contracts" "packages" "util-packages" "../../common/interpreter/gipsy_scheme/packages"))

(define contract-input "simple-contract.scm")
(define contract-output (string-append "_" contract-input))

(build-contract contract-output contract-input package-directories)
```

The ``build-contract`` function defines handlers for two expressions that can be used to include
dependent sources: ``require`` and ``require-when``. A file identified by a ``require`` expression
will be included one time. A file identified by a ``require-when`` expression will be included if
the supplied predicate holds.

## Gipsy Language Details ##

The Gipsy interpreter is based on TinyScheme which implements a substantial subset of the [Scheme
R5RS](http://www.schemers.org/Documents/Standards/R5RS/HTML/) standard.

### Object-Oriented Extensions ###

The object extensions in Gipsy are based on the
[OOPS package](http://www.dmn.tzi.org/software/elk/doc/oops.html) from Elk Scheme. The OOPS extension defines
several functions for defining, creating and interacting with objects:

* ``define-class``
* ``define-method``
* ``make-instance``
* ``make-instance*``
* ``class-set!``
* ``instance-set!``
* ``class?``
* ``instance?``
* ``send``

### Contract Properties ###

Gipsy uses symbol properties to pass meta-information about the private data object into the
contract classes. The function ``get`` can be used to retrieve the value of a symbol property and
the function ``put`` can be used to set the value of a property. For example, ``(get ':message
'originator)`` will retrieve the identity of the originator of a message and ``(put ':ledger
'dependencies dependencies)`` adds a contract dependency to the state update.

The following properties are interpreted:

* ``:message``
    * ``originator`` -- (read) the identity of the message originator

* ``:ledger``
    * ``dependencies`` -- (write) an association list of contract dependencies

* ``:contract``
    * ``id`` -- (read) contract id
    * ``state`` -- (read) base64 encoded hash of the encrypted contract state
    * ``creator`` -- (read) identity of the contract creator
    * ``code-hash`` -- (read) base64 encoded hash of the contract code and contract name

### Cryptographic Library ###

* Symmetric Key Encryption
    * ``aes-encode-key``
    * ``aes-encode-iv``
    * ``aes-encrypt``
    * ``aes-decrypt``

* Public Key Encryption
    * ``rsa-create-keys``
    * ``rsa-encrypt``
    * ``rsa-decrypt``

* ECDSA Signing
    * ``ecdsa-create-signing-keys``
    * ``ecdsa-sign-message``
    * ``ecdsa-verify-signature``

* Additional Functions
    * ``compute-message-hash``
    * ``random-identifier``

### Other Useful Functions ###

* assert
* package
* catch/throw

### Other Useful Classes ###

#### Contract Base ####

#### Encryption Keys ####

#### Signing Keys ####
