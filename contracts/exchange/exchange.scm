;; Copyright 2018 Intel Corporation
;;
;; Licensed under the Apache License, Version 2.0 (the "License");
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

;;
;; exchange.scm
;;
;; Orchestrate a fair exchange.
;;
;; Externalized asset: ((value <integer>) (owner <ecdsa verifying key>))

(require-when (member "debug" *args*) "debug.scm")

(require "contract-base.scm")
(require "exchange_common.scm")
(require "asset_request_class.scm")
(require "authoritative_asset_class.scm")

(define exchange-package
  (package
   ;; =================================================================
   ;; CLASS: _exchange
   ;; =================================================================
   (define-class _exchange
     (super-class base-contract)
     (instance-vars
      (exchange-state 'created)         ; created, initialized, offered, exchanged, canceled
      (asset-request-object #f)
      (root-authority-key "")
      (offered-authoritative-asset #f)
      (exchanged-authoritative-asset #f)))

   ;; -----------------------------------------------------------------
   ;; NAME: initialize
   ;;
   ;; DESCRIPTION:
   ;; Contract method called to initialize the exchange with the requested
   ;; asset description and root authority
   ;;
   ;; PARAMETERS:
   ;;    _serialized-asset-request -- serialized object of type asset-request-class
   ;;    _root-authority-key -- public key for the requested root of trust
   ;; -----------------------------------------------------------------
   (define-method _exchange (initialize _serialized-asset-request _root-authority-key)
     (assert (equal? creator (get ':message 'originator)) "only creator may prime the exchange")
     (assert (eq? exchange-state 'created) "exchange has already been primed")

     (instance-set! self 'asset-request-object (deserialize-asset-request _serialized-asset-request))
     (instance-set! self 'root-authority-key _root-authority-key)
     (instance-set! self 'exchange-state 'initialized)

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: offer-asset
   ;;
   ;; DESCRIPTION:
   ;; Contract method called to set the asset that will be offered for auction
   ;;
   ;; PARAMETERS:
   ;;    _serialized-authoritative-asset -- serialized object of type authoriative-asset-class
   ;; -----------------------------------------------------------------
   (define-method _exchange (offer-asset _serialized-authoritative-asset)
     (assert (equal? creator (get ':message 'originator)) "only creator may offer an asset")
     (assert (eq? exchange-state 'initialized) "offered asset has already been recorded")

     (let ((object (deserialize-authoritative-asset _serialized-authoritative-asset)))
       (assert (send object 'verify) "unable to verify offered asset authority")
       (let* ((asset-object (send object 'get-asset))
              (asset-owner-key (send asset-object 'get-owner))
              (escrow-key (send asset-object 'get-escrow-key))
              (exchange-key (send contract-signing-keys 'get-public-signing-key)))
         (assert (string=? asset-owner-key (get ':message 'originator)) "offer must come from asset owner")
         (assert (string=? escrow-key exchange-key) "asset was not escrowed to the exchange"))

       (instance-set! self 'offered-authoritative-asset object)

       ;; make sure the escrow transaction has been committed
       (let ((dependencies (send object 'get-issuer-authority) 'get-dependencies))
         (if (pair? dependencies)
             (put ':ledger 'dependencies dependencies)))

       (instance-set! self 'exchange-state 'offered))

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: cancel-offer
   ;;
   ;; DESCRIPTION:
   ;; Contract method called to change the state of the exchange to canceled.
   ;; The change allows for the offered asset to be disbursed.
   ;;
   ;; Note that because the current implementation does not handle failed
   ;; exchanges (see notes for exchange-asset) so allowing the offer to
   ;; be canceled makes it possible to prevent an exchanged asset from being
   ;; disbursed.
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method _exchange (cancel-offer)
     (assert (equal? creator (get ':message 'originator)) "only creator may cancel exchange")
     (assert (eq? exchange-state 'offered) "no assets offered")

     (instance-set! self 'exchange-state 'canceled))

   ;; -----------------------------------------------------------------
   ;; NAME: cancel
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method _exchange (cancel-attestation)
     (assert (equal? creator (get ':message 'originator)) "only creator may cancel exchange")
     (assert (eq? exchange-state 'canceled) "exchange is not canceled")
     (let ((offered-asset-object (send offered-authoritative-asset 'get-asset)))
       (create-cancellation offered-asset-object creator contract-signing-keys)))

   ;; -----------------------------------------------------------------
   ;; NAME: examine-offered-asset
   ;;
   ;; DESCRIPTION:
   ;; Contract method to retrieve the offered asset.
   ;;
   ;; RETURNS:
   ;; Serialized authoritative asset
   ;; -----------------------------------------------------------------
   (define-method _exchange (examine-offered-asset)
     (assert (eq? exchange-state 'offered) "no asset offered")
     (send offered-authoritative-asset 'serialize-for-sending))

   ;; -----------------------------------------------------------------
   ;; NAME: examine-requested-asset
   ;;
   ;; DESCRIPTION:
   ;; Contract method to retrieve the requested asset description
   ;;
   ;; RETURNS:
   ;; The root authority identity and the serialized request
   ;; -----------------------------------------------------------------
   (define-method _exchange (examine-requested-asset)
     (assert (eq? exchange-state 'offered) "no asset offered")
     (list root-authority-key (send asset-request-object 'serialize)))

   ;; -----------------------------------------------------------------
   ;; NAME: exchange-asset
   ;;
   ;; DESCRIPTION:
   ;; Submit the authoritative asset that will be exchanged for the
   ;; offered asset. The authoritative asset must be escrowed to the
   ;; the exchange contract object and must match the asset request.
   ;;
   ;; Note that this operation is not friendly to failed exchange
   ;; requests. There is no way currently provided to cancel the
   ;; escrow of the authoritative asset.
   ;;
   ;; PARAMETERS:
   ;;
   ;; RETURNS:
   ;; -----------------------------------------------------------------
   (define-method _exchange (exchange-asset _serialized-authoritative-asset)
     (assert (eq? exchange-state 'offered) "not accepting exchanges")

     (let ((object (deserialize-authoritative-asset _serialized-authoritative-asset)))
       (assert (send object 'verify) "unable to verify exchange asset authority")
       (let* ((asset-object (send object 'get-asset))
              (asset-owner (send asset-object 'get-owner))
              (escrow-key (send asset-object 'get-escrow-key))
              (exchange-key (send contract-signing-keys 'get-public-signing-key)))
         (assert (string=? asset-owner (get ':message 'originator)) "exchange must come from asset owner")
         (assert (string=? escrow-key exchange-key) "asset was not escrowed to the exchange")
         (assert (send asset-request-object 'match asset-object) "asset does not match request")
         (assert (send object 'trusted-authority? root-authority-key) "does not match root authority"))

       (instance-set! self 'exchanged-authoritative-asset object)

       ;; make sure the escrow transaction has been committed
       (let ((dependencies (send object 'get-issuer-authority) 'get-dependencies))
         (if (pair? dependencies)
             (put ':ledger 'dependencies dependencies)))

       (instance-set! self 'exchange-state 'exchanged))

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: get-attestation
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method _exchange (claim-exchange)
     (assert (eq? exchange-state 'exchanged) "exchange is not completed")

     (let* ((exchange-asset-object (send exchanged-authoritative-asset 'get-asset))
            (old-owner-identity (send exchange-asset-object 'get-owner))
            (offered-asset-object (send offered-authoritative-asset 'get-asset))
            (new-owner-identity (send offered-asset-object 'get-owner)))
       (assert (equal? new-owner-identity (get ':message 'originator)) "not authorized for exchange")
       (create-claim exchange-asset-object old-owner-identity new-owner-identity contract-signing-keys)))

   ;; -----------------------------------------------------------------
   ;; NAME: claim-offer
   ;;
   ;; DESCRIPTION: Claim ownership of the offered asset. Only the identity
   ;; that provided the exchanged asset may claim the offered asset.
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method _exchange (claim-offer)
     (assert (eq? exchange-state 'exchanged) "exchange is not completed")

     (let* ((offered-asset-object (send offered-authoritative-asset 'get-asset))
            (old-owner-identity (send offered-asset-object 'get-owner))
            (exchange-asset-object (send exchanged-authoritative-asset 'get-asset))
            (new-owner-identity (send exchange-asset-object 'get-owner)))
       (assert (equal? new-owner-identity (get ':message 'originator)) "not authorized for exchange")
       (create-claim offered-asset-object old-owner-identity new-owner-identity contract-signing-keys)))

   ;; =================================================================
   ;; CLASS: exchange
   ;;
   ;; final exchange contract class definition hides all definitions in
   ;; the _exchange contract class to ensure that no leakage of methods
   ;; occurs
   ;; =================================================================
   (define-class exchange-contract
     (instance-vars (contract #f)))

   (define-method exchange-contract (initialize-instance . args)
     (if (not contract)
         (instance-set! self 'contract (make-instance exchange-package::_exchange))))

   (define-method exchange-contract (initialize _serialized-asset-request _root-authority-key)
     (send contract 'initialize _serialized-asset-request _root-authority-key))

   (define-method exchange-contract (offer-asset _serialized-authoritative-asset)
     (send contract 'offer-asset _serialized-authoritative-asset))

   (define-method exchange-contract (cancel-offer)
     (send contract 'cancel-offer))

   (define-const-method exchange-contract (examine-offered-asset)
     (send contract 'examine-offered-asset))

   (define-const-method exchange-contract (examine-requested-asset)
     (send contract 'examine-requested-asset))

   (define-method exchange-contract (exchange-asset _serialized-authoritative-asset)
     (send contract 'exchange-asset _serialized-authoritative-asset))

   (define-const-method exchange-contract (claim-exchange)
     (send contract 'claim-exchange))

   (define-const-method exchange-contract (claim-offer)
     (send contract 'claim-offer))

   (define-const-method exchange-contract (get-verifying-key)
     (send contract 'get-public-signing-key))
   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define exchange-contract exchange-package::exchange-contract)
