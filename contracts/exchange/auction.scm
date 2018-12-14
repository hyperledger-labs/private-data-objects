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

(require "asset_request_class.scm")       ; needed for deserialize
(require "authoritative_asset_class.scm") ; needed for deserialize
(require "bid_store_package.scm")

(define auction-package
  (package

   ;; =================================================================
   ;; CLASS: _auction
   ;; =================================================================
   (define-class _auction
     (super-class base-contract)
     (instance-vars
      (auction-state 'created)         ; created, initialized, offered, closed, confirmed, canceled
      (asset-request-object #f)
      (root-authority-key "")
      (offered-authoritative-asset #f)
      (auction-winner-key "")
      (bids #f)))

   ;; -----------------------------------------------------------------
   ;; NAME: initialize-instance
   ;;
   ;; DESCRIPTION:
   ;; Function called when an _auction object is created.
   ;;
   ;; PARAMETERS:
   ;; args -- key/value parameters for the contructor that do not explicitly
   ;; set the value of instance variables
   ;; -----------------------------------------------------------------
   (define-method _auction (initialize-instance . args)
     (if (not bids)
         (instance-set! self 'bids (make-instance bid-store-class))))

   ;; -----------------------------------------------------------------
   ;; NAME: initialize
   ;;
   ;; DESCRIPTION:
   ;; Contract method called to initialize the auction with the requested
   ;; asset description and root authority
   ;;
   ;; PARAMETERS:
   ;;    _serialized-asset-request -- serialized object of type asset-request-class
   ;;    _root-authority-key -- public key for the requested root of trust
   ;; -----------------------------------------------------------------
   (define-method _auction (initialize _serialized-asset-request _root-authority-key)
     (assert (equal? creator (get ':message 'originator)) "only creator may initialize the auction")
     (assert (eq? auction-state 'created) "auction has already been initialized")

     (instance-set! self 'asset-request-object (deserialize-asset-request _serialized-asset-request))
     (instance-set! self 'root-authority-key _root-authority-key)
     (instance-set! self 'auction-state 'initialized)

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
   (define-method _auction (offer-asset _serialized-authoritative-asset)
     (assert (equal? creator (get ':message 'originator)) "only creator may offer an asset")
     (assert (eq? auction-state 'initialized) "offered asset has already been recorded")

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

       (instance-set! self 'auction-state 'offered))

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: cancel-auction
   ;;
   ;; DESCRIPTION:
   ;; Contract method called to change the state of the auction to canceled.
   ;; The change allows for the offered asset to be disbursed.
   ;;
   ;; Note that because the current implementation does not handle failed
   ;; bids (see notes for submit-bid) so allowing the auction to
   ;; be canceled makes it possible to prevent a bid asset from being
   ;; disbursed.
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method _auction (cancel-auction)
     (assert (equal? creator (get ':message 'originator)) "only creator may cancel exchange")
     (assert (eq? auction-state 'offered) "no assets offered")

     (instance-set! self 'auction-state 'canceled))

   ;; -----------------------------------------------------------------
   ;; NAME: cancel-auction-attestation
   ;;
   ;; DESCRIPTION:
   ;; Contract method to create an attestation that can be used to claim
   ;; the offered asset from escrow; only valid if the auction is
   ;; actually canceled
   ;;
   ;; PARAMETERS:
   ;;
   ;; RETURNS:
   ;; List of dependencies and a signature over the disburse attestation
   ;; -----------------------------------------------------------------
   (define-method _auction (cancel-auction-attestation)
     (assert (equal? creator (get ':message 'originator)) "only creator may cancel exchange")
     (assert (eq? auction-state 'canceled) "exchange is not canceled")
     (create-cancellation creator contract-signing-keys))

   ;; -----------------------------------------------------------------
   ;; NAME: examine-offered-asset
   ;;
   ;; DESCRIPTION:
   ;; Contract method to retrieve the offered asset.
   ;;
   ;; RETURNS:
   ;; Serialized authoritative asset
   ;; -----------------------------------------------------------------
   (define-method _auction (examine-offered-asset)
     (assert (eq? auction-state 'offered) "no asset offered")
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
   (define-method _auction (examine-requested-asset)
     (assert (eq? auction-state 'offered) "no asset offered")
     (list root-authority-key (send asset-request-object 'serialize)))

   ;; -----------------------------------------------------------------
   ;; NAME: submit-bid
   ;;
   ;; DESCRIPTION:
   ;; Contract method to submit an authoritative asset as a bid
   ;;
   ;; PARAMETERS:
   ;; _serialized-authoritative-asset -- serialized object of type authoriative-asset-class
   ;; -----------------------------------------------------------------
   (define-method _auction (submit-bid _serialized-authoritative-asset)
     ;; we need accept bids after the auction is closed or canceled because
     ;; we need to provide an opportunity for the asset to be cleared of
     ;; escrow, so submitting a bid to a canceled or closed auction will allow
     ;; the bid to be later canceled
     (assert (member auction-state '(offered closed confirmed canceled)) "not accepting bids")

     ;; these checks verify that the bid is correct and matches all of the
     ;; associated criteria; if it fails to meet the criteria, should we generate
     ;; an attestation that allows the asset to be disbursed?
     (let ((object (deserialize-authoritative-asset _serialized-authoritative-asset)))
       (assert (send object 'verify) "unable to verify offered asset authority")
       (assert (send object 'trusted-authority? root-authority-key) "asset does not match root authority")
       (let* ((asset-object (send object 'get-asset))
              (asset-owner (send asset-object 'get-owner))
              (escrow-key (send asset-object 'get-escrow-key))
              (exchange-key (send contract-signing-keys 'get-public-signing-key)))
         (assert (string=? asset-owner (get ':message 'originator)) "exchange must come from asset owner")
         (assert (string=? escrow-key exchange-key) "asset was not escrowed to the exchange")
         (assert (send asset-request-object 'match asset-object) "asset does not match request")

         ;; save the bid in the bid store, note that this will fail if there is already
         ;; an active bid. once again this raises the question of whether we should create
         ;; an attestation. in this case, the owner of the bid could have checked to see
         ;; if they had already bid so we'll just chalk this up to operator error
         (send bids 'submit-bid asset-owner object)))
     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: cancel-bid
   ;;
   ;; DESCRIPTION:
   ;; Contract method to cancel a bid. Note that this modifies the state
   ;; of the bid but does not generate the attestation to release the
   ;; escrow.
   ;; -----------------------------------------------------------------
   (define-method _auction (cancel-bid)
     (let* ((identity (get ':message 'originator)))

       ;; just have to make sure that the auction winner is not backing out of
       ;; the commitment of resources
       (assert (not (and (member auction-state '(closed confirmed))
                         (string=? identity auction-winner-key)))
               "auction winner may not cancel their bid")

       (send bids 'cancel-bid identity))

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: cancel-bid-attestation
   ;;
   ;; DESCRIPTION:
   ;; Contract method to generate an attestation that a bid has been canceled
   ;; so that escrow can be released.
   ;;
   ;; RETURNS:
   ;; List of dependencies and a signature over the disburse attestation
   ;; -----------------------------------------------------------------
   (define-method _auction (cancel-bid-attestation)
     (let* ((identity (get ':message 'originator)))
       (protect
        (let* ((canceled-bid (send bids 'get-canceled-bid identity))
               (canceled-asset (send canceled-bid 'get-asset)))
          (create-cancellation canceled-asset identity contract-signing-keys))
        "no canceled bid")))

   ;; ----------------------------------------------------------------
   ;; NAME: check-bid
   ;;
   ;; DESCRIPTION:
   ;; Contract method to examine the originators current bid
   ;;
   ;; RETURNS:
   ;; Serialized bid
   ;; ----------------------------------------------------------------
   (define-method _auction (check-bid)
     (let ((identity (get ':message 'originator)))
       (protect
        (send bids 'get-active-bid identity 'externalize)
        "no bid")))

   ;; ----------------------------------------------------------------
   ;; NAME: max-bid
   ;;
   ;; DESCRIPTION:
   ;; Contract method to examine maximum bid
   ;;
   ;; RETURNS:
   ;; The pair of bid asset type and bid amount for the maximum bid
   ;; ----------------------------------------------------------------
   (define-method _auction (max-bid)
     (send bids 'max-bid-information))

   ;; -----------------------------------------------------------------
   ;; NAME: close-auction
   ;;
   ;; DESCRIPTION:
   ;; Contract method to close bidding on the auction. Must be executed
   ;; by the creator of the auction contract object.
   ;;
   ;; Note that the auction creator can determine the amount of a winning
   ;; bid by repeatedly submitting a bid with a separate identity, calling
   ;; close-auction and confirm-close. The only way to prevent exposure
   ;; of the maximum bid amount is to require a proof of commitment of the
   ;; close state prior to any claims. This will be addressed in the future.
   ;; -----------------------------------------------------------------
   (define-method _auction (close-auction)
     (assert (eq? auction-state 'offered) "no asset offered")
     (assert (equal? creator (get ':message 'originator)) "only creator may close bidding")

     (instance-set! self 'auction-winner-key (send bids 'max-bidder))
     (instance-set! self 'auction-state 'closed)

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: confirm-close
   ;;
   ;; DESCRIPTION:
   ;; Contract method to confirm that the auction has been closed. Must
   ;; be executed by the winning bidder.
   ;; -----------------------------------------------------------------
   (define-method _auction (confirm-close)
     (assert (eq? auction-state 'closed) "auction is not closed")
     (assert (equal? auction-winner-key (get ':message 'originator)) "only auction winner may confirm close")

     (instance-set! self 'auction-state 'confirmed)

     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: claim-bid
   ;;
   ;; DESCRIPTION:
   ;; Contract method to generate the attestation that allows the auction
   ;; creator to claim the winning bid
   ;; -----------------------------------------------------------------
   (define-method _auction (claim-bid)
     (assert (eq? auction-state 'confirmed) "auction is not completed")
     (assert (equal? creator (get ':message 'originator)) "only creator may claim bids")
     (let* ((winning-bid (send bids 'get-active-bid auction-winner-key))
            (winning-asset (send winning-bid 'get-asset)))
       (create-claim winning-asset auction-winner-key creator contract-signing-keys)))

   ;; -----------------------------------------------------------------
   ;; NAME: claim-offer
   ;;
   ;; DESCRIPTION:
   ;; Contract method that allows the auction winner to claim ownership
   ;; of the offered asset.
   ;; -----------------------------------------------------------------
   (define-method _auction (claim-offer)
     (assert (eq? auction-state 'confirmed) "auction is not completed")
     (let ((identity (get ':message 'originator)))
       (assert (equal? auction-winner-key identity) "only auction winner may claim offered asset"))

     (let ((offered-asset (send offered-authoritative-asset 'get-asset)))
       (create-claim offered-asset creator auction-winner-key contract-signing-keys)))

   ;; =================================================================
   ;; CLASS: exchange
   ;;
   ;; final exchange contract class definition hides all definitions in
   ;; the _auction contract class to ensure that no leakage of methods
   ;; occurs
   ;; =================================================================
   (define-class auction-contract
     (instance-vars (contract #f)))

   (define-method auction-contract (initialize-instance . args)
     (if (not contract)
         (instance-set! self 'contract (make-instance auction-package::_auction))))

   (define-method auction-contract (initialize _serialized-asset-request _root-authority-key)
     (send contract 'initialize _serialized-asset-request _root-authority-key))

   (define-method auction-contract (offer-asset _serialized-authoritative-asset)
     (send contract 'offer-asset _serialized-authoritative-asset))

   (define-method auction-contract (cancel-auction)
     (send contract 'cancel-auction))

   (define-const-method auction-contract (cancel-auction-attestation)
     (send contract 'cancel-auction-attestation))

   (define-const-method auction-contract (examine-offered-asset)
     (send contract 'examine-offered-asset))

   (define-const-method auction-contract (examine-requested-asset)
     (send contract 'examine-requested-asset))

   (define-method auction-contract (submit-bid _serialized-authoritative-asset)
     (send contract 'submit-bid _serialized-authoritative-asset))

   (define-method auction-contract (cancel-bid)
     (send contract 'cancel-bid))

   (define-const-method auction-contract (cancel-bid-attestation)
     (send contract 'cancel-bid-attestation))

   (define-const-method auction-contract (check-bid)
     (send contract 'check-bid))

   ;; once we get the contract commit issue addressed, remove this
   ;; method to keep the auction completely blinded
   (define-const-method auction-contract (max-bid)
     (send contract 'max-bid))

   (define-method auction-contract (close-auction)
     (send contract 'close-auction))

   (define-method auction-contract (confirm-close)
     (send contract 'confirm-close))

   (define-const-method auction-contract (claim-bid)
     (send contract 'claim-bid))

   (define-const-method auction-contract (claim-offer)
     (send contract 'claim-offer))

   (define-const-method auction-contract (get-verifying-key)
     (send contract 'get-public-signing-key))
   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define auction-contract auction-package::auction-contract)
