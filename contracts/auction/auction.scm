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

;; auction.scm
;;
;; Define the contract class for an auction. The auction contract provides an
;; example of a contract that can be used to exchange value in an asset ledger
;; or, in this case, the integer key contract
;;

(require-when (member "debug" *args*) "debug.scm")
(require "contract-base.scm")
(require "escrow-counter.scm")
(require "key-store.scm")

;; ================================================================================
;; CLASS: bid-store
;; ================================================================================
(define-class bid-store
  (super-class key-store)
  (instance-vars
   (minimum-bid 0)))

(define-method bid-store (set-bid identity new-bid)
  (assert (instance? new-bid) "bid must be an instance of bid class" new-bid)
  (if (send self 'exists? identity)
      (let ((current-bid (send self 'get identity)))
        (assert (not (send current-bid 'is-active?)) "old bid must be cancelled before a new one is submitted" identity)
        (send self 'set identity new-bid))
      (send self 'create identity new-bid)))

(define-method bid-store (del-bid identity)
  (let ((current-bid (send self 'get identity)))
    (assert (instance? current-bid) "unknown identity" identity)
    (send current-bid 'deactivate)))

(define-method bid-store (get-active-bid identity . flags)
  (let ((current-bid (send self 'get identity)))
    (assert (instance? current-bid) "unknown identity" identity)
    (assert (send current-bid 'is-active?) "bid is not active" identity)
    (if (member 'externalize flags)
        (send current-bid 'externalize)
        current-bid)))

(define-method bid-store (get-cancelled-bid identity . flags)
  (let ((current-bid (send self 'get identity)))
    (assert (instance? current-bid) "unknown identity" identity)
    (assert (not (send current-bid 'is-active?)) "bid is not active" identity)
    (if (member 'externalize flags)
        (send current-bid 'externalize)
        current-bid)))

(define-method bid-store (max-bid . flags)
  (let ((high-bid ()))
    (hashtab-package::hash-for-each
     (lambda (k b)
       (if (send b 'is-active?)
           (if (or (null? high-bid) (send b 'is-greater-than? high-bid))
               (set! high-bid b))))
     store)
    (if (member 'externalize flags)
        (send high-bid 'externalize)
        high-bid)))

;; =================================================================
;; CLASS: auction
;; =================================================================
(define-class auction
  (super-class base-contract)
  (class-vars
   (_bid-type_	escrow-counter))
  (instance-vars
   (auction-inited	#f)             ; flag to indicate that the asset hosting key is present
   (auction-primed	#f)             ; flag to indicate that the auction is primed with the offered asset
   (auction-closed	#f)             ; flag to indicate that no additional bids will be accepted
   (offered-asset	#f)             ; this should really be oops-util::void, serialization issues
   (maximum-bid         #f)
   (asset-contract-public-key "")
   (state #f)))

(define-method auction (initialize-instance . args)
  (if (not state)
      (instance-set! self 'state (make-instance bid-store))))

;; -----------------------------------------------------------------
;; NAME: initialize
;;
;; DESCRIPTION: initialize the auction with the public key of the
;; asset hosting contract.
;;
;; PARAMETERS:
;;   asset-key -- the public key of the asset hosting contract
;; -----------------------------------------------------------------
(define-method auction (initialize asset-key)
  (assert (not auction-inited) "can set the asset key only one time")
  (instance-set! self 'asset-contract-public-key asset-key)
  (instance-set! self 'auction-inited #t)
  #t)

;; -----------------------------------------------------------------
;; NAME: prime-auction, prime-auction*
;;
;; DESCRIPTION: prime the auction with the offered asset. The offered
;; asset also serves as the minimum bid. Note that the offered asset
;; must be escrowed. The transaction to record successfully priming the
;; auction must follow the transaction to record the escrow of the
;; offered asset.
;;
;; PARAMETERS:
;;   bidinfo -- list of parameters used to initialize an escrow-counter
;;   initial-bid -- an escrow-counter object
;;   dependencies -- association list mapping contract ids to corresponding state hash
;;   signature -- base64 encoded signature from the asset contract
;; -----------------------------------------------------------------
(define-method auction (prime-auction* bidinfo dependencies signature)
  (let ((initial-bid (make-instance* escrow-counter bidinfo)))
    (send self 'prime-auction initial-bid dependencies signature)))

(define-method auction (prime-auction initial-bid dependencies signature)
  "Prime the auction with the initial counter"
  (assert auction-inited "must initialize the auction before priming")
  (assert (not auction-primed) "cannot prime an auction that is already active")
  (assert (instance? initial-bid) "not an instance" initial-bid)
  (let ((bidclass (oops::class-name initial-bid)))
    (assert (eqv? bidclass (oops::class-name _bid-type_)) "wrong bid type" bidclass))

  (let ((requestor (get ':message 'originator)))
    (assert (string=? creator requestor) "only the creator of the auction may prime it" requestor)
    (assert (send initial-bid 'is-owner? requestor) "initial asset must be owned by the creator" requestor))

  (let* ((externalized (send initial-bid 'externalize))
         (expression (list externalized dependencies))
         (agent-keys (make-instance signing-keys (public-key asset-contract-public-key) (private-key ""))))
    (assert (send agent-keys 'verify-expression expression signature)
            "Bid must be signed by the asset contract" expression))

  (instance-set! self 'offered-asset initial-bid)
  (send state 'create creator initial-bid)
  (instance-set! self 'auction-primed #t)

  ;; this update cannot be committed unless the dependencies are committed
  (if (pair? dependencies) (put ':ledger 'dependencies dependencies))
  #t)

;; -----------------------------------------------------------------
;; NAME: get-offered-asset
;; -----------------------------------------------------------------
(define-const-method auction (get-offered-asset)
  (assert auction-primed "bidding is not active")
  (assert (not auction-closed) "the auction has completed")
  (list (send offered-asset 'get-key) (send offered-asset 'get-value)))

;; -----------------------------------------------------------------
;; NAME: submit-bid, submit-bid*
;;
;; DESCRIPTION: Submit a bid to the auction, the auction must be active
;; and the bid must be higher than the previous bid from this
;; participant
;;
;; PARAMETERS:
;;   bidinfo -- list of parameters used to initialize an escrow-counter
;;   bid -- an escrow-counter object
;;   dependencies -- association list mapping contract ids to corresponding state hash
;;   signature -- base64 encoded signature from the asset contract
;; -----------------------------------------------------------------
(define-method auction (submit-bid* bidinfo dependencies signature)
  (let ((initial-bid (make-instance* escrow-counter bidinfo)))
    (send self 'submit-bid initial-bid dependencies signature)))

(define-method auction (submit-bid bid dependencies signature)
  (assert auction-primed "bidding is not active")
  (assert (not auction-closed) "the auction has completed")
  (assert (instance? bid) "not an instance" bid)
  (let ((bidclass (oops::class-name bid)))
    (assert (eqv? bidclass (oops::class-name _bid-type_)) "wrong bid type" bidclass))

  (let* ((externalized (send bid 'externalize))
         (expression (list externalized dependencies))
         (agent-keys (make-instance signing-keys (public-key asset-contract-public-key) (private-key ""))))
    (assert (send agent-keys 'verify-expression expression signature)
            "Bid must be signed by the asset contract" expression))

  (let ((requestor (get ':message 'originator)))
    (assert (send bid 'is-owner? requestor) "only the owner of a bid may submit the bid" requestor)
    (send state 'set-bid requestor bid))

  ;; this update cannot be committed unless the dependencies are committed
  (if (pair? dependencies) (put ':ledger 'dependencies dependencies))

  #t)

;; -----------------------------------------------------------------
;; NAME: cancel-bid
;;
;; DESCRIPTION:
;; when a bid is cancelled we should return enough to cancel the
;; escrow in the integer-key contract, we have to return cancelled
;; bids even when the auction is closed
;; -----------------------------------------------------------------
(define-method auction (cancel-bid)
  (assert auction-primed "bidding is not active")
  (let* ((requestor (get ':message 'originator))
         (bid (send state 'get-active-bid requestor)))
    (send bid 'deactivate))
  #t)

;; ----------------------------------------------------------------
;; NAME: cancelled-bid-attestation
;;
;; DESCRIPTION: generate an attestation that a bid has been cancelled;
;; this is distinct from the actual cancellation of the bid because we
;; need to record the state change first.
;; -----------------------------------------------------------------
(define-const-method auction (cancel-attestation)
  (assert auction-primed "bidding is not active")
  (let* ((requestor (get ':message 'originator))
         (externalized (send state 'get-cancelled-bid requestor 'externalize))
         (dependencies (list (list (get ':contract 'id) (get ':contract 'state))))
         (expression (list externalized dependencies))
         (signature (send contract-signing-keys 'sign-expression expression)))
    (list externalized dependencies signature)))

;; ----------------------------------------------------------------
;; NAME: check-bid
;; ----------------------------------------------------------------
(define-const-method auction (check-bid)
  (assert auction-primed "bidding is not active")
  (assert (not auction-closed) "the auction has completed")
  (let* ((requestor (get ':message 'originator)))
    (send state 'get-active-bid requestor 'externalize)))

;; ----------------------------------------------------------------
;; NAME: max-bid
;; ----------------------------------------------------------------
(define-const-method auction (max-bid)
  (assert auction-primed "bidding is not active")
  (assert (not auction-closed) "the auction has completed")
  (let ((maxbid (send state 'max-bid)))
    (send maxbid 'get-value)))

;; -----------------------------------------------------------------
;; NAME: close-bidding
;;
;; DESCRIPTION: close the auction for bidding, note that the actual
;; exchange attestation must be generated separately to ensure that the
;; closed state is committed to the ledger.
;; -----------------------------------------------------------------
(define-method auction (close-bidding)
  (assert auction-primed "cannot close auction that has not started")
  (assert (not auction-closed) "the auction has already completed")
  (let ((requestor (get ':message 'originator)))
    (assert (string=? requestor creator) "only the auction creator may close bidding"))

  (instance-set! self 'auction-closed #t)
  (instance-set! self 'maximum-bid (send state 'max-bid))

  ;; should the max bid be cancelled? there is a bit of a problem in
  ;; that the auction creator could never submit the exchange to the
  ;; asset contract which would prevent the high bidder from disbursing
  ;; their asset; although a cancel-attestation could be generated.
  (send maximum-bid 'deactivate)

  #t)

;; -----------------------------------------------------------------
;; NAME: exchange-attestation
;;
;; DESCRIPTION: generate the attestation that handles the actual
;; exchange of asset ownership in the asset contract
;; -----------------------------------------------------------------
(define-const-method auction (exchange-attestation)
  (let ((requestor (get ':message 'originator)))
    (assert (string=? requestor creator) "only the auction creator may generate the exchange attestation" requestor))

  (assert auction-closed "cannot generate exchange attestation until the auction is closed")

  (let* ((offered (send offered-asset 'externalize))
         (maxbid (send maximum-bid 'externalize))
         (dependencies (list (list (get ':contract 'id) (get ':contract 'state))))
         (expression (list offered maxbid dependencies))
         (signature (send contract-signing-keys 'sign-expression expression)))
    (list offered maxbid dependencies signature)))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(require-when (member "test-auction" *args*) "auction-test.scm")
