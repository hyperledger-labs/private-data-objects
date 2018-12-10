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

(require "indexed-key-store.scm")

(define bid-store-package
  (package

   (define authoritative-asset-class-name 'authoritative-asset-class)

   ;; ================================================================================
   ;; CLASS: bid-class
   ;;
   ;; The bid-class wraps an authorized asset with a flag to mark it as active
   ;; or inactive.
   ;; ================================================================================
   (define-class bid-class
     (instance-vars
      (authoritative-asset #f)                           ; and authoritative-asset-class object
      (active #t)))

   (define-method bid-class (initialize-instance . args)
     (assert authoritative-asset "asset must be defined during bid initialization")
     (assert (instance? authoritative-asset) "bid must be an asset object")
     (assert (eq? (oops::class-name authoritative-asset) bid-store-package::authoritative-asset-class-name)
             "bid must be an authoritative asset"))

   (define-method bid-class (is-active?) active)
   (define-method bid-class (is-inactive?) (not active))
   (define-method bid-class (deactivate) (instance-set! self 'active #f))
   (define-method bid-class (externalize) (send authoritative-asset 'serialize-for-sending))
   (define-method bid-class (get-authoritative-asset) authoritative-asset)
   (define-method bid-class (get-asset) (send authoritative-asset 'get-asset))

   (define-method bid-class (get-count)
     (assert active "bid is not active")
     (send (send authoritative-asset 'get-asset) 'get-count))

   (define-method bid-class (is-greater-than? _bid)
     (let ((count1 (send self 'get-count))
           (count2 (send _bid 'get-count)))
       (> count1 count2)))

   ;; ================================================================================
   ;; CLASS: bid-store-class
   ;;
   ;; The bid-store is an object class for storing bids for an auction. The basic
   ;; data structure is a key/value store that maps an identity to a bid. At most
   ;; one bid is accepted for each identity. A bid is an object that supports at a
   ;; minimum deactivate, is-active?, externalize, is-greater-than?.
   ;; ================================================================================
   (define-class bid-store-class
     (super-class indexed-key-store)
     (instance-vars))

   ;; -----------------------------------------------------------------
   ;; NAME: set-bid
   ;;
   ;; DESCRIPTION: Assign a bid to an identity. There must not be another
   ;; active bid from the identity.
   ;;
   ;; PARAMETERS:
   ;; identity -- string, identity of the bidder
   ;; new-bid -- authoritative-asset that will be used for the bid
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (submit-bid identity new-bid-asset)
     (assert (let ((current-bid (send self 'exists? identity)))
               (or (not current-bid) (send current-bid 'is-inactive?)))
             "old bid must be canceled before a new one is submitted" identity)
     (assert (instance? new-bid-asset) "bid must be an asset object")
     (assert (eq? (oops::class-name new-bid-asset) 'authoritative-asset-class) "bid must be an authoritative asset")

     (let ((new-bid (make-instance bid-store-package::bid-class (authoritative-asset new-bid-asset))))
       (send self 'set identity new-bid)))

   ;; -----------------------------------------------------------------
   ;; NAME: initialize
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; identity -- string, identity of the bidder
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (cancel-bid identity)
     (let ((current-bid (send self 'get-active-bid identity)))
       (send current-bid 'deactivate)
       (send self 'set identity current-bid)))

   ;; -----------------------------------------------------------------
   ;; NAME: get-active-bid
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; identity -- string, identity of the bidder
   ;; flags --
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (get-active-bid identity . flags)
     (let ((current-bid (send self 'get identity)))
       (assert (send current-bid 'is-active?) "bid is not active" identity)
       (if (member 'externalize flags)
           (send current-bid 'externalize)
           current-bid)))

   ;; -----------------------------------------------------------------
   ;; NAME: get-canceled-bid
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (get-canceled-bid identity . flags)
     (let ((current-bid (send self 'get identity)))
       (assert (send current-bid 'is-inactive?) "bid is active" identity)
       (if (member 'externalize flags)
           (send current-bid 'externalize)
           current-bid)))

   ;; -----------------------------------------------------------------
   ;; NAME: max-bid
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (max-bid)
     (let ((high-bid ()))
       (hashtab-package::hash-for-each
        (lambda (k b)
          (let ((value (send self 'get k)))
            (if (send value 'is-active?)
                (if (or (null? high-bid) (send value 'is-greater-than? high-bid))
                    (set! high-bid value)))))
        store)

       high-bid))

   ;; -----------------------------------------------------------------
   ;; NAME: max-bidder
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (max-bidder)
     (send (send (send self 'max-bid) 'get-asset) 'get-owner))

   ;; -----------------------------------------------------------------
   ;; NAME: max-bid-information
   ;;
   ;; DESCRIPTION:
   ;;
   ;; PARAMETERS:
   ;; -----------------------------------------------------------------
   (define-method bid-store-class (max-bid-information)
     (let* ((bid (send self 'max-bid))
            (asset (send bid 'get-asset)))
       (list (send asset 'get-asset-type-id) (send asset 'get-count))))

   ))

(define bid-store-class bid-store-package::bid-store-class)
