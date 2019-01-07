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

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(require "debug.scm")
(require "contract-base.scm")

(require "asset_type.scm")
(require "issuer.scm")
(require "vetting_organization.scm")
(require "auction.scm")

(require "test_common.scm")

;; -----------------------------------------------------------------
;; indexes for some keys
(define blue-vetting 0)
(define blue-issuer  1)
(define red-vetting  2)
(define red-issuer   3)

(define alice  11)

(define bob    21)
(define carl   22)
(define debra  23)
(define erin   24)

;; -----------------------------------------------------------------
;; set up the blue marble issuer
;; -----------------------------------------------------------------
(define blue-asset-type-pdo)
(define blue-type-identifier)
(define blue-vetting-pdo)
(define blue-issuer-pdo)

(use-person blue-vetting)
(catch-failed-test
 (set! blue-asset-type-pdo (make-instance asset-type-contract))
 (send blue-asset-type-pdo 'initialize "blue marbles" "asset type for representing blue marbles" "")
 (set! blue-type-identifier (send blue-asset-type-pdo 'get-identifier))
 (test-logger::logger-info "Blue Type ID: " blue-type-identifier)

 (set! blue-vetting-pdo (make-instance vetting-organization-contract))
 (send blue-vetting-pdo 'initialize blue-type-identifier))

(use-person blue-issuer)
(catch-failed-test
 (set! blue-issuer-pdo (make-instance issuer-contract))
 (let ((blue-issuer-verifying-key (send blue-issuer-pdo 'get-verifying-key (use-person* blue-issuer))))
   (send blue-vetting-pdo 'add-approved-key blue-issuer-verifying-key (use-person* blue-vetting))
   (let ((blue-authority (send blue-vetting-pdo 'get-authority blue-issuer-verifying-key (use-person* blue-issuer))))
     (assert (send blue-issuer-pdo 'initialize blue-type-identifier blue-authority (use-person* blue-issuer)) "initialize failed")

     (test-logger::logger-info "---------- issue blue marble assets ----------")
     (do ((pnumber person-first (+ pnumber 1)))
         ((>= pnumber person-count))
       (assert (send blue-issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* blue-issuer)) "issue failed")
       (assert (= (send blue-issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance")))))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

;; -----------------------------------------------------------------
;; set up the red marble issuer
;; -----------------------------------------------------------------
(define red-asset-type-pdo)
(define red-type-identifier)
(define red-vetting-pdo)
(define red-issuer-pdo)

(use-person red-vetting)
(catch-failed-test
 (set! red-asset-type-pdo (make-instance asset-type-contract))
 (send red-asset-type-pdo 'initialize "red marbles" "asset type for representing red marbles" "")

 (set! red-type-identifier (send red-asset-type-pdo 'get-identifier))
 (test-logger::logger-info "Red Type ID: " red-type-identifier)

 (set! red-vetting-pdo (make-instance vetting-organization-contract))
 (send red-vetting-pdo 'initialize red-type-identifier))

(use-person red-issuer)
(catch-failed-test
 (set! red-issuer-pdo (make-instance issuer-contract))
 (let ((red-issuer-verifying-key (send red-issuer-pdo 'get-verifying-key (use-person* red-issuer))))
   (send red-vetting-pdo 'add-approved-key red-issuer-verifying-key (use-person* red-vetting))
   (let ((red-authority (send red-vetting-pdo 'get-authority red-issuer-verifying-key (use-person* red-issuer))))
     (assert (send red-issuer-pdo 'initialize red-type-identifier red-authority (use-person* red-issuer)) "initialize failed")

     (test-logger::logger-info "---------- issue red marble assets ----------")
     (do ((pnumber person-first (+ pnumber 1)))
         ((>= pnumber person-count))
       (assert (send red-issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* red-issuer)) "issue failed")
       (assert (= (send red-issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance")))))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as alice
;;
;; alice owns blue marbles and wants to offer them for red marbles
;; -----------------------------------------------------------------
(define auction-pdo)

(use-person alice)
(catch-failed-test
 ;; create the exchange contract
 (set!  auction-pdo (make-instance auction-contract))

 (test-logger::logger-info "---------- prime exchange and offer asset ----------")

 ;; create an asset request for 21 red marbles with red-vetting-pdo as the root of trust
 (let ((asset-request (make-instance asset-request-class (asset-type-id red-type-identifier) (count 21))))
   (let ((serialized-request (send asset-request 'serialize))
         (red-vetting-key (send red-vetting-pdo 'get-verifying-key)))
     (send auction-pdo 'initialize serialized-request red-vetting-key)))

 ;; escrow the blue marbles that will be offered for exchange
 (assert (send blue-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow blue marbles")
 (let ((serialized-attestation (send blue-issuer-pdo 'escrow-attestation)))
   (assert (send auction-pdo 'offer-asset serialized-attestation) "failed to offer asset")))

(test-logger::logger-info "OFFERED ASSET: " (send auction-pdo 'examine-offered-asset))
(test-logger::logger-info "REQUESTED ASSET: " (send auction-pdo 'examine-requested-asset))
(dump-ledger blue-issuer-pdo "BLUE LEDGER")

;; -----------------------------------------------------------------
;; work as bob
;;
;; bob owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------
(use-person bob)
(catch-failed-test
 (test-logger::logger-info "---------- bob bid ----------")

 (assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
 (let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
   (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset")))

(dump-authoritative-asset (send auction-pdo 'check-bid))

;; -----------------------------------------------------------------
;; work as carl
;;
;; carl owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------
(use-person carl)
(catch-failed-test
 (test-logger::logger-info "---------- carl bid ----------")
 (assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
 (let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
   (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset")))

(dump-authoritative-asset (send auction-pdo 'check-bid))

;; -----------------------------------------------------------------
;; work as debra
;;
;; debra owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------
(use-person debra)
(catch-failed-test
 (test-logger::logger-info "---------- debra bid ----------")
 (assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
 (let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
   (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset")))

(dump-authoritative-asset (send auction-pdo 'check-bid))

;; -----------------------------------------------------------------
;; work as erin
;;
;; erin owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------
(use-person erin)
(catch-failed-test
 (test-logger::logger-info "---------- erin bid ----------")
 (assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
 (let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
   (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset"))

 (dump-authoritative-asset (send auction-pdo 'check-bid)))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as bob
;;
;; cancel the bid
;; -----------------------------------------------------------------
(use-person bob)
(catch-failed-test
 (test-logger::logger-info "---------- cancel bob's bid ----------")

 (assert (send auction-pdo 'cancel-bid) "failed to cancel bob bid")
 (let* ((serialized-attestation (send auction-pdo 'cancel-bid-attestation))
        (dependencies (nth serialized-attestation 0))
        (signature (nth serialized-attestation 1)))
   (assert (send red-issuer-pdo 'disburse dependencies signature) "disburse failed"))

 (catch-success
  (dump-authoritative-asset (send auction-pdo 'check-bid)) "bid was not cancelled"))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as alice
;;
;; show maximum bid
;; -----------------------------------------------------------------
(use-person alice)
(catch-failed-test
 (test-logger::logger-info "maximum bid " (send auction-pdo 'max-bid)))

;; -----------------------------------------------------------------
;; work as alice and erin
;;
;; close the auction
;; -----------------------------------------------------------------
(test-logger::logger-info "---------- close the auction ----------")

(use-person alice)
(catch-failed-test
 (assert (send auction-pdo 'close-auction) "failed to close the auction"))

(use-person erin)
(catch-failed-test
 (assert (send auction-pdo 'confirm-close) "failed to confirm the close"))

;; -----------------------------------------------------------------
;; work as alice
;;
;; claim the highest bid
;; -----------------------------------------------------------------
(test-logger::logger-info "---------- claim the winning bid ----------")
(dump-ledger red-issuer-pdo "RED LEDGER")

(use-person alice)
(catch-failed-test
 (let* ((serialized-claim (send auction-pdo 'claim-bid))
        (old-owner (nth serialized-claim 0))
        (dependencies (nth serialized-claim 1))
        (signature (nth serialized-claim 2)))
   (assert (send red-issuer-pdo 'claim old-owner dependencies signature) "failed to claim the bid asset")))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as erin
;;
;; claim the offered asset
;; -----------------------------------------------------------------
(test-logger::logger-info "---------- claim the offered asset ----------")
(dump-ledger blue-issuer-pdo "BLUE LEDGER")

(use-person erin)
(catch-failed-test
 (let* ((serialized-claim (send auction-pdo 'claim-offer))
        (old-owner (nth serialized-claim 0))
        (dependencies (nth serialized-claim 1))
        (signature (nth serialized-claim 2)))
   (assert (send blue-issuer-pdo 'claim old-owner dependencies signature) "failed to claim the bid asset")))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

(test-logger::highlight "AUCTION TEST COMPLETED SUCCESSFULLY")
(quit 0)
