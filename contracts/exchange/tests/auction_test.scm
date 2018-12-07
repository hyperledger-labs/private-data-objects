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
(define blue-vetting  20)
(define blue-issuer  21)
(define red-vetting  25)
(define red-issuer  26)

(define alice  1)

(define bob    11)
(define carl   12)
(define debra  13)
(define erin   14)

;; -----------------------------------------------------------------
;; set up the blue marble issuer
;; -----------------------------------------------------------------
(use-person blue-vetting)
(define blue-asset-type-pdo (make-instance asset-type-contract))
(send blue-asset-type-pdo 'initialize "blue marbles" "asset type for representing blue marbles" "")
(define blue-type-identifier (send blue-asset-type-pdo 'get-identifier))
(result-print "Blue Type ID: " blue-type-identifier)

(define blue-vetting-pdo (make-instance vetting-organization-contract))
(send blue-vetting-pdo 'initialize blue-type-identifier)

(use-person blue-issuer)
(define blue-issuer-pdo (make-instance issuer-contract))

(let ((blue-issuer-verifying-key (send blue-issuer-pdo 'get-verifying-key (use-person* blue-issuer))))
  (send blue-vetting-pdo 'add-approved-key blue-issuer-verifying-key (use-person* blue-vetting))
  (let ((blue-authority (send blue-vetting-pdo 'get-authority blue-issuer-verifying-key (use-person* blue-issuer))))
    (assert (send blue-issuer-pdo 'initialize blue-type-identifier blue-authority (use-person* blue-issuer)) "initialize failed")

    (result-print "---------- issue blue marble assets ----------")
    (do ((pnumber 0 (+ pnumber 1)))
        ((= pnumber 10))
      (assert (send blue-issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* blue-issuer)) "issue failed")
      (assert (= (send blue-issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance"))))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

;; -----------------------------------------------------------------
;; set up the red marble issuer
;; -----------------------------------------------------------------
(use-person red-vetting)
(define red-asset-type-pdo (make-instance asset-type-contract))
(send red-asset-type-pdo 'initialize "red marbles" "asset type for representing red marbles" "")
(define red-type-identifier (send red-asset-type-pdo 'get-identifier))
(result-print "Red Type ID: " red-type-identifier)

(define red-vetting-pdo (make-instance vetting-organization-contract))
(send red-vetting-pdo 'initialize red-type-identifier)

(use-person red-issuer)
(define red-issuer-pdo (make-instance issuer-contract))

(let ((red-issuer-verifying-key (send red-issuer-pdo 'get-verifying-key (use-person* red-issuer))))
  (send red-vetting-pdo 'add-approved-key red-issuer-verifying-key (use-person* red-vetting))
  (let ((red-authority (send red-vetting-pdo 'get-authority red-issuer-verifying-key (use-person* red-issuer))))
    (assert (send red-issuer-pdo 'initialize red-type-identifier red-authority (use-person* red-issuer)) "initialize failed")

    (result-print "---------- issue red marble assets ----------")
    (do ((pnumber 10 (+ pnumber 1)))
        ((= pnumber 20))
      (assert (send red-issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* red-issuer)) "issue failed")
      (assert (= (send red-issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance"))))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as alice
;;
;; alice owns blue marbles and wants to offer them for red marbles
;; -----------------------------------------------------------------

(use-person alice)

;; create the exchange contract
(define auction-pdo (make-instance auction-contract))

(display "---------- prime exchange and offer asset ----------\n")

;; create an asset request for 21 red marbles with red-vetting-pdo as the root of trust
(let ((asset-request (make-instance asset-request-class (asset-type-id red-type-identifier) (count 21))))
  (let ((serialized-request (send asset-request 'serialize))
        (red-vetting-key (send red-vetting-pdo 'get-verifying-key)))
    (send auction-pdo 'initialize serialized-request red-vetting-key)))

;; escrow the blue marbles that will be offered for exchange
(assert (send blue-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow blue marbles")
(let ((serialized-attestation (send blue-issuer-pdo 'escrow-attestation)))
  (assert (send auction-pdo 'offer-asset serialized-attestation) "failed to offer asset"))

(result-print "OFFERED ASSET: " (send auction-pdo 'examine-offered-asset))
(result-print "REQUESTED ASSET: " (send auction-pdo 'examine-requested-asset))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

;; -----------------------------------------------------------------
;; work as bob
;;
;; bob owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------

(use-person bob)

(display "---------- bob bid ----------\n")
(assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
(let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
  (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset"))

(display "submit completed\n")
(let ((serialized-bid (send auction-pdo 'check-bid)))
  (dump-authoritative-asset serialized-bid))

;; -----------------------------------------------------------------
;; work as carl
;;
;; carl owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------

(use-person carl)

(display "---------- carl bid ----------\n")
(assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
(let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
  (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset"))

(dump-authoritative-asset (send auction-pdo 'check-bid))

;; -----------------------------------------------------------------
;; work as debra
;;
;; debra owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------

(use-person debra)

(display "---------- debra bid ----------\n")
(assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
(let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
  (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset"))

(dump-authoritative-asset (send auction-pdo 'check-bid))

;; -----------------------------------------------------------------
;; work as erin
;;
;; erin owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------

(use-person erin)

(display "---------- erin bid ----------\n")
(assert (send red-issuer-pdo 'escrow (send auction-pdo 'get-verifying-key)) "failed to escrow red marbles")
(let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
  (assert (send auction-pdo 'submit-bid serialized-attestation) "failed to offer asset"))

(dump-authoritative-asset (send auction-pdo 'check-bid))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as bob
;;
;; cancel the bid
;; -----------------------------------------------------------------

(display "---------- cancel bob's bid ----------\n")

(use-person bob)

(assert (send auction-pdo 'cancel-bid) "failed to cancel bob bid")
(let* ((serialized-attestation (send auction-pdo 'cancel-bid-attestation))
       (dependencies (nth serialized-attestation 0))
       (signature (nth serialized-attestation 1)))
  (assert (send red-issuer-pdo 'disburse dependencies signature) "disburse failed"))

(catch-success
 (dump-authoritative-asset (send auction-pdo 'check-bid)) "bid was not cancelled")

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as alice
;;
;; show maximum bid
;; -----------------------------------------------------------------

(display "---------- show the maximum bid ----------\n")
(use-person alice)
(write (send auction-pdo 'max-bid))
(newline)

;; -----------------------------------------------------------------
;; work as alice and erin
;;
;; close the auction
;; -----------------------------------------------------------------

(display "---------- close the auction ----------\n")

(use-person alice)
(assert (send auction-pdo 'close-auction) "failed to close the auction")

(use-person erin)
(assert (send auction-pdo 'confirm-close) "failed to confirm the close")

;; -----------------------------------------------------------------
;; work as alice
;;
;; claim the highest bid
;; -----------------------------------------------------------------

(display "---------- claim the winning bid ----------\n")

(dump-ledger red-issuer-pdo "RED LEDGER")

(use-person alice)

(let* ((serialized-claim (send auction-pdo 'claim-bid))
       (old-owner (nth serialized-claim 0))
       (dependencies (nth serialized-claim 1))
       (signature (nth serialized-claim 2)))
  (assert (send red-issuer-pdo 'claim old-owner dependencies signature) "failed to claim the bid asset"))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as erin
;;
;; claim the offered asset
;; -----------------------------------------------------------------

(display "---------- claim the offered asset ----------\n")

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

(use-person erin)

(let* ((serialized-claim (send auction-pdo 'claim-offer))
       (old-owner (nth serialized-claim 0))
       (dependencies (nth serialized-claim 1))
       (signature (nth serialized-claim 2)))
  (assert (send blue-issuer-pdo 'claim old-owner dependencies signature) "failed to claim the bid asset"))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")
