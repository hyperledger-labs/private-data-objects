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
(require "exchange.scm")

(require "test_common.scm")

;; -----------------------------------------------------------------
;; indexes for some keys
(define blue-vetting  20)
(define blue-issuer  21)
(define red-vetting  25)
(define red-issuer  26)

(define alice  1)
(define bob    11)

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
     (do ((pnumber 0 (+ pnumber 1)))
         ((= pnumber 10))
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
     (do ((pnumber 10 (+ pnumber 1)))
         ((= pnumber 20))
       (assert (send red-issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* red-issuer)) "issue failed")
       (assert (= (send red-issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance")))))

(dump-ledger red-issuer-pdo "RED LEDGER")

;; -----------------------------------------------------------------
;; work as alice
;;
;; alice owns blue marbles and wants to offer them for red marbles
;; -----------------------------------------------------------------
(define exchange-pdo)

(use-person alice)
(catch-failed-test
 (test-logger::logger-info "---------- prime exchange and offer asset ----------")
 (set! exchange-pdo (make-instance exchange-contract))

 ;; create an asset request for 21 red marbles with red-vetting-pdo as the root of trust
 (let ((asset-request (make-instance asset-request-class (asset-type-id red-type-identifier) (count 21))))
   (let ((serialized-request (send asset-request 'serialize))
         (red-vetting-key (send red-vetting-pdo 'get-verifying-key)))
     (send exchange-pdo 'initialize serialized-request red-vetting-key)))

 ;; escrow the blue marbles that will be offered for exchange
 (assert (send blue-issuer-pdo 'escrow (send exchange-pdo 'get-verifying-key)) "failed to escrow blue marbles")
 (let ((serialized-attestation (send blue-issuer-pdo 'escrow-attestation)))
   (assert (send exchange-pdo 'offer-asset serialized-attestation) "failed to offer asset")))

(test-logger::logger-info "OFFERED ASSET: " (send exchange-pdo 'examine-offered-asset))
(test-logger::logger-info "REQUESTED ASSET: " (send exchange-pdo 'examine-requested-asset))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

;; -----------------------------------------------------------------
;; work as bob
;;
;; bob owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------

(use-person bob)
(catch-failed-test
 (test-logger::logger-info "---------- exchange asset ----------")
 (assert (send red-issuer-pdo 'escrow (send exchange-pdo 'get-verifying-key)) "failed to escrow red marbles")
 (let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
   (assert (send exchange-pdo 'exchange-asset serialized-attestation) "failed to offer asset")))

(dump-ledger red-issuer-pdo "RED LEDGER")

(catch-failed-test
 (test-logger::logger-info "---------- bob claims the offer ----------")
 (let* ((claim-attestation (send exchange-pdo 'claim-offer))
        (owner-identity (nth claim-attestation 0))
        (dependencies (nth claim-attestation 1))
        (signature (nth claim-attestation 2)))
   ;; time for bob to claim his blue marbles
   (assert (send blue-issuer-pdo 'claim owner-identity dependencies signature) "failed to claim blue marbles")))

(dump-ledger blue-issuer-pdo "BLUE LEDGER")

;; -----------------------------------------------------------------
;; work as alice
;; -----------------------------------------------------------------

(use-person alice)
(catch-failed-test
 (test-logger::logger-info "---------- alice claims the exchange ----------")
 (let* ((claim-attestation (send exchange-pdo 'claim-exchange))
        (owner-identity (nth claim-attestation 0))
        (dependencies (nth claim-attestation 1))
        (signature (nth claim-attestation 2)))
   ;; time for alice to claim her red marbles
   (assert (send red-issuer-pdo 'claim owner-identity dependencies signature) "failed to claim red marbles")))

(dump-ledger red-issuer-pdo "RED LEDGER")

(test-logger::highlight "EXCHANGE TEST COMPLETED SUCCESSFULLY")
(quit 0)
