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

(require "test_common.scm")

;; -----------------------------------------------------------------
;; indexes for some keys
(define creator  1)
(define exchange 2)
(define vetting  3)
(define first-person 10)

;; -----------------------------------------------------------------
;; create the asset type pdo
;; -----------------------------------------------------------------
(use-person vetting)
(define asset-type-pdo (make-instance asset-type-contract))

(send asset-type-pdo 'initialize "blue marbles" "asset type for representing blue marbles" "")
(define type-identifier (send asset-type-pdo 'get-identifier))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(use-person vetting)
(define vetting-pdo (make-instance vetting-organization-contract))
(send vetting-pdo 'initialize type-identifier)

;; -----------------------------------------------------------------
;; create the issuer pdo
;; -----------------------------------------------------------------
(use-person creator)
(define issuer-pdo (make-instance issuer-contract))
(let ((issuer-verifying-key (send issuer-pdo 'get-verifying-key (use-person* creator))))
  (send vetting-pdo 'add-approved-key issuer-verifying-key (use-person* vetting)))

;; -----------------------------------------------------------------
;; first test... issue a number of assets and check balances
;; -----------------------------------------------------------------
(catch-failed-test
       (let* ((issuer-verifying-key (send issuer-pdo 'get-verifying-key (use-person* creator)))
              (_authority (send vetting-pdo 'get-authority issuer-verifying-key (use-person* creator))))
         (assert (send issuer-pdo 'initialize type-identifier _authority (use-person* creator)) "initialize failed")

         (test-logger::logger-info "---------- issue assets ----------")
         (do ((pnumber first-person (+ pnumber 1)))
             ((>= pnumber person-count))
           (assert (send issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* creator)) "issue failed")
           (assert (= (send issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance"))))

(dump-ledger issuer-pdo)

(catch-failed-test
       (assert (zero? (send issuer-pdo 'get-balance (use-person* 5))) "balance should have been 0"))

;; -----------------------------------------------------------------
;; second test... transfer assets
;; -----------------------------------------------------------------
(catch-failed-test
       (test-logger::logger-info "---------- transfer 5 assets from person 1 to person 2 ----------")
       (let ((balance11 (send issuer-pdo 'get-balance (use-person* 11)))
             (balance12 (send issuer-pdo 'get-balance (use-person* 12))))
         (assert (send issuer-pdo 'transfer (person 12) 5 (use-person* 11)) "transfer failed")
         (assert (= (send issuer-pdo 'get-balance (use-person* 11)) (- balance11 5)) "incorrect balance after transfer")
         (assert (= (send issuer-pdo 'get-balance (use-person* 12)) (+ balance12 5)) "incorrect balance after transfer")))

(catch-failed-test
       (test-logger::logger-info "---------- transfer 5 assets from person 1 to new person 11 ----------")
       (let ((balance11 (send issuer-pdo 'get-balance (use-person* 11)))
             (balance21 (send issuer-pdo 'get-balance (use-person* 21))))
         (assert (send issuer-pdo 'transfer (person 21) 5 (use-person* 11)) "transfer failed")
         (assert (= (send issuer-pdo 'get-balance (use-person* 11)) (- balance11 5)) "incorrect balance for old user after transfer")
         (assert (= (send issuer-pdo 'get-balance (use-person* 21)) (+ balance21 5)) "incorrect balance for new user after transfer")))

;; -----------------------------------------------------------------
;; third test... escrow assets
;; -----------------------------------------------------------------

(catch-failed-test
       (test-logger::logger-info "---------- escrow asset ----------")
       (assert (send issuer-pdo 'escrow (person exchange) (use-person* 13)) "escrow failed")
       (assert (not (active-entry? issuer-pdo (person 13))) "failed to escrow entry")
       (catch-success (send issuer-pdo 'transfer (person 23) 1 (use-person* 13)) "illegal transfer succeeded")
       (let* ((serialized-attestation (send issuer-pdo 'escrow-attestation (use-person* 13)))
              (authoritative-asset-object (deserialize-authoritative-asset serialized-attestation))
              (asset-object (send authoritative-asset-object 'get-asset))
              (dependencies (send authoritative-asset-object 'get-dependencies))
              (signature (send authoritative-asset-object 'get-signature))
              (authority-object (send authoritative-asset-object 'get-issuer-authority)))
         (assert (string=? type-identifier (send asset-object 'get-asset-type-id)) "incorrect asset type")
         (assert (let ((k1 (send authority-object 'get-issuer-verifying-key))
                       (k2 (send issuer-pdo 'get-verifying-key)))
                   (string=? k1 k2)) "wrong verifying key")
         (assert (send authority-object 'verify type-identifier) "failed to verify authority")
         (assert (= (length dependencies) 1) "incorrect dependencies")
         (assert (string=? (get ':contract 'id) (caar dependencies)) "incorrect contract id in dependencies")
         (assert (string=? (get ':contract 'state) (cadar dependencies)) "incorrect state hash in dependencies")

         (test-logger::logger-info "---------- disburse escrowed asset ----------")
         ;; reproduces create-cancellation
         (let* ((dependencies (list (list (random-identifier 32) (random-identifier 32))))
                (escrow-identifier (send asset-object 'get-escrow-identifier))
                (expression (list "_disburse_"  escrow-identifier (send asset-object 'get-owner) dependencies))
                (signature (send (person-key exchange) 'sign-expression expression)))
           (assert (send issuer-pdo 'disburse dependencies signature (use-person* 13)) "disburse failed")
           (assert (active-entry? issuer-pdo (person 13)) "failed to release escrow")

           (let ((balance3 (send issuer-pdo 'get-balance (use-person* 13)))
                 (balance13 (send issuer-pdo 'get-balance (use-person* 23))))
             (assert (send issuer-pdo 'transfer (person 23) 1 (use-person* 13)) "transfer failed")
             (assert (= (send issuer-pdo 'get-balance (use-person* 13)) (- balance3 1)) "wrong balance")
             (assert (= (send issuer-pdo 'get-balance (use-person* 23)) (+ balance13 1)) "wrong balance"))

           ;; attempt duplicate cancellation
           (assert (send issuer-pdo 'escrow (person exchange) (use-person* 13)) "escrow failed")
           (assert (not (active-entry? issuer-pdo (person 13))) "failed to escrow entry")

           (catch-success (send issuer-pdo 'disburse dependencies signature (use-person* 13)) "illegal cancel succeeded"))))

(dump-ledger issuer-pdo)

;; -----------------------------------------------------------------
;; final test... claim escrowed assets
;; -----------------------------------------------------------------
(catch-failed-test
       (test-logger::logger-info "---------- claim ----------")
       (assert (send issuer-pdo 'escrow (person exchange) (use-person* 14)) "escrow failed")

       (let* ((serialized-attestation (send issuer-pdo 'escrow-attestation (use-person* 14)))
              (authoritative-asset-object (deserialize-authoritative-asset serialized-attestation))
              (asset-object (send authoritative-asset-object 'get-asset))

              ;; reproduce create claim
              (dependencies (list (list (random-identifier 32) (random-identifier 32))))
              (escrow-identifier (send asset-object 'get-escrow-identifier))
              (expression (list "_claim_" escrow-identifier (send asset-object 'get-owner) (person 24) dependencies))
              (signature (send (person-key exchange) 'sign-expression expression))

              (balance14 (send issuer-pdo 'get-balance (use-person* 14)))
              (balance24 (send issuer-pdo 'get-balance (use-person* 24))))

         (assert (send issuer-pdo 'claim (person 14) dependencies signature (use-person* 24)) "claim failed")
         (assert (= (send issuer-pdo 'get-balance (use-person* 14)) 0) "wrong balance")
         (assert (= (send issuer-pdo 'get-balance (use-person* 24)) (+ balance24 balance14)) "wrong balance")))

(dump-ledger issuer-pdo)

(test-logger::highlight "ISSUER TEST COMPLETED SUCCESSFULLY")
(quit 0)
