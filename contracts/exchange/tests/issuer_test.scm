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

;; -----------------------------------------------------------------
(put ':contract 'id (random-identifier 32))
(put ':contract 'state (random-identifier 32))

(define person-key (key-list-generator 30))

;; indexes for some keys
(define creator  20)
(define exchange 21)
(define vetting  22)

(define (person n) (send (person-key n) 'get-public-signing-key))
(define (use-person n) (put ':message 'originator (person n)))
(define (use-person* n) (list ':message 'originator (person n)))

;; -----------------------------------------------------------------
(define (dump-ledger ledger-pdo)
  (result-print "---------- LEDGER STATE ----------")
  (let loop ((ledger-state (send ledger-pdo 'dump-ledger)))
    (if (pair? ledger-state)
        (let* ((entry (car ledger-state))
               (entry-key (car entry))
               (entry-val (cadr (assoc 'count (cadr entry))))
               (owner (cadr (assoc 'owner (cadr entry)))))
          (result-print (string-append entry-key " --> ") entry-val)
          (loop (cdr ledger-state))))))

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
(catch error-print
       (let* ((issuer-verifying-key (send issuer-pdo 'get-verifying-key (use-person* creator)))
              (_authority (send vetting-pdo 'get-authority issuer-verifying-key (use-person* creator))))
         (assert (send issuer-pdo 'initialize type-identifier _authority (use-person* creator)) "initialize failed")

         (result-print "---------- issue assets ----------")
         (do ((pnumber 1 (+ pnumber 1)))
             ((> pnumber 10))
           (assert (send issuer-pdo 'issue (person pnumber) (+ 10 pnumber) (use-person* creator)) "issue failed")
           (assert (= (send issuer-pdo 'get-balance (use-person* pnumber)) (+ 10 pnumber)) "incorrect balance"))))

(dump-ledger issuer-pdo)

(catch error-print
       (assert (zero? (send issuer-pdo 'get-balance (use-person* 11))) "balance should have been 0"))

;; -----------------------------------------------------------------
;; second test... transfer assets
;; -----------------------------------------------------------------
(catch error-print
       (result-print "---------- transfer 5 assets from person 1 to person 2 ----------")
       (let ((balance1 (send issuer-pdo 'get-balance (use-person* 1)))
             (balance2 (send issuer-pdo 'get-balance (use-person* 2))))
         (assert (send issuer-pdo 'transfer (person 2) 5 (use-person* 1)) "transfer failed")
         (assert (= (send issuer-pdo 'get-balance (use-person* 1)) (- balance1 5)) "incorrect balance after transfer")
         (assert (= (send issuer-pdo 'get-balance (use-person* 2)) (+ balance2 5)) "incorrect balance after transfer")))

(catch error-print
       (result-print "---------- transfer 5 assets from person 1 to new person 11 ----------")
       (let ((balance1 (send issuer-pdo 'get-balance (use-person* 1)))
             (balance11 (send issuer-pdo 'get-balance (use-person* 11))))
         (assert (send issuer-pdo 'transfer (person 11) 5 (use-person* 1)) "transfer failed")
         (assert (= (send issuer-pdo 'get-balance (use-person* 1)) (- balance1 5)) "incorrect balance for old user after transfer")
         (assert (= (send issuer-pdo 'get-balance (use-person* 11)) (+ balance11 5)) "incorrect balance for new user after transfer")))

;; -----------------------------------------------------------------
;; third test... escrow assets
;; -----------------------------------------------------------------
(catch error-print
       (result-print "---------- escrow asset ----------")
       (assert (send issuer-pdo 'escrow (person exchange) (use-person* 3)) "escrow failed")
       (catch-success (send issuer-pdo 'transfer (person 13) 1 (use-person* 3)) "illegal transfer succeeded")
       (let* ((serialized-attestation (send issuer-pdo 'escrow-attestation (use-person* 3)))
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

         (result-print "---------- disburse escrowed asset ----------")
         (let* ((dependencies (list (list (random-identifier 32) (random-identifier 32))))
                (expression (list "_disburse_" (send asset-object 'get-owner) dependencies))
                (signature (send (person-key exchange) 'sign-expression expression)))
           (assert (send issuer-pdo 'disburse dependencies signature (use-person* 3)) "disburse failed")
           (let ((balance3 (send issuer-pdo 'get-balance (use-person* 3)))
                 (balance13 (send issuer-pdo 'get-balance (use-person* 13))))
             (assert (send issuer-pdo 'transfer (person 13) 1 (use-person* 3)) "transfer failed")
             (assert (= (send issuer-pdo 'get-balance (use-person* 3)) (- balance3 1)) "wrong balance")
             (assert (= (send issuer-pdo 'get-balance (use-person* 13)) (+ balance13 1)) "wrong balance")))))

(dump-ledger issuer-pdo)

;; -----------------------------------------------------------------
;; final test... claim escrowed assets
;; -----------------------------------------------------------------
(catch error-print
       (result-print "---------- claim ----------")
       (assert (send issuer-pdo 'escrow (person exchange) (use-person* 4)) "escrow failed")

       (let* ((serialized-attestation (send issuer-pdo 'escrow-attestation (use-person* 4)))
              (authoritative-asset-object (deserialize-authoritative-asset serialized-attestation))
              (asset-object (send authoritative-asset-object 'get-asset))

              (dependencies (list (list (random-identifier 32) (random-identifier 32))))
              (expression (list "_claim_" (send asset-object 'get-owner) (person 14) dependencies))
              (signature (send (person-key exchange) 'sign-expression expression))

              (balance4 (send issuer-pdo 'get-balance (use-person* 4)))
              (balance14 (send issuer-pdo 'get-balance (use-person* 14))))

         (assert (send issuer-pdo 'claim (person 4) dependencies signature (use-person* 14)) "claim failed")
         (assert (= (send issuer-pdo 'get-balance (use-person* 4)) 0) "wrong balance")
         (assert (= (send issuer-pdo 'get-balance (use-person* 14)) (+ balance14 balance4)) "wrong balance")))

(dump-ledger issuer-pdo)
