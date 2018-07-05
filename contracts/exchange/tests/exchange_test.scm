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


;; -----------------------------------------------------------------
(put ':contract 'id (random-identifier 32))
(put ':contract 'state (random-identifier 32))

(define person-key (key-list-generator 40))

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
               (escrow (cadr (assoc 'escrow-key (cadr entry))))
               (owner (cadr (assoc 'owner (cadr entry)))))
          (if (string=? escrow "")
              (result-print (string-append entry-key " --> ") entry-val)
              (result-print (string-append entry-key " --> ") entry-val "<ESCROW>"))
          (loop (cdr ledger-state))))))

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
(use-person blue-vetting)
(define blue-asset-type-pdo (make-instance asset-type-contract))
(send blue-asset-type-pdo 'initialize "blue marbles" "asset type for representing blue marbles" "")
(define blue-type-identifier (send blue-asset-type-pdo 'get-identifier))

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

(dump-ledger blue-issuer-pdo)

;; -----------------------------------------------------------------
;; set up the red marble issuer
;; -----------------------------------------------------------------
(use-person red-vetting)
(define red-asset-type-pdo (make-instance asset-type-contract))
(send red-asset-type-pdo 'initialize "red marbles" "asset type for representing red marbles" "")
(define red-type-identifier (send red-asset-type-pdo 'get-identifier))

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

(dump-ledger red-issuer-pdo)

;; -----------------------------------------------------------------
;; work as alice
;;
;; alice owns blue marbles and wants to offer them for red marbles
;; -----------------------------------------------------------------

(use-person alice)

;; create the exchange contract
(define exchange-pdo (make-instance exchange-contract))

(display "---------- prime exchange and offer asset ----------\n")

;; create an asset request for 21 red marbles with red-vetting-pdo as the root of trust
(let ((asset-request (make-instance asset-request-class (asset-type-id red-type-identifier) (count 21))))
  (let ((serialized-request (send asset-request 'serialize))
        (red-vetting-key (send red-vetting-pdo 'get-verifying-key)))
    (send exchange-pdo 'initialize serialized-request red-vetting-key)))

;; escrow the blue marbles that will be offered for exchange
(assert (send blue-issuer-pdo 'escrow (send exchange-pdo 'get-verifying-key)) "failed to escrow blue marbles")
(let ((serialized-attestation (send blue-issuer-pdo 'escrow-attestation)))
  (assert (send exchange-pdo 'offer-asset serialized-attestation) "failed to offer asset"))

(result-print "OFFERED ASSET: " (send exchange-pdo 'examine-offered-asset))
(result-print "REQUESTED ASSET: " (send exchange-pdo 'examine-requested-asset))

(dump-ledger blue-issuer-pdo)

;; -----------------------------------------------------------------
;; work as bob
;;
;; bob owns red marbles and wants to trade them for alice's blue marbles
;; -----------------------------------------------------------------

(use-person bob)

(display "---------- exchange asset ----------\n")

(assert (send red-issuer-pdo 'escrow (send exchange-pdo 'get-verifying-key)) "failed to escrow red marbles")
(let ((serialized-attestation (send red-issuer-pdo 'escrow-attestation)))
  (display "pre-exchange\n")
  (assert (send exchange-pdo 'exchange-asset serialized-attestation) "failed to offer asset"))

(dump-ledger red-issuer-pdo)

(display "---------- bob claims the offer ----------\n")
(let* ((claim-attestation (send exchange-pdo 'claim-offer))
       (owner-identity (nth claim-attestation 0))
       (dependencies (nth claim-attestation 1))
       (signature (nth claim-attestation 2)))
  ;; time for bob to claim his blue marbles
  (assert (send blue-issuer-pdo 'claim owner-identity dependencies signature) "failed to claim blue marbles"))

(dump-ledger blue-issuer-pdo)

;; -----------------------------------------------------------------
;; work as alice
;; -----------------------------------------------------------------

(use-person alice)

(display "---------- alice claims the exchange ----------\n")
(let* ((claim-attestation (send exchange-pdo 'claim-exchange))
       (owner-identity (nth claim-attestation 0))
       (dependencies (nth claim-attestation 1))
       (signature (nth claim-attestation 2)))
  ;; time for alice to claim her red marbles
  (assert (send red-issuer-pdo 'claim owner-identity dependencies signature) "failed to claim red marbles"))

(dump-ledger red-issuer-pdo)
