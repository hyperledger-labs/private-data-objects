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
;; integer-key.scm
;;
;; Define the contract class for integer-key. The integer-key contract is
;; a simple test contract that associates positive integer values with a
;; string key. Simple rules on update rights are implemented. Value escrow
;; is supported to test contract to contract interactions.
;;

(require-when (member "debug" *args*) "debug.scm")
(require "contract-base.scm")
(require "escrow-counter.scm")
(require "key-store.scm")

;; =================================================================
;; CLASS: integer-key
;; =================================================================
(define-class integer-key
  (super-class base-contract)
  (instance-vars
   (state #f)
   (count 0)))

(define-method integer-key (initialize-instance . args)
  (if (not state)
      (instance-set! self 'state (make-instance key-store))))

;; -----------------------------------------------------------------
;; Methods to interogate the counter store
;; -----------------------------------------------------------------
(define-const-method integer-key (get-state)
  (assert (or (null? creator) (equal? creator (get ':message 'originator))) "only creator may dump state")
  (send state 'get-state))

(define-const-method integer-key (get-value key)
  (let* ((requestor (get ':message 'originator))
         (counter (send state 'get key)))
    (assert (send counter 'is-owner? requestor) "only the current owner may get the value of a counter" requestor)
    (send counter 'get-value)))

;; -----------------------------------------------------------------
;; Methods to modify the value of a counter
;; -----------------------------------------------------------------
(define-method integer-key (create key . initial-value)
  (let ((value (if (pair? initial-value) (coerce-number (car initial-value)) 0)))
    (assert (and (integer? value) (<= 0 value)) "initialization value must not be negative")
    (let* ((requestor (get ':message 'originator))
           (counter (make-instance escrow-counter (key key) (value value) (owner requestor))))
      (send state 'create key counter)
      #t)))

;; no owner check required for increment... any one can do it
(define-method integer-key (inc key . oparam)
  (let ((value (if (pair? oparam) (coerce-number (car oparam)) 1)))
    (assert (and (integer? value) (< 0 value)) "increment must be positive integer" value)
    (let* ((requestor (get ':message 'originator))
           (counter (send state 'get key)))
      (assert (send counter 'is-active?) "counter must be active to modify")
      (send counter 'inc value)
      #t)))

(define-method integer-key (dec key . oparam)
  ;; only the owner may decrement a counter
  (let ((value (if (pair? oparam) (coerce-number (car oparam)) 1)))
    (assert (and (integer? value) (< 0 value)) "decrement must be positive integer" value)
    (let* ((requestor (get ':message 'originator))
           (counter (send state 'get key)))
      (assert (send counter 'is-active?) "counter must be active to modify")
      (assert (send counter 'is-owner? requestor) "only the current owner may decrement the value of a counter" requestor)
      (send counter 'dec value)
      #t)))

(define-method integer-key (xfer src dst param)
  (let ((value (coerce-number param)))
    (assert (and (integer? value) (< 0 value)) "amount must be positive integer" value)
    (assert (not (equal? src dst)) "source and destination must be different" src dst)
    (let* ((requestor (get ':message 'originator))
           (scounter (send state 'get src))
           (dcounter (send state 'get dst)))
      (assert (send scounter 'is-owner? requestor) "only the current owner may decrement the value of a counter" requestor)
      (assert (send scounter 'is-active?) "counter must be active to transfer")
      (send scounter 'dec value)
      (send dcounter 'inc value)
      #t)))

(define-method integer-key (transfer-ownership key new-owner)
  (let* ((requestor (get ':message 'originator))
         (counter (send state 'get key)))
    (assert (send counter 'is-owner? requestor) "only the current owner may transfer ownership" requestor)
    (assert (send counter 'is-active?) "counter must be active to transfer")
    (send counter 'set-owner new-owner)))

;; -----------------------------------------------------------------
;; Methods to handle escrow of a counter
;; -----------------------------------------------------------------

;; -----------------------------------------------------------------
;; NAME: escrow
;;
;; DESCRIPTION: place a counter in escrow to a given identity; the
;; counter will be marked inactive. Note that this method changes the
;; state of a counter but does not return an escrow attestion since the
;; state change in this function must be committed first.
;;
;; PARAMETERS:
;;   key -- counter identifier
;;   agent-public-key -- the public key of the owner of the escrow
;; -----------------------------------------------------------------
(define-method integer-key (escrow key agent-public-key)
  (let* ((requestor (get ':message 'originator))
         (counter (send state 'get key)))
    (assert (send counter 'is-owner? requestor) "only the current owner may escrow the value" requestor)
    (send counter 'deactivate agent-public-key)
    #t))

;; -----------------------------------------------------------------
;; NAME: escrow-attestation
;;
;; DESCRIPTION: generate an attestation that a counter has
;; been escrowed; this is distinct from the actual escrow in order
;; to ensure that the state change is committed to the ledger
;;
;; PARAMETERS:
;;   key -- counter identifier
;; -----------------------------------------------------------------
(define-const-method integer-key (escrow-attestation key)
  (let* ((requestor (get ':message 'originator))
         (counter (send state 'get key)))

    (assert (send counter 'is-owner? requestor) "only owner may retrieve escrow status" requestor)
    (assert (not (send counter 'is-active?)) "counter has not been escrowed")

    (let* ((externalized (send counter 'externalize))
           (dependencies (list (list (get ':contract 'id) (get ':contract 'state))))
           (expression (list externalized dependencies))
           (signature (send contract-signing-keys 'sign-expression expression)))
      (list externalized dependencies signature))))

;; -----------------------------------------------------------------
;; NAME: disburse
;;
;; DESCRIPTION: release a counter from escrow; the signature is provided
;; by the agent that is currently responsible for the counter; the signature
;; is over the externalized counter and any dependencies that are specified
;;
;; PARAMETERS:
;;   key -- counter identifier
;;   dependencies -- association list mapping contract ids to corresponding state hash
;;   signature -- base64 encoded signature
;; -----------------------------------------------------------------
(define-method integer-key (disburse key dependencies signature)
  (let* ((requestor (get ':message 'originator))
         (counter (send state 'get key)))

    (assert (send counter 'is-owner? requestor) "only the current owner may disburse the value" requestor)
    (assert (not (send counter 'is-active?)) "counter has not been escrowed")

    (let* ((externalized (send counter 'externalize))
           (expression (list externalized dependencies))
           (public-key (send counter 'get-escrow-key))
           (agent-keys (make-instance signing-keys (public-key public-key) (private-key ""))))

      (assert (send agent-keys 'verify-expression expression signature) "signature mismatch" signature)

      ;; this update cannot be committed unless the dependencies are committed
      (if (pair? dependencies) (put ':ledger 'dependencies dependencies))
      (send counter 'activate)

      #t)))

;; -----------------------------------------------------------------
;; NAME: exchange-ownership
;;
;; DESCRIPTION: exchange the ownership of two counters that have been
;; escrowed to a common agent (for fair exchange); the escrow agent
;; provides permission for the exchange in the signature
;;
;; PARAMETERS:
;;   key1 -- counter identifier
;;   key2 -- counter identifier
;;   dependencies -- association list mapping contract ids to corresponding state hash
;;   signature -- base64 encoded signature, signature generated using agents keys
;; -----------------------------------------------------------------
(define-method integer-key (exchange-ownership key1 key2 dependencies signature)
  (let* ((requestor (get ':message 'originator))
         (counter1 (send state 'get key1))
         (counter2 (send state 'get key2)))

    (assert (send counter1 'is-owner? requestor) "exchange can only be initiated by the owner of a counter" requestor)
    (assert (not (send counter1 'is-active?)) "counter has not been escrowed" key1)
    (assert (not (send counter2 'is-active?)) "counter has not been escrowed" key2)

    ; handle the verification of signatures first
    (let ((escrow1 (send counter1 'get-escrow-key))
          (escrow2 (send counter2 'get-escrow-key)))

      (assert (string=? escrow1 escrow2) "exchange requires escrow by the same entity")

      (let* ((agent-keys (make-instance signing-keys (public-key escrow1) (private-key "")))
             (external1 (send counter1 'externalize))
             (external2 (send counter2 'externalize))
             (expression (list external1 external2 dependencies)))

        (assert (send agent-keys 'verify-expression expression signature) "signature mismatch" signature)))

    ; check the owners and initiate the transfer
    (let ((owner1 (send counter1 'get-owner))
          (owner2 (send counter2 'get-owner)))
      ;; this update cannot be committed unless the dependencies are committed
      (if (pair? dependencies) (put ':ledger 'dependencies dependencies))
      (send counter1 'activate)
      (send counter1 'set-owner owner2)
      (send counter2 'activate)
      (send counter2 'set-owner owner1)

      #t)))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(require-when (member "test-integer-key" *args*) "integer-key-test.scm")
