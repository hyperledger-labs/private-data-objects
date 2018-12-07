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
;; NAME: make-key
;;
;; DESCRIPTION: this is a utility function to create a shorter key
;; from an owner's identity (which is an ECDSA public key)
;; -----------------------------------------------------------------
(define (make-key identity . args)
  (let ((value (string-append identity (if (pair? args) (car args) ""))))
    (compute-message-hash value)))

;; -----------------------------------------------------------------
;; NAME: nth
;;
;; DESCRIPTION: return the nth element in a list
;; -----------------------------------------------------------------
(define (nth lst n)
  (if (zero? n) (car lst) (nth (cdr lst) (- n 1))))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define (null-string? s)
  (and (string? s) (zero? (string-length s))))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define (create-claim asset old-owner-identity new-owner-identity signing-key-object)
  (let* ((dependencies (list (list (get ':contract 'id) (get ':contract 'state))))
         (escrow-identifier (send asset 'get-escrow-identifier))
         (expression (list "_claim_" escrow-identifier old-owner-identity new-owner-identity dependencies))
         (signature (send signing-key-object 'sign-expression expression)))
    (list old-owner-identity dependencies signature)))

(define (verify-claim asset old-owner-identity new-owner-identity dependencies signature)
  (let* ((escrow-identifier (send asset 'get-escrow-identifier))
         (expression (list "_claim_" escrow-identifier old-owner-identity new-owner-identity dependencies))
         (escrow-key (send asset 'get-escrow-key))
         (agent-keys (make-instance signing-keys (public-key escrow-key) (private-key ""))))
    (assert (send agent-keys 'verify-expression expression signature) "claim signature mismatch")))

(define (create-cancellation asset identity signing-key-object)
  (let* ((dependencies (list (list (get ':contract 'id) (get ':contract 'state))))
         (escrow-identifier (send asset 'get-escrow-identifier))
         (expression (list "_disburse_" escrow-identifier identity dependencies))
         (signature (send signing-key-object 'sign-expression expression)))
    (list dependencies signature)))

(define (verify-cancellation asset identity dependencies signature)
  (let* ((escrow-identifier (send asset 'get-escrow-identifier))
         (expression (list "_disburse_" escrow-identifier identity dependencies))
         (escrow-key (send asset 'get-escrow-key))
         (agent-keys (make-instance signing-keys (public-key escrow-key) (private-key ""))))
    (assert (send agent-keys 'verify-expression expression signature) "cancellation signature mismatch")))
