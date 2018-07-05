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

(require "contract-base.scm")

(require "asset_class.scm")
(require "authority_class.scm")

;; =================================================================
;; CLASS: authoritative-asset-class
;; =================================================================
(define-class authoritative-asset-class
  (instance-vars
   (asset #f)
   (dependencies '())                   ; state updates that must be committed before this attestation is valid
   (signature "")                       ; signature from the issuer that this is a valid asset
   (issuer-authority #f)))

(define-method authoritative-asset-class (get-asset) asset)
(define-method authoritative-asset-class (get-dependencies) dependencies)
(define-method authoritative-asset-class (get-signature) signature)
(define-method authoritative-asset-class (get-issuer-authority) issuer-authority)

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authoritative-asset-class (trusted-authority? authority-key)
  (let loop ((authority-object issuer-authority))
    (let ((issuer-verifying-key (send authority-object 'get-issuer-verifying-key))
          (parent-authority (send authority-object 'get-parent-authority)))
      (if (send authority-object 'is-root-authority?)
          (string=? authority-key parent-authority)
          (or (string=? authority-key issuer-verifying-key) (loop parent-authority))))))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authoritative-asset-class (verify)
  (assert (instance? asset) "invalid asset")
  (assert (instance? issuer-authority) "invalid authority")
  (assert (string? signature) "invalid signature")

  (and
   (send issuer-authority 'verify (send asset 'get-asset-type-id))
   (let* ((expression (send self 'serialize-for-signing))
          (issuer-keys (send issuer-authority 'get-issuer-keys)))
     (send issuer-keys 'verify-expression expression signature))))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;;     signing-keys -- asset issuer's signing-keys
;; -----------------------------------------------------------------
(define-method authoritative-asset-class (sign signing-keys)
  (let ((expression (send self 'serialize-for-signing)))
    (instance-set! self 'signature (send signing-keys 'sign-expression expression))))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authoritative-asset-class (serialize-for-signing)
  (list (send asset 'serialize-for-signing) dependencies))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authoritative-asset-class (serialize-for-sending)
  (let ((serialized-asset (send asset 'serialize-for-sending))
	(serialized-authority (send issuer-authority 'serialize-for-sending)))
    (list serialized-asset dependencies signature serialized-authority)))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authoritative-asset-class (deserialize serialized)
  (instance-set! self 'asset (make-instance asset-class))
  (instance-set! self 'dependencies (nth serialized 1))
  (instance-set! self 'signature (nth serialized 2))
  (instance-set! self 'issuer-authority (make-instance authority-class))

  (send asset 'deserialize (nth serialized 0))
  (send issuer-authority 'deserialize (nth serialized 3))

  ;; make sure this is a good asset
  (assert (send issuer-authority 'verify (send asset 'get-asset-type-id)) "unable to verify issuer authority")
  (assert (send self 'verify) "unable to verify asset")

  #t)

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define (deserialize-authoritative-asset serialized)
  (let ((object (make-instance authoritative-asset-class)))
    (display "deserialize\n")
    (send object 'deserialize serialized)
    object))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define (create-authoritative-asset asset-object dependencies authority-object)
  (let ((object (make-instance authoritative-asset-class)))
    (instance-set! object 'asset asset-object)
    (instance-set! object 'dependencies dependencies)
    (instance-set! object 'issuer-authority authority-object)
    object))
