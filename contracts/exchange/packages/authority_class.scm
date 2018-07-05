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
(require "exchange_common.scm")

;; =================================================================
;; CLASS: authority-class
;; =================================================================
(define-class authority-class
  (instance-vars
   (issuer-verifying-key "")
   (dependencies '())          ; state updates that must be committed before this attestation is valid
   (signature "")              ; this is the signature from either the trust root or the parent authority
   (parent-authority #f)))

(define-method authority-class (get-issuer-verifying-key) issuer-verifying-key)
(define-method authority-class (get-dependencies) dependencies)
(define-method authority-class (get-signature) signature)
(define-method authority-class (get-parent-authority) parent-authority)

(define-method authority-class (is-root-authority?)
  (string? parent-authority))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (get-issuer-keys)
  (make-instance signing-keys (public-key issuer-verifying-key) (private-key "")))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (get-parent-keys)
  (if (send self 'is-root-authority?)
      (make-instance signing-keys (public-key parent-authority) (private-key ""))
      (send parent-authority 'get-issuer-keys)))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (sign asset-type-id signing-keys)
  (let* ((expression (send self 'serialize-for-signing asset-type-id))
         (signature (send signing-keys 'sign-expression expression)))
    (instance-set! self 'signature signature)
    signature))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (verify asset-type-id)
  (let* ((expression (send self 'serialize-for-signing asset-type-id))
         (verifying-keys (send self 'get-parent-keys)))
    (send verifying-keys 'verify-expression expression signature)))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (serialize-for-signing asset-type-id)
  (list asset-type-id issuer-verifying-key dependencies))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (serialize-for-sending)
  (if (send self 'is-root-authority?)
      (list issuer-verifying-key dependencies signature parent-authority)
      (list issuer-verifying-key dependencies signature (send parent-authority 'serialize-for-sending))))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define-method authority-class (deserialize serialized)
  (instance-set! self 'issuer-verifying-key (nth serialized 0))
  (instance-set! self 'dependencies (nth serialized 1))
  (instance-set! self 'signature (nth serialized 2))
  (let ((serialized-parent (nth serialized 3)))
    (if (string? serialized-parent)
        (instance-set! self 'parent-authority serialized-parent)
        (begin
          (instance-set! self 'parent-authority (make-instance authority-class))
          (send parent-authority 'deserialize serialized-parent))))
  #t)

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define (deserialize-authority-object serialized)
  (let ((object (make-instance authority-class)))
    (send object 'deserialize serialized)
    object))

;; -----------------------------------------------------------------
;; NAME:
;;
;; DESCRIPTION:
;;
;; PARAMETERS:
;; -----------------------------------------------------------------
(define (create-root-authority asset-type-id issuer-verifying-key dependencies root-authority-keys)
  (let ((object (make-instance authority-class)))
    (instance-set! object 'issuer-verifying-key issuer-verifying-key)
    (instance-set! object 'dependencies dependencies)
    (instance-set! object 'parent-authority (send root-authority-keys 'get-public-signing-key))
    (send object 'sign asset-type-id root-authority-keys)
    object))
