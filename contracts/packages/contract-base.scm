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

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(define (coerce-number value)
  (if (number? value) value (string->number value)))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define-class signing-keys
  (instance-vars
   (private-key "")
   (public-key "")))

(define-method signing-keys (initialize-instance . args)
  (if (string=? public-key "")
      (let ((_keys_ (ecdsa-create-signing-keys)))
        (instance-set! self 'private-key (car _keys_))
        (instance-set! self 'public-key (cadr _keys_)))))

(define-method signing-keys (get-public-signing-key) public-key)

(define-method signing-keys (sign message)
  (assert (string? message) "message must be a string" message)
  (assert (not (string=? private-key "")) "not initialized for signing")
  (ecdsa-sign-message message private-key))

(define-method signing-keys (sign-expression expression)
  (send self 'sign (expression->string expression)))

(define-method signing-keys (verify message signature)
  (assert (string? message) "message must be a string" message)
  (assert (string? signature) "signature must be a string" signature)
  (ecdsa-verify-signature message signature public-key))

(define-method signing-keys (verify-expression expression signature)
  (send self 'verify (expression->string expression) signature))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define-class encryption-keys
  (instance-vars
   (private-key "")
   (public-key "")))

(define-method encryption-keys (initialize-instance . args)
  (if (string=? public-key "")
      (let ((_keys_ (rsa-create-keys)))
        (instance-set! self 'private-key (car _keys_))
        (instance-set! self 'public-key (cadr _keys_)))))

(define-method encryption-keys (get-public-encryption-key) public-key)

(define-method encryption-keys (encrypt message)
  (assert (string? message) "message must be a string" message)
  (assert (not (string=? private-key "")) "not initialized for encryption")
  (rsa-encrypt message public-key))

(define-method encryption-keys (encrypt-expression expression)
  (send self 'encrypt (expression->string expression)))

(define-method encryption-keys (decrypt-expression cipher)
  (string->expression (send self 'decrypt cipher)))

(define-method encryption-keys (decrypt cipher)
  (assert (string? cipher) "cipher text must be a string" cipher)
  (rsa-decrypt cipher private-key))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define-class base-contract
  (instance-vars
   (creator "")
   (contract-signing-keys #f)
   (contract-encryption-keys #f)))

(define-method base-contract (initialize-instance . args)
  (if (string=? creator "")
      (instance-set! self 'creator (get ':message 'originator)))
  (if (not contract-signing-keys)
      (instance-set! self 'contract-signing-keys (make-instance signing-keys)))
  (if (not contract-encryption-keys)
      (instance-set! self 'contract-encryption-keys (make-instance encryption-keys))))

(define-method base-contract (get-creator) creator)

(define-const-method base-contract (get-public-encryption-key)
  (send contract-encryption-keys 'get-public-encryption-key))

(define-const-method base-contract (get-public-signing-key)
  (send contract-signing-keys 'get-public-signing-key))

;;(define-method base-contract (encrypt message)
;;  (send contract-encryption-keys 'encrypt message))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
;; key-list-generator is used primarily for generating batches of
;; keys for building tests
(include-when
 (member "debug" *args*)
 (define (key-list-generator count)
   (let ((_keys_ (list->vector (do ((count count (- count 1))
                                    (result '() (cons (make-instance signing-keys) result)))
                                   ((zero? count) result)))))
     (lambda (n) (vector-ref _keys_ n)))))
