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

(require "utility.scm")

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define signing-keys-package
  (package
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

   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define signing-keys signing-keys-package::signing-keys)

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
