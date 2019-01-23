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
(define encryption-keys-package
  (package
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

   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define encryption-keys encryption-keys-package::encryption-keys)
