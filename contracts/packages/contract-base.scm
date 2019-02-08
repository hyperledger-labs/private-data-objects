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
(require "signing-keys.scm")
(require "encryption-keys.scm")

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define base-contract-package
  (package
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

   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define base-contract base-contract-package::base-contract)
