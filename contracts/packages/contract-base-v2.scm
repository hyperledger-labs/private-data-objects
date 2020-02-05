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
(define base-contract-v2-package
  (package
   (define-class base-contract-v2
     (class-vars
      (interface-version 2))

     (instance-vars
      (base_initialized #f)
      (creator "")
      (contract-signing-keys #f)
      (contract-encryption-keys #f)))

   (define-method base-contract-v2 (initialize-instance . args)
     (if (not base_initialized)
         (let* ((environment (car args))
                (requestor (send environment 'get-originator-id)))
           (instance-set! self 'creator requestor)
           (instance-set! self 'contract-signing-keys (make-instance signing-keys))
           (instance-set! self 'contract-encryption-keys (make-instance encryption-keys))
           (instance-set! self 'base_initialized #t))))

   (define-method base-contract-v2 (_get-public-encryption-key_)
     (send contract-encryption-keys 'get-public-encryption-key))

   (define-method base-contract-v2 (_get-public-signing-key_)
     (send contract-signing-keys 'get-public-signing-key))

   (define-const-method base-contract-v2 (get-public-encryption-key environment)
     (let ((key (send self '_get-public-encryption-key_)))
       (dispatch-package::return-value key #f)))

   (define-const-method base-contract-v2 (get-public-signing-key environment)
     (let ((key (send self '_get-public-signing-key_)))
       (dispatch-package::return-value key #f)))

   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define base-contract-v2 base-contract-v2-package::base-contract-v2)
