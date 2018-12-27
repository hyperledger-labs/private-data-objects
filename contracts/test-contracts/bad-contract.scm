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

(define bad-contract-package
  (package

   ;; =================================================================
   ;; CLASS: bad-contract
   ;; =================================================================
   (define-class bad-contract
     (instance-vars (value 0)))

   ;; -----------------------------------------------------------------
   ;; NAME: big-state
   ;;
   ;; DESCRIPTION:
   ;; Update the value instance variable to include a big matrix
   ;;
   ;; PARAMETERS:
   ;; str -- value to put in each of the matrix cells
   ;; count -- dimensions of the matrix
   ;; -----------------------------------------------------------------
   (define-method bad-contract (big-state str count)
     (assert (string? str) "first parameter must be a string")
     (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
     (instance-set! self 'value (make-vector count (make-vector count str)))
     #t)

   (define-method bad-contract (clear-state)
     (instance-set! self 'value ()))

   ;; -----------------------------------------------------------------
   ;; NAME: many-keys
   ;;
   ;; DESCRIPTION:
   ;; Add many keys to the KV store with a small value
   ;;
   ;; PARAMETERS:
   ;; str -- string used to build the key
   ;; count -- number of keys to create
   ;; -----------------------------------------------------------------
   (define-method bad-contract (many-keys str count)
     (assert (string? str) "first parameter must be a string")
     (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
     (let loop ((i 0))
       (if (< i count)
           (let ((key (string-append str (number->string i))))
             (key-value-put key "_")
             (loop (+ i 1)))))
     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: deep-recursion
   ;;
   ;; DESCRIPTION:
   ;; Many levels of recursion, designed to blow out the gipsy stack
   ;;
   ;; PARAMETERS:
   ;; count -- depth of recursion
   ;; -----------------------------------------------------------------
   (define (_recursive-function_ n)
     (if (< 0 n) (+ 1 (bad-contract-package::_recursive-function_ (- n 1))) 0))

   (define-method bad-contract (deep-recursion count)
     (assert (and (integer? count) (< 0 count)) "parameter must be a positive integer")
     (bad-contract-package::_recursive-function_ count))

   ;; -----------------------------------------------------------------
   ;; NAME: big-value
   ;;
   ;; DESCRIPTION:
   ;; Create a big value with a small key
   ;;
   ;; PARAMETERS:
   ;; str -- string used to build the value
   ;; count -- number of characters to put in the value
   ;; -----------------------------------------------------------------
   (define-method bad-contract (big-value str count)
     (assert (and (string? str) (= (string-length str) 1)) "first parameter must be a one character string")
     (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
     (let ((big-string (make-string count (string-ref str 0))))
       (key-value-put str big-string)
       (key-value-get str)))

   ))

(define bad-contract bad-contract-package::bad-contract)
