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

(require "safe-key-store.scm")

(define-macro (assert pred . message)
  `(if (not ,pred) (throw ,@message)))

(define memory-test-package
  (package

   (define default-value "_")
   (define default-key "key")

   (define (get-with-default key pred args default)
     (let* ((arg-value (if (pair? args) (assoc key args) #f))
            (value (cond ((not arg-value) default)
                         ((pair? (cdr arg-value)) (cadr arg-value))
                         ((throw "invalid associative argument" key)))))
       (assert (pred value) "wrong type of associative argument" key)
       value))

   ;; =================================================================
   ;; CLASS: memory-test
   ;; =================================================================
   (define-class memory-test
     (instance-vars (value 0)))

   ;; -----------------------------------------------------------------
   ;; NAME: big-state
   ;;
   ;; DESCRIPTION:
   ;; Update the value instance variable to include a big matrix
   ;;
   ;; PARAMETERS:
   ;; dimension -- dimensions of the matrix
   ;; optional: value -- value to put in each of the matrix cells
   ;;
   ;; '(big-state 10 '(value "v"))
   ;;
   ;; -----------------------------------------------------------------
   (define-method memory-test (big-state dimension . args)
     (assert (and (integer? dimension) (< 0 dimension)) "second parameter must be a positive integer")
     (let ((value (memory-test-package::get-with-default 'value string? args memory-test-package::default-value)))
       (instance-set! self 'value (make-vector dimension (make-vector dimension value))))
     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: clear-state
   ;;
   ;; DESCRIPTION:
   ;; Clear the value making the intrinsic state small again
   ;; -----------------------------------------------------------------
   (define-method memory-test (clear-state)
     (instance-set! self 'value ())
     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: deep-recursion
   ;;
   ;; DESCRIPTION:
   ;; Many levels of recursion, designed to blow out the gipsy stack
   ;;
   ;; PARAMETERS:
   ;; depth -- depth of recursion
   ;; -----------------------------------------------------------------
   (define (_recursive-function_ n)
     (if (< 0 n) (+ 1 (memory-test-package::_recursive-function_ (- n 1))) 0))

   (define-method memory-test (deep-recursion depth)
     (assert (and (integer? depth) (< 0 depth)) "parameter must be a positive integer")
     (memory-test-package::_recursive-function_ depth))

   ;; -----------------------------------------------------------------
   ;; NAME: many-keys
   ;;
   ;; DESCRIPTION:
   ;; Add many keys to the KV store with a small value
   ;;
   ;; PARAMETERS:
   ;; count -- number of keys to create
   ;; optional: key-base -- string used to build the key
   ;; optional: value -- value to put into each key
   ;;
   ;; '(many-keys 10 '(key-base "key") '(value "v"))
   ;;
   ;; -----------------------------------------------------------------
   (define-method memory-test (many-keys count . args)
     (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
     (let ((key-base (memory-test-package::get-with-default 'key-base string? args memory-test-package::default-key))
           (value (memory-test-package::get-with-default 'value string? args memory-test-package::default-value)))
       (let loop ((i 0))
         (if (< i count)
             (let ((key (string-append key-base (number->string i))))
               (safe-kv-put key "_")
               (loop (+ i 1))))))
     #t)

   ;; -----------------------------------------------------------------
   ;; NAME: big-value
   ;;
   ;; DESCRIPTION:
   ;; Create a big value with a small key
   ;;
   ;; PARAMETERS:
   ;; size -- number of characters to put in the value
   ;; optional: key -- key to use for the put
   ;; optional: value-base -- string to use for the value
   ;; -----------------------------------------------------------------
   (define-method memory-test (big-value size . args)
     (assert (and (integer? size) (< 0 size)) "second parameter must be a positive integer")
     (let ((key (memory-test-package::get-with-default 'key string? args memory-test-package::default-key))
           (value-base (memory-test-package::get-with-default 'value-base string? args memory-test-package::default-value)))
       (assert (= (string-length value-base) 1) "value base must be a one character string")
       (let ((big-string (make-string size (string-ref value-base 0))))
         (safe-kv-put key big-string)
         (safe-kv-get key))))

   ))

(define memory-test memory-test-package::memory-test)
