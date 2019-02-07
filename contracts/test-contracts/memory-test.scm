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
(require "safe-key-store.scm")
(require "persistent-vector.scm")

(define memory-test-package
  (package

   (define default-value "_")
   (define default-key "key")

   ;; =================================================================
   ;; CLASS: memory-test
   ;; =================================================================
   (define-class memory-test
     (instance-vars
      (_initialized #f)
      (_persistent_vector #f)
      (_value 0)))

   (define-method memory-test (initialize-instance . args)
     (if (not _initialized)
         (instance-set! self '_persistent_vector (make-instance persistent-vector '(prefix "memtest")))))

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
     (let ((value (utility-package::get-with-default 'value string? args memory-test-package::default-value)))
       (instance-set! self '_value (make-vector dimension (make-vector dimension value))))
     #t)

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method memory-test (fill-vector count first)
     (assert (and (integer? count) (< 0 count)) "parameter must be a positive integer")
     (send _persistent_vector 'extend (+ first count))

     (let loop ((i 0))
       (if (< i count)
           (begin (send _persistent_vector 'set (+ first i) 1) (loop (+ i 1)))))

     (send _persistent_vector 'foldr (lambda (v i) (+ v i)) 0 `(first ,first))
     )

   ;; -----------------------------------------------------------------
   ;; NAME: clear-state
   ;;
   ;; DESCRIPTION:
   ;; Clear the value making the intrinsic state small again
   ;; -----------------------------------------------------------------
   (define-method memory-test (clear-state)
     (let ((last (send _persistent_vector 'get-size)))
       (let loop ((index 0))
         (if (< index last)
             (begin (send _persisten_vector del index) (loop (+ index 1))))))
     (instance-set! self '_value ())
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
     (let ((key-base (utility-package::get-with-default 'key-base string? args memory-test-package::default-key))
           (value (utility-package::get-with-default 'value string? args memory-test-package::default-value)))
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
     (let ((key (utility-package::get-with-default 'key string? args memory-test-package::default-key))
           (value-base (utility-package::get-with-default 'value-base string? args memory-test-package::default-value)))
       (assert (= (string-length value-base) 1) "value base must be a one character string")
       (let ((big-string (make-string size (string-ref value-base 0))))
         (safe-kv-put key big-string)
         (safe-kv-get key))))

   ))

(define memory-test memory-test-package::memory-test)
