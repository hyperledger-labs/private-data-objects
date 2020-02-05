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
     (class-vars
      (interface-version 2))

     (instance-vars
      (_initialized #f)
      (_persistent_vector #f)
      (_value 0)))

   (define-method memory-test (initialize-instance . args)
     (if (not _initialized)
         (let ((v (make-instance persistent-vector '(prefix "memtest") '(default 0))))
           (instance-set! self '_persistent_vector v)
           (instance-set! self '_initialized #t))))

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
   (define-method memory-test (big-state environment dimension . args)
     (assert (and (integer? dimension) (< 0 dimension)) "second parameter must be a positive integer")
     (let ((value (utility-package::get-with-default "value" string? args memory-test-package::default-value)))
       (instance-set! self '_value (make-vector dimension (make-vector dimension value))))
     (dispatch-package::return-success #t))

   ;; -----------------------------------------------------------------
   ;; NAME: clear-state
   ;;
   ;; DESCRIPTION:
   ;; Clear the value making the intrinsic state small again
   ;; -----------------------------------------------------------------
   (define-method memory-test (clear-state environment)
     (instance-set! self '_value ())
     (dispatch-package::return-success #t))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method memory-test (fill-vector environment . args)
     (let* ((vector-size (send _persistent_vector 'get-size))
            (first (utility-package::get-with-default "first" integer? args 0))
            (last (utility-package::get-with-default "last" integer? args (- vector-size 1)))
            (value (utility-package::get-with-default "value" integer? args 1)))
       (assert (and (<= 0 first) (<= first last)) "invalid positional parameters" first last)
       (if (<= vector-size last)
           (send _persistent_vector 'extend (+ last 1)))

       (let loop ((index first))
         (if (<= index last)
             (begin
               (send _persistent_vector 'set index value)
               (loop (+ index 1)))))

       ;; add up all of the values and return them
       (dispatch-package::return-value
        (send _persistent_vector 'foldr (lambda (v i) (+ v i)) 0)
        #t)))

   ;; -----------------------------------------------------------------
   ;; -----------------------------------------------------------------
   (define-method memory-test (dump-vector environment . args)
     (let* ((vector-size (send _persistent_vector 'get-size))
            (first (utility-package::get-with-default "first" integer? args 0))
            (last (utility-package::get-with-default "last" integer? args (- vector-size 1))))
       (assert (and (<= 0 first) (<= first last) (< last vector-size)) "invalid positional parameters" first last)

       ;; dump the values in the vector
       (let ((result (send _persistent_vector 'map (lambda (v) v) `(first ,first) `(last ,last))))
         (dispatch-package::return-value (apply vector result) #f))))

   ;; -----------------------------------------------------------------
   ;; NAME: clear-vector
   ;;
   ;; DESCRIPTION:
   ;; Clear some of the values in the vector
   ;; -----------------------------------------------------------------
   (define-method memory-test (clear-vector environment . args)
     (let* ((vector-size (send _persistent_vector 'get-size))
            (first (utility-package::get-with-default "first" integer? args 0))
            (last (utility-package::get-with-default "last" integer? args (- vector-size 1)))
            (skip (utility-package::get-with-default "skip" integer? args 4)))
       (assert (and (<= 0 first) (<= first last) (< last vector-size)) "invalid positional parameters" first last)
       (assert (< 0 skip) "skip must be positive integer" skip)
       (let loop ((index first))
         (if (<= index last)
             (begin (send _persistent_vector 'del index) (loop (+ index skip)))))

       ;; add up all of the values and return them
       (let ((result (send _persistent_vector 'foldr (lambda (v i) (+ v i)) 0 `(first ,first) `(last ,last))))
         (dispatch-package::return-value result #t))))

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

   (define-method memory-test (deep-recursion environment depth)
     (assert (and (integer? depth) (< 0 depth)) "parameter must be a positive integer")
     (dispatch-package::return-value
      (memory-test-package::_recursive-function_ depth)
      #f))

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
   (define-method memory-test (many-keys environment count . args)
     (assert (and (integer? count) (< 0 count)) "second parameter must be a positive integer")
     (let ((key-base (utility-package::get-with-default "key-base" string? args memory-test-package::default-key))
           (value (utility-package::get-with-default "value" string? args memory-test-package::default-value)))
       (let loop ((i 0))
         (if (< i count)
             (let ((key (string-append key-base (number->string i))))
               (safe-kv-put key "_")
               (loop (+ i 1))))))
     (dispatch-package::return-success #t))

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
   (define-method memory-test (big-value environment size . args)
     (assert (and (integer? size) (< 0 size)) "second parameter must be a positive integer")
     (let ((key (utility-package::get-with-default "key" string? args memory-test-package::default-key))
           (value-base (utility-package::get-with-default "value-base" string? args memory-test-package::default-value)))
       (assert (= (string-length value-base) 1) "value base must be a one character string")
       (let ((big-string (make-string size (string-ref value-base 0))))
         (safe-kv-put key big-string)
         (dispatch-package::return-value
          (safe-kv-get key)
          #t))))

   ))

(define memory-test memory-test-package::memory-test)
