;; Copyright 2019 Intel Corporation
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

;; PACKAGE: persistent-vector
;;
;; This package implements a persistent vector that leverages
;; the extrinsic key value store operations.
;;
;; The initialization of the class includes an optional prefix that
;; can be used to uniquify keys. While this is generally not necessary
;; for contracts executed in the enclave, it is definitely necessary
;; for developing multiple contracts using the standard tinyscheme
;; interpreter.


(require "safe-key-store.scm")
(require "serialize.scm")
(require "utility.scm")

(define persistent-vector-package
  (package

   (define (make-index-key prefix index)
     (string-append prefix ":" (number->string index)))

   (define-class persistent-vector
     (instance-vars
      (_deserialize #f)
      (_serialize #f)
      (_initialized #f)
      (_size 0)
      (_default "")
      (_prefix "")))

   ;; -----------------------------------------------------------------
   ;; initialization
   ;; -----------------------------------------------------------------
   (define-method persistent-vector (initialize-instance . args)
     (if (not _initialized)
         (let ((prefix  (utility-package::get-with-default 'prefix string? args _prefix))
               (default (utility-package::get-with-default 'default (lambda (v) #t) args _default))
               (size (utility-package::get-with-default 'size (lambda (v) (and (integer? v) (<= 0 v))) args _size))
               (deserialize (utility-package::get-with-default 'deserialize closure? args serialize-package::deserialize-object))
               (serialize (utility-package::get-with-default 'serialize closure? args serialize-package::serialize-object)))
           (assert (not (string=? prefix "")) "must define a prefix for the vector")
           (instance-set! self '_size size)
           (instance-set! self '_prefix prefix)
           (instance-set! self '_default default)
           (instance-set! self '_deserialize deserialize)
           (instance-set! self '_serialize serialize)
           (instance-set! self '_initialized #t))))

   ;; -----------------------------------------------------------------
   ;; size
   ;; -----------------------------------------------------------------
   (define-method persistent-vector (get-size) _size)

   (define-method persistent-vector (extend size)
     (assert (and (integer? size) (<= 0 size)) "size must be a non-negative integer")
     (instance-set! self '_size size))

   ;; -----------------------------------------------------------------
   ;; get/set/del
   ;; -----------------------------------------------------------------
   (define-method persistent-vector (set index value)
     (assert (and (integer? index) (<= 0 index) (< index _size)) "invalid index")
     (let ((index-key (persistent-vector-package::make-index-key _prefix index)))
       (safe-kv-put index-key (_serialize value)))
     #t)

   (define-method persistent-vector (get index)
     (assert (and (integer? index) (<= 0 index) (< index _size)) "invalid index")
     (let* ((index-key (persistent-vector-package::make-index-key _prefix index))
            (value (safe-kv-get index-key)))
       (if (string=? value "") _default (_deserialize value))))

   (define-method persistent-vector (del index)
     (assert (and (integer? index) (<= 0 index) (< index _size)) "invalid index")
     (let* ((index-key (persistent-vector-package::make-index-key _prefix index)))
       (safe-kv-del index-key))
     #t)

   ;; -----------------------------------------------------------------
   ;; map/for-each/foldr
   ;; -----------------------------------------------------------------
   (define-method persistent-vector (map f . args)
     (let ((first (utility-package::get-with-default 'first integer? args 0))
           (last (utility-package::get-with-default 'last integer? args (- _size 1))))
       (assert (<= 0 first) "first index must be a non-negative integer")
       (assert (< last _size) "last index must be smaller than the vector size")
       (assert (<= first last) "first index must precede last index")
       (let loop ((index first))
         (if (<= index last)
             (cons (f (send self 'get index)) (loop (+ index 1)))
             '()))))

   (define-method persistent-vector (for-each f . args)
     (let ((first (utility-package::get-with-default 'first integer? args 0))
           (last (utility-package::get-with-default 'last integer? args (- _size 1))))
       (assert (<= 0 first) "first index must be a non-negative integer")
       (assert (< last _size) "last index must be smaller than the vector size")
       (assert (<= first last) "first index must precede last index")
       (let loop ((index first))
         (if (<= index last)
             (begin (f (send self 'get index)) (loop (+ index 1)))))))

   (define-method persistent-vector (foldr f i . args)
     (let ((first (utility-package::get-with-default 'first integer? args 0))
           (last (utility-package::get-with-default 'last integer? args (- _size 1))))
       (assert (<= 0 first) "first index must be a non-negative integer")
       (assert (< last _size) "last index must be smaller than the vector size")
       (assert (<= first last) "first index must precede last index")
       (let loop ((index first))
         (if (<= index last)
             (f (send self 'get index) (loop (+ index 1)))
             i))))

   ))

;; -----------------------------------------------------------------
;; -----------------------------------------------------------------
(define persistent-vector persistent-vector-package::persistent-vector)
