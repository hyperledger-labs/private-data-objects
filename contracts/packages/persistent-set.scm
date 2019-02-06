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

;; PACKAGE: persistent-set
;;
;; This package implements a persistent unordered list that leverages
;; the persistent vector to store the list. All parameters
;; required by the persistent vector class are required here.
;;
;; The initialization of the class includes an mandatory prefix that
;; serves as a unique name for the list in the persistent store. While

(require "safe-key-store.scm")
(require "persistent-vector.scm")
(require "serialize.scm")
(require "utility.scm")

(define persistent-set-package
  (package

   (define (make-key prefix string-value)
     (compute-message-hash (string-append prefix ":" string-value)))

   (define (is-set? value)
     (not (string=? value "")))

   (define-class persistent-set
     (instance-vars
      (_initialized #f)
      (_vector #f)
      (_deserialize #f)
      (_serialize #f)
      (_prefix "")))

   ;; -----------------------------------------------------------------
   ;; initialization
   ;; -----------------------------------------------------------------
   (define-method persistent-set (initialize-instance . args)
     (if (not _initialized)
         (let ((prefix  (utility-package::get-with-default 'prefix string? args _prefix))
               (deserialize (utility-package::get-with-default 'deserialize closure? args serialize-package::deserialize-object))
               (serialize (utility-package::get-with-default 'serialize closure? args serialize-package::serialize-object)))
           (assert (not (string=? prefix "")) "must define a prefix for the vector")
           (instance-set! self '_prefix (compute-message-hash (string-append "set" prefix)))
           (instance-set! self '_deserialize deserialize)
           (instance-set! self '_serialize serialize)
           (instance-set! self '_vector (make-instance* persistent-vector
                                                        (list
                                                         (list '_serialize (lambda (v) v))
                                                         (list '_deserialize (lambda (v) v))
                                                         (list '_default "")
                                                         (list '_prefix prefix))))
           (instance-set! self '_initialized #t))))

   (define-method persistent-set (add value)
     (let* ((serialized-value (_serialize value))
            (serialized-key (persistent-set-package::make-key _prefix serialized-value)))
       (if (not (send self '_in? serialized-key))
           (let ((index (send _vector 'get-size)))
             (send _vector 'extend (+ index 1))
             (send _vector 'set index serialized-value)
             (safe-key-store::put serialized-key (number->string index))))))

   (define-method persistent-set (remove value)
     (let* ((serialized-value (_serialize value))
            (serialized-key (persistent-set-package::make-key _prefix serialized-value)))
       (if (send self '_in? serialized-key)
           (let ((index (string->number (safe-key-store::get serialized-key))))
             (send _vector 'del index)
             (safe-key-store::del serialized-key)))))

   (define-method persistent-set (in? value)
     (let* ((serialized-value (_serialize value))
            (serialized-key (persistent-set-package::make-key _prefix serialized-value)))
       (send self '_in? serialized-key)))

   (define-method persistent-set (_in? serialized-key)
     (let ((value (safe-key-store::get serialized-key)))
       (persistent-set-package::is-set? value)))

   ;; -----------------------------------------------------------------
   ;; map/for-each/foldr
   ;; -----------------------------------------------------------------
   (define-method persistent-set (map f)
     (let ((last (send _vector 'get-size)))
       (let loop ((index 0))
         (if (< index last)
             (let ((value (send _vector 'get index)))
               (if (persistent-set-package::is-set? value)
                   (cons (f (_deserialize value)) (loop (+ index 1)))
                   (loop (+ index 1))))
             '()))))

   (define-method persistent-set (for-each f)
     (let ((last (send _vector 'get-size)))
       (let loop ((index 0))
         (if (< index last)
             (let ((value (send _vector 'get index)))
               (if (persistent-set-package::is-set? value)
                   (begin (f (_deserialize value)) (loop (+ index 1)))
                   (loop (+ index 1))))))
       #t))

   (define-method persistent-set (foldr f i)
     (let ((last (send _vector 'get-size)))
       (let loop ((index 0))
         (if (< index last)
             (let ((value (send _vector 'get index)))
               (if (persistent-set-package::is-set? value)
                   (f (_deserialize value) (loop (+ index 1)))
                   (loop (+ index 1))))
             i))))
   ))

(define persistent-set persistent-set-package::persistent-set)
