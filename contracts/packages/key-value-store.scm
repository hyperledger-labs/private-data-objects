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

(require "hashtab.scm")

(define-class key-value-store
  (instance-vars
   (table-size 347)
   (store #f))
  (class-vars
   (_ht-set_ (hashtab-package::associator string=?))
   (_ht-get_ (hashtab-package::inquirer string=?))
   (_ht-del_ (hashtab-package::remover string=?))))

(define-method key-value-store (initialize-instance . args)
  (if (not store)
      (instance-set! self 'store (hashtab-package::make-hash-table table-size))))

;; -----------------------------------------------------------------
;; Methods to interogate the store
;; -----------------------------------------------------------------
(define-method key-value-store (map proc)
  (hashtab-package::hash-map (lambda (k v) (proc k (send self 'get k))) store))

(define-method key-value-store (for-each proc)
  (hashtab-package::hash-for-each (lambda (k v) (proc k (send self 'get k))) store))

;; -----------------------------------------------------------------
;; Methods to update the value associated with a value, note that
;; value is an instance of the value object and value is an integer
;; -----------------------------------------------------------------
(define-method key-value-store (exists? key)
  (_ht-get_ store key))

(define-method key-value-store (get key)
  (assert (_ht-get_ store key) "key does not exist" key)
  (eval (string->expression (key-value-get key))))

(define-method key-value-store (set key value)
  (assert (oops::instance? value) "value must be an object instance" value)
  (_ht-set_ store key #t)
  (key-value-put key (expression->string (serialize-instance value)))
  #t)

(define-method key-value-store (del key)
  (assert (_ht-get_ store key) "key does not exist" key)
  (_ht-del_ store key)
  (key-value-delete key)
  #t)
