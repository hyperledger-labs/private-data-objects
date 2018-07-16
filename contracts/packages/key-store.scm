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

(define-class key-store
  (instance-vars
   (store (hashtab-package::make-hash-table 347)))
  (class-vars
   (_ht-set_ (hashtab-package::associator string=?))
   (_ht-get_ (hashtab-package::inquirer string=?))
   (_ht-del_ (hashtab-package::remover string=?))))

;; -----------------------------------------------------------------
;; Methods to interogate the store
;; -----------------------------------------------------------------
(define-method key-store (get-state)
  (let ((result '()))
    (hashtab-package::hash-for-each
     (lambda (key value) (set! result (cons (list key (send value 'externalize 'full)) result)))
     store)
    result))

;; -----------------------------------------------------------------
;; Methods to update the value associated with a value, note that
;; value is an instance of the value object and value is an integer
;; -----------------------------------------------------------------
(define-method key-store (create key value)
  (assert (not (_ht-get_ store key)) "key already exists" key)
  (_ht-set_ store key value)
  #t)

(define-method key-store (exists? key)
  (let ((value (_ht-get_ store key)))
    value))

(define-method key-store (get key)
  (let ((value (_ht-get_ store key)))
    (assert value "key does not exist" key)
    value))

(define-method key-store (set key value)
  (let ((oldvalue (_ht-get_ store key)))
    (assert oldvalue "key does not exist" key)
    (_ht-del_ store key)
    (_ht-set_ store key value)))

(define-method key-store (del key)
  (let ((value (_ht-get_ store key)))
    (assert value "key does not exist" key)
    (_ht-del_ store key)))
