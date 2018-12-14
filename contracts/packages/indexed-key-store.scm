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

;; PACKAGE: index-key-store-package
;;
;; This package implements a key-value store that extends the persistent
;; key-value store package to include support for iteration over the keys
;; that are stored. The list of keys is stored in the intrinsic state of the
;; contract object so this is not appropriate for a large number of keys.

(require "hashtab.scm")
(require "persistent-key-store.scm")

(define indexed-key-store-package
  (package

   (define-class indexed-key-store
     (super-class persistent-key-store)
     (instance-vars
      (table-size 347)
      (store #f))
     (class-vars
      (_ht-set_ (hashtab-package::associator string=?))
      (_ht-get_ (hashtab-package::inquirer string=?))
      (_ht-del_ (hashtab-package::remover string=?))))

   (define-method indexed-key-store (initialize-instance . args)
     (if (not store)
         (instance-set! self 'store (hashtab-package::make-hash-table table-size))))

   ;; -----------------------------------------------------------------
   ;; Methods to interogate the store
   ;; -----------------------------------------------------------------
   (define-method indexed-key-store (map proc)
     (hashtab-package::hash-map (lambda (k v) (proc k (send self 'get k))) store))

   (define-method indexed-key-store (for-each proc)
     (hashtab-package::hash-for-each (lambda (k v) (proc k (send self 'get k))) store))

   ;; -----------------------------------------------------------------
   ;; Methods to update the value associated with a value, note that
   ;; value is an instance of the value object and value is an integer
   ;; -----------------------------------------------------------------
   (define-method indexed-key-store (exists? key)
     (_ht-get_ store key))

   (define-method indexed-key-store (get key . args)
     (if (pair? args)
         (send-to-class persistent-key-store self 'get key (car args))
         (send-to-class persistent-key-store self 'get key)))

   (define-method indexed-key-store (set key value)
     (send-to-class persistent-key-store self 'set key value)
     (_ht-set_ store key #t)
     #t)

   (define-method indexed-key-store (del key)
     (send-to-class persistent-key-store self 'del key)
     (_ht-del_ store key)
     #t)
   ))

(define indexed-key-store indexed-key-store-package::indexed-key-store)
