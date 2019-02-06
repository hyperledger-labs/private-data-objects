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

;; PACKAGE: persistent-key-store-package
;;
;; This package implements a persistent key-value store that leverages
;; the extrinsic key value store operations. This class is useful
;; for large key-value stores that do not require enumeration of the
;; keys.
;;
;; The initialization of the class includes an optional prefix that
;; can be used to uniquify keys. While this is generally not necessary
;; for contracts executed in the enclave, it is definitely necessary
;; for developing multiple contracts using the standard tinyscheme
;; interpreter.


(require "safe-key-store.scm")
(require "serialize.scm")

(define persistent-key-store-package
  (package

   (define (make-key prefix key)
     (compute-message-hash (string-append prefix ":" key)))

   ;; =================================================================
   ;; CLASS: persistent-key-store
   ;; =================================================================
   (define-class persistent-key-store
     (instance-vars
      (_initialized #f)
      (_deserialize #f)
      (_serialize_ #f)
      (_prefix "")))

   (define-method persistent-key-store (initialize-instance . args)
     (if (not _initialized)
         (let ((prefix  (utility-package::get-with-default 'prefix string? args ""))
               (deserialize (utility-package::get-with-default 'deserialize closure? args serialize-package::deserialize-object))
               (serialize (utility-package::get-with-default 'serialize closure? args serialize-package::serialize-object)))
           (if (not (string=? prefix ""))
               (instance-set! self '_prefix (compute-message-hash prefix)))
           (instance-set! self '_deserialize deserialize)
           (instance-set! self '_serialize_ serialize)
           (instance-set! self '_initialized #t))))

   ;; -----------------------------------------------------------------
   ;; Methods to update the value associated with a value, note that
   ;; value is an instance of the value object and value is an integer
   ;; -----------------------------------------------------------------

   ;; get the value associated with a key, args can provide a default value
   ;; if the key does not exist in the store
   (define-method persistent-key-store (get key . args)
     (assert (string? key) "key must be a string" key)
     (let* ((_key (persistent-key-store-package::make-key key _prefix))
            (_val (safe-kv-get _key)))
       (cond (_val (_deserialize _val))
             ((pair? args) (car args))
             ((throw "key does not exist" key)))))

   (define-method persistent-key-store (set key value)
     (assert (string? key) "key must be a string" key)
     (assert (oops::instance? value) "value must be an object instance" value)
     (let* ((serialized-string (_serialize_ value))
            (_key (persistent-key-store-package::make-key key _prefix)))
       (safe-kv-put _key serialized-string))
     #t)

   (define-method persistent-key-store (del key)
     (assert (string? key) "key must be a string" key)
     (let ((_key (persistent-key-store-package::make-key key _prefix)))
       (safe-kv-del _key))
     #t)

   (define-method persistent-key-store (exists? key)
     (assert (string? key) "key must be a string" key)
     (let* ((_key (persistent-key-store-package::make-key key _prefix))
            (_val (safe-kv-get _key)))
       (and (string? _val) (< 0 (string-length _val)))))

   ))

(define persistent-key-store persistent-key-store-package::persistent-key-store)
